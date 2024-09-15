package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/crypto/acme/autocert"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"www.bamsoftware.com/git/champa.git/armor"
	"www.bamsoftware.com/git/champa.git/encapsulation"
	"www.bamsoftware.com/git/champa.git/noise"
	"www.bamsoftware.com/git/champa.git/turbotunnel"
)

const (
	// smux streams will be closed after this much time without receiving data.
	idleTimeout = 2 * time.Minute

	// How long we may wait for downstream data before sending an empty
	// response.
	maxResponseDelay = 100 * time.Millisecond

	// How long to wait for a TCP connection to upstream to be established.
	upstreamDialTimeout = 30 * time.Second

	// net/http Server.ReadTimeout, the maximum time allowed to read an
	// entire request, including the body. Because we are likely to be
	// proxying through an AMP cache, we expect requests to be small, with
	// no streaming body.
	serverReadTimeout = 10 * time.Second
	// net/http Server.WriteTimeout, the maximum time allowed to write an
	// entire response, including the body. Because we are likely to be
	// proxying through an AMP cache, our responses are limited in size and
	// not streaming.
	serverWriteTimeout = 20 * time.Second
	// net/http Server.IdleTimeout, how long to keep a keep-alive HTTP
	// connection open, awaiting another request.
	serverIdleTimeout = idleTimeout
)

// handleStream bidirectionally connects a client stream with a TCP socket
// addressed by upstream.
func handleStream(stream *smux.Stream, upstream string, conv uint32) error {
	dialer := net.Dialer{
		Timeout: upstreamDialTimeout,
	}
	upstreamConn, err := dialer.Dial("tcp", upstream)
	if err != nil {
		return fmt.Errorf("stream %08x:%d connect upstream: %v", conv, stream.ID(), err)
	}
	defer upstreamConn.Close()
	upstreamTCPConn := upstreamConn.(*net.TCPConn)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(stream, upstreamTCPConn)
		if err == io.EOF {
			// smux Stream.Write may return io.EOF.
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream %08x:%d copy stream←upstream: %v", conv, stream.ID(), err)
		}
		upstreamTCPConn.CloseRead()
		stream.Close()
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(upstreamTCPConn, stream)
		if err == io.EOF {
			// smux Stream.WriteTo may return io.EOF.
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream %08x:%d copy upstream←stream: %v", conv, stream.ID(), err)
		}
		upstreamTCPConn.CloseWrite()
	}()
	wg.Wait()

	return nil
}

// acceptStreams wraps a KCP session in a Noise channel and an smux.Session,
// then awaits smux streams. It passes each stream to handleStream.
func acceptStreams(conn *kcp.UDPSession, upstream string, privkey []byte) error {
	// Put a Noise channel on top of the KCP conn.
	rw, err := noise.NewServer(conn, privkey)
	if err != nil {
		return err
	}

	// Put an smux session on top of the encrypted Noise channel.
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveTimeout = idleTimeout
	smuxConfig.MaxReceiveBuffer = 16 * 1024 * 1024 // default is 4 * 1024 * 1024
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024   // default is 65536
	sess, err := smux.Server(rw, smuxConfig)
	if err != nil {
		return err
	}
	defer sess.Close()

	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}
			if err == io.ErrClosedPipe {
				// We don't want to report this error.
				err = nil
			}
			return err
		}
		log.Printf("begin stream %08x:%d", conn.GetConv(), stream.ID())
		go func() {
			defer func() {
				log.Printf("end stream %08x:%d", conn.GetConv(), stream.ID())
				stream.Close()
			}()
			err := handleStream(stream, upstream, conn.GetConv())
			if err != nil {
				log.Printf("stream %08x:%d handleStream: %v", conn.GetConv(), stream.ID(), err)
			}
		}()
	}
}

// acceptSessions listens for incoming KCP connections and passes them to
// acceptStreams.
func acceptSessions(ln *kcp.Listener, upstream string, privkey []byte) error {
	for {
		conn, err := ln.AcceptKCP()
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}
			return err
		}
		log.Printf("begin session %08x", conn.GetConv())
		// Permit coalescing the payloads of consecutive sends.
		conn.SetStreamMode(true)
		// Disable the dynamic congestion window (limit only by the
		// maximum of local and remote static windows).
		conn.SetNoDelay(
			0, // default nodelay
			0, // default interval
			0, // default resend
			1, // nc=1 => congestion window off
		)
		conn.SetWindowSize(1024, 1024) // Default is 32, 32.
		go func() {
			defer func() {
				log.Printf("end session %08x", conn.GetConv())
				conn.Close()
			}()
			err := acceptStreams(conn, upstream, privkey)
			if err != nil && !errors.Is(err, io.ErrClosedPipe) {
				log.Printf("session %08x acceptStreams: %v", conn.GetConv(), err)
			}
		}()
	}
}

type Handler struct {
	pconn *turbotunnel.QueuePacketConn
}

// decodeRequest extracts a ClientID and a payload from an incoming HTTP
// request. In case of a decoding failure, the returned payload slice will be
// nil. The payload is always non-nil after a successful decoding, even if the
// payload is empty.
func decodeRequest(req *http.Request) (turbotunnel.ClientID, []byte) {
	// Check the version indicator of the incoming client–server protocol.
	switch {
	case strings.HasPrefix(req.URL.Path, "/0"):
		// Version "0"'s payload is base64-encoded, using the URL-safe
		// alphabet without padding, in the final path component
		// (earlier path components are ignored).
		_, encoded := path.Split(req.URL.Path[2:]) // Remove "/0" prefix.
		decoded, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			return turbotunnel.ClientID{}, nil
		}
		var clientID turbotunnel.ClientID
		n := copy(clientID[:], decoded)
		if n != len(clientID) {
			return turbotunnel.ClientID{}, nil
		}
		payload := decoded[n:]
		return clientID, payload
	default:
		return turbotunnel.ClientID{}, nil
	}
}

func (handler *Handler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	const maxPayloadLength = 5000

	if req.Method != "GET" {
		http.Error(rw, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	rw.Header().Set("Content-Type", "text/html")
	// Attempt to hint to an AMP cache not to waste resources caching this
	// document. "The Google AMP Cache considers any document fresh for at
	// least 15 seconds."
	// https://developers.google.com/amp/cache/overview#google-amp-cache-updates
	rw.Header().Set("Cache-Control", "max-age=15")
	rw.WriteHeader(http.StatusOK)

	enc, err := armor.NewEncoder(rw)
	if err != nil {
		log.Printf("armor.NewEncoder: %v", err)
		return
	}
	defer enc.Close()

	clientID, payload := decodeRequest(req)
	if payload == nil {
		// Could not decode the client request. We do not even have a
		// meaningful clientID or nonce. This may be a result of the
		// client deliberately sending a short request for traffic
		// shaping purposes. Send back a dummy, though still
		// AMP-compatible, response.
		// TODO: random padding.
		return
	}

	// Read incoming packets from the payload.
	r := bytes.NewReader(payload)
	for {
		p, err := encapsulation.ReadData(r)
		if err != nil {
			break
		}
		handler.pconn.QueueIncoming(p, clientID)
	}

	limit := maxPayloadLength
	// We loop and bundle as many outgoing packets as will fit, up to
	// maxPayloadLength. We wait up to maxResponseDelay for the first
	// available packet; after that we only include whatever packets are
	// immediately available.
	timer := time.NewTimer(maxResponseDelay)
	defer timer.Stop()
	first := true
	for {
		var p []byte
		unstash := handler.pconn.Unstash(clientID)
		outgoing := handler.pconn.OutgoingQueue(clientID)
		// Prioritize taking a packet first from the stash, then from
		// the outgoing queue, then finally check for expiration of the
		// timer. (We continue to bundle packets even after the timer
		// expires, as long as the packets are immediately available.)
		select {
		case p = <-unstash:
		default:
			select {
			case p = <-unstash:
			case p = <-outgoing:
			default:
				select {
				case p = <-unstash:
				case p = <-outgoing:
				case <-timer.C:
				}
			}
		}
		// We wait for the first packet only. Later packets must be
		// immediately available.
		timer.Reset(0)

		if len(p) == 0 {
			// Timer expired, we are done bundling packets into this
			// response.
			break
		}

		limit -= len(p)
		if !first && limit < 0 {
			// This packet doesn't fit in the payload size limit.
			// Stash it so that it will be first in line for the
			// next response.
			handler.pconn.Stash(p, clientID)
			break
		}
		first = false

		// Write the packet to the AMP response.
		_, err := encapsulation.WriteData(enc, p)
		if err != nil {
			log.Printf("encapsulation.WriteData: %v", err)
			break
		}
		if rw, ok := rw.(http.Flusher); ok {
			rw.Flush()
		}
	}
}

func run(upstream, hostname string, privkey []byte) error {
	// Start up the virtual PacketConn for turbotunnel.
	pconn := turbotunnel.NewQueuePacketConn(turbotunnel.DummyAddr{}, idleTimeout*2)

	ln, err := kcp.ServeConn(nil, 0, 0, pconn)
	if err != nil {
		return fmt.Errorf("opening KCP listener: %v", err)
	}
	defer ln.Close()

	go func() {
		err := acceptSessions(ln, upstream, privkey)
		if err != nil {
			log.Printf("acceptSessions: %v", err)
		}
	}()

	done := make(chan error, 10)

	handler := &Handler{
		pconn: pconn,
	}

	// Create a new ServeMux
	mux := http.NewServeMux()

	// Handle requests to /champa/
	mux.Handle("/champa/", http.StripPrefix("/champa", handler))

	// Handle all other requests with the existing handler
	mux.Handle("/", handler)

	// Create a cache directory for the certificates
	certDir := "/etc/letsencrypt/live/autocert-cache"

	// Create the autocert manager
	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(hostname),
		Cache:      autocert.DirCache(certDir),
	}

	// Create a TLS config using the autocert manager
	tlsConfig := certManager.TLSConfig()
	tlsConfig.MinVersion = tls.VersionTLS12 // Ensure minimum TLS 1.2

	// Create the servers
	httpServer := &http.Server{
		Addr:    ":80",
		Handler: certManager.HTTPHandler(nil),
	}
	defer httpServer.Close()

	tlsServer := &http.Server{
		Addr:         ":443",
		Handler:      mux,
		TLSConfig:    tlsConfig,
		ReadTimeout:  serverReadTimeout,
		WriteTimeout: serverWriteTimeout,
		IdleTimeout:  serverIdleTimeout,
	}
	defer tlsServer.Close()

	go func() {
		log.Printf("Starting HTTP server on :80 for ACME challenge")
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			done <- fmt.Errorf("HTTP server error: %v", err)
		}
	}()

	go func() {
		log.Printf("Starting HTTPS server on :443")
		if err := tlsServer.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			done <- fmt.Errorf("HTTPS server error: %v", err)
		}
	}()

	// The goroutines are expected to run forever. Return the first error
	// from any of them.
	return <-done

	//server := &http.Server{
	//	Addr:         listen,
	//	Handler:      handler,
	//	ReadTimeout:  serverReadTimeout,
	//	WriteTimeout: serverWriteTimeout,
	//	IdleTimeout:  serverIdleTimeout,
	//	// The default MaxHeaderBytes is plenty for our purposes.
	//}
	//defer server.Close()
	//
	//return server.ListenAndServe()
}

func main() {
	var genKey bool
	var privkeyFilename string
	var privkeyString string
	var pubkeyFilename string
	var hostname string

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), `Usage:
  %[1]s -gen-key -privkey-file PRIVKEYFILE -pubkey-file PUBKEYFILE
  %[1]s -privkey-file PRIVKEYFILE LISTENADDR UPSTREAMADDR

Example:
  %[1]s -gen-key -privkey-file server.key -pubkey-file server.pub
  %[1]s -privkey-file server.key 127.0.0.1:8080 127.0.0.1:7001

`, os.Args[0])
		flag.PrintDefaults()
	}
	flag.BoolVar(&genKey, "gen-key", false, "generate a server keypair; print to stdout or save to files")
	flag.StringVar(&privkeyString, "privkey", "", fmt.Sprintf("server private key (%d hex digits)", noise.KeyLen*2))
	flag.StringVar(&privkeyFilename, "privkey-file", "", "read server private key from file (with -gen-key, write to file)")
	flag.StringVar(&pubkeyFilename, "pubkey-file", "", "with -gen-key, write server public key to file")
	flag.StringVar(&hostname, "hostname", "", "generate certs with this hostname")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.LUTC)

	if genKey {
		// -gen-key mode.

		if flag.NArg() != 0 || privkeyString != "" {
			flag.Usage()
			os.Exit(1)
		}
		if err := generateKeypair(privkeyFilename, pubkeyFilename); err != nil {
			fmt.Fprintf(os.Stderr, "cannot generate keypair: %v\n", err)
			os.Exit(1)
		}
	} else {
		// Ordinary server mode.

		if flag.NArg() != 2 {
			flag.Usage()
			os.Exit(1)
		}

		if hostname == "" {
			fmt.Println("hostname is required")
			os.Exit(1)
		}

		upstream := flag.Arg(0)
		// We keep upstream as a string in order to eventually pass it to
		// net.Dial in handleStream. But we do a preliminary resolution of the
		// name here, in order to exit with a quick error at startup if the
		// address cannot be parsed or resolved.
		{
			upstreamTCPAddr, err := net.ResolveTCPAddr("tcp", upstream)
			if err == nil && upstreamTCPAddr.IP == nil {
				err = fmt.Errorf("missing host in address")
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "cannot parse upstream address: %v\n", err)
				os.Exit(1)
			}
		}

		var privkey []byte
		if privkeyFilename != "" && privkeyString != "" {
			fmt.Fprintf(os.Stderr, "only one of -privkey and -privkey-file may be used\n")
			os.Exit(1)
		} else if privkeyFilename != "" {
			var err error
			privkey, err = readKeyFromFile(privkeyFilename)
			if err != nil {
				fmt.Fprintf(os.Stderr, "cannot read privkey from file: %v\n", err)
				os.Exit(1)
			}
		} else if privkeyString != "" {
			var err error
			privkey, err = noise.DecodeKey(privkeyString)
			if err != nil {
				fmt.Fprintf(os.Stderr, "privkey format error: %v\n", err)
				os.Exit(1)
			}
		} else {
			log.Println("generating a temporary one-time keypair")
			log.Println("use the -privkey or -privkey-file option for a persistent server keypair")
			var err error
			privkey, err = noise.GeneratePrivkey()
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			log.Printf("pubkey %x", noise.PubkeyFromPrivkey(privkey))
		}

		err := run(upstream, hostname, privkey)
		if err != nil {
			log.Fatal(err)
		}
	}
}
