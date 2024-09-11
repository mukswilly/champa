package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"www.bamsoftware.com/git/champa.git/noise"
	"www.bamsoftware.com/git/champa.git/turbotunnel"
)

// smux streams will be closed after this much time without receiving data.
const idleTimeout = 2 * time.Minute

// readKeyFromFile reads a key from a named file.
func readKeyFromFile(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return noise.ReadKey(f)
}

// noisePacketConn implements the net.PacketConn interface. It acts as an
// intermediary between an upper layer and an inner net.PacketConn, decrypting
// packets on ReadFrom and encrypting them on WriteTo.
type noisePacketConn struct {
	sess *noise.Session
	net.PacketConn
}

// readNoiseMessageOfTypeFrom returns the first complete Noise message whose
// msgTime is wantedType, discarding messages of any other msgType.
func readNoiseMessageOfTypeFrom(conn net.PacketConn, wantedType byte) ([]byte, net.Addr, error) {
	for {
		msgType, msg, addr, err := noise.ReadMessageFrom(conn)
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}
			return nil, nil, err
		}
		if msgType == wantedType {
			return msg, addr, nil
		}
	}
}

// noiseDial performs a Noise handshake over the given net.PacketConn, and
// returns a noisePacketConn with a working noise.Session.
func noiseDial(conn net.PacketConn, addr net.Addr, pubkey []byte) (*noisePacketConn, error) {
	p := []byte{noise.MsgTypeHandshakeInit}
	pre, p, err := noise.InitiateHandshake(p, pubkey)
	if err != nil {
		return nil, err
	}
	// TODO: timeout or context
	_, err = conn.WriteTo(p, addr)
	if err != nil {
		return nil, err
	}

	msg, _, err := readNoiseMessageOfTypeFrom(conn, noise.MsgTypeHandshakeResp)
	if err != nil {
		return nil, err
	}

	sess, err := pre.FinishHandshake(msg)
	if err != nil {
		return nil, err
	}

	return &noisePacketConn{sess, conn}, nil
}

// ReadFrom implements the net.PacketConn interface for noisePacketConn.
func (c *noisePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	msg, addr, err := readNoiseMessageOfTypeFrom(c.PacketConn, noise.MsgTypeTransport)
	if err != nil {
		return 0, nil, err
	}
	dec, err := c.sess.Decrypt(nil, msg)
	if err != nil {
		return 0, nil, err
	}
	return copy(p, dec), addr, nil
}

// WriteTo implements the net.PacketConn interface for noisePacketConn.
func (c *noisePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	buf := []byte{noise.MsgTypeTransport}
	buf, err := c.sess.Encrypt(buf, p)
	if err != nil {
		return 0, err
	}
	return c.PacketConn.WriteTo(buf, addr)
}

func handle(local *net.TCPConn, sess *smux.Session, conv uint32) error {
	stream, err := sess.OpenStream()
	if err != nil {
		return fmt.Errorf("session %08x opening stream: %v", conv, err)
	}
	defer func() {
		log.Printf("end stream %08x:%d", conv, stream.ID())
		stream.Close()
	}()
	log.Printf("begin stream %08x:%d", conv, stream.ID())

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(stream, local)
		if err == io.EOF {
			// smux Stream.Write may return io.EOF.
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream %08x:%d copy stream←local: %v", conv, stream.ID(), err)
		}
		local.CloseRead()
		stream.Close()
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(local, stream)
		if err == io.EOF {
			// smux Stream.WriteTo may return io.EOF.
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream %08x:%d copy local←stream: %v", conv, stream.ID(), err)
		}
		local.CloseWrite()
	}()
	wg.Wait()

	return err
}

func run(serverURL, cacheURL *url.URL, front, localAddr string, pubkey []byte) error {
	ln, err := net.Listen("tcp", localAddr)
	if err != nil {
		return err
	}
	defer ln.Close()

	http.DefaultTransport.(*http.Transport).MaxConnsPerHost = 20

	var poll PollFunc = func(ctx context.Context, p []byte) (io.ReadCloser, error) {
		return exchangeAMP(ctx, serverURL, cacheURL, front, p)
	}
	pconn := NewPollingPacketConn(turbotunnel.DummyAddr{}, poll)
	defer pconn.Close()

	// Add a Noise layer over the AMP polling to encrypt and authenticate
	// each KCP packet.
	nconn, err := noiseDial(pconn, turbotunnel.DummyAddr{}, pubkey)
	if err != nil {
		return err
	}

	// Open a KCP conn over the Noise layer.
	conn, err := kcp.NewConn2(turbotunnel.DummyAddr{}, nil, 0, 0, nconn)
	if err != nil {
		return fmt.Errorf("opening KCP conn: %v", err)
	}
	defer func() {
		log.Printf("end session %08x", conn.GetConv())
		conn.Close()
	}()
	log.Printf("begin session %08x", conn.GetConv())
	// Permit coalescing the payloads of consecutive sends.
	conn.SetStreamMode(true)
	// Disable the dynamic congestion window (limit only by the maximum of
	// local and remote static windows).
	conn.SetNoDelay(
		0, // default nodelay
		0, // default interval
		0, // default resend
		1, // nc=1 => congestion window off
	)
	// ACK received data immediately; this is good in our polling model.
	conn.SetACKNoDelay(true)
	conn.SetWindowSize(1024, 1024) // Default is 32, 32.
	// TODO: We could optimize a call to conn.SetMtu here, based on a
	// maximum URL length we want to send (such as the 8000 bytes
	// recommended at https://datatracker.ietf.org/doc/html/rfc7230#section-3.1.1).
	// The idea is that if we can slightly reduce the MTU from its default
	// to permit one more packet per request, we should do it.
	// E.g. 1400*5 = 7000, but 1320*6 = 7920.

	// Start a smux session on the Noise channel.
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveTimeout = idleTimeout
	smuxConfig.MaxReceiveBuffer = 4 * 1024 * 1024 // default is 4 * 1024 * 1024
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024  // default is 65536
	sess, err := smux.Client(conn, smuxConfig)
	if err != nil {
		return fmt.Errorf("opening smux session: %v", err)
	}
	defer sess.Close()

	for {
		local, err := ln.Accept()
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}
			return err
		}
		go func() {
			defer local.Close()
			err := handle(local.(*net.TCPConn), sess, conn.GetConv())
			if err != nil {
				log.Printf("handle: %v", err)
			}
		}()
	}
}

func main() {
	var cache string
	var front string
	var pubkeyFilename string
	var pubkeyString string

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), `Usage:
  %[1]s -pubkey-file PUBKEYFILE [-cache CACHEURL] [-front DOMAIN] SERVERURL LOCALADDR

Example:
  %[1]s -pubkey-file server.pub -cache https://amp.cache.example/ -front amp.cache.example https://server.example/champa/ 127.0.0.1:7000

`, os.Args[0])
		flag.PrintDefaults()
	}
	flag.StringVar(&cache, "cache", "", "URL of AMP cache (try https://cdn.ampproject.org/)")
	flag.StringVar(&front, "front", "", "domain to domain-front HTTPS requests with (try www.google.com)")
	flag.StringVar(&pubkeyString, "pubkey", "", fmt.Sprintf("server public key (%d hex digits)", noise.KeyLen*2))
	flag.StringVar(&pubkeyFilename, "pubkey-file", "", "read server public key from file")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.LUTC)

	if flag.NArg() != 2 {
		flag.Usage()
		os.Exit(1)
	}
	serverURL, err := url.Parse(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot parse server URL: %v\n", err)
		os.Exit(1)
	}
	localAddr := flag.Arg(1)

	var cacheURL *url.URL
	if cache != "" {
		cacheURL, err = url.Parse(cache)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot parse AMP cache URL: %v\n", err)
			os.Exit(1)
		}
	}

	var pubkey []byte
	if pubkeyFilename != "" && pubkeyString != "" {
		fmt.Fprintf(os.Stderr, "only one of -pubkey and -pubkey-file may be used\n")
		os.Exit(1)
	} else if pubkeyFilename != "" {
		var err error
		pubkey, err = readKeyFromFile(pubkeyFilename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot read pubkey from file: %v\n", err)
			os.Exit(1)
		}
	} else if pubkeyString != "" {
		var err error
		pubkey, err = noise.DecodeKey(pubkeyString)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pubkey format error: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Fprintf(os.Stderr, "the -pubkey or -pubkey-file option is required\n")
		os.Exit(1)
	}

	err = run(serverURL, cacheURL, front, localAddr, pubkey)
	if err != nil {
		log.Fatal(err)
	}
}
