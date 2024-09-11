package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"www.bamsoftware.com/git/champa.git/amp"
	"www.bamsoftware.com/git/champa.git/armor"
)

// cacheBreaker returns a random byte slice of fixed length.
func cacheBreaker() []byte {
	buf := make([]byte, 12)
	_, err := rand.Read(buf)
	if err != nil {
		panic(err)
	}
	return buf
}

func exchangeAMP(ctx context.Context, serverURL, cacheURL *url.URL, front string, p []byte) (io.ReadCloser, error) {
	// Append a cache buster and the encoded p to the path of serverURL.
	u := serverURL.ResolveReference(&url.URL{
		// Use strings.Join, rather than path.Join, in order to retain a
		// closing slash when p is empty.
		Path: strings.Join([]string{
			// "0" is the client–server protocol version indicator.
			"0" + base64.RawURLEncoding.EncodeToString(cacheBreaker()),
			base64.RawURLEncoding.EncodeToString(p),
		}, "/"),
	})

	// Proxy through an AMP cache, if requested.
	if cacheURL != nil {
		var err error
		u, err = amp.CacheURL(u, cacheURL, "c")
		if err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)

	// Do domain fronting, if requested.
	if front != "" {
		_, port, err := net.SplitHostPort(req.URL.Host)
		if err == nil {
			req.URL.Host = net.JoinHostPort(front, port)
		} else {
			req.URL.Host = front
		}
	}

	req.Header.Set("User-Agent", "") // Disable default "Go-http-client/1.1".

	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("server returned status %v", resp.Status)
	}
	if _, err := resp.Location(); err == nil {
		// The Google AMP Cache can return a "silent redirect" with
		// status 200, a Location header set, and a JavaScript redirect
		// in the body. The redirect points directly at the origin
		// server for the request (bypassing the AMP cache). We do not
		// follow redirects nor execute JavaScript, but in any case we
		// cannot extract information from this response and it's better
		// to treat it as a poll error, rather than an EOF when given to
		// the AMP armor decoder.
		//
		// Such a response looks like this (header slightly excerpted):
		//
		// HTTP/2 200 OK
		// Cache-Control: private
		// Content-Type: text/html; charset=UTF-8
		// Location: https://example.com/champa/...
		// Server: sffe
		// X-Silent-Redirect: true
		//
		// <HTML><HEAD>
		// <meta http-equiv="content-type" content="text/html;charset=utf-8">
		// <TITLE>Redirecting</TITLE>
		// <META HTTP-EQUIV="refresh" content="0; url=https://example.com/champa/...">
		// </HEAD>
		// <BODY onLoad="location.replace('https://example.com/champa/...'+document.location.hash)">
		// </BODY></HTML>
		resp.Body.Close()
		return nil, fmt.Errorf("server returned a Location header")
	}

	dec, err := armor.NewDecoder(bufio.NewReader(resp.Body))
	if err != nil {
		resp.Body.Close()
		return nil, err
	}

	// The caller should read from the decoder (which reads from the
	// response body), but close the actual response body when done.
	return &struct {
		io.Reader
		io.Closer
	}{
		Reader: dec,
		Closer: resp.Body,
	}, nil
}
