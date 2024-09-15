package main

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"testing"

	"www.bamsoftware.com/git/champa.git/turbotunnel"
)

func mustNewRequest(method, path string) *http.Request {
	req, err := http.NewRequest(method, path, nil)
	if err != nil {
		panic(err)
	}
	return req
}

func TestDecodeRequest(t *testing.T) {
	defClientID := turbotunnel.ClientID{'C', 'L', 'I', 'E', 'N', 'T', 'I', 'D'}
	defPayload := []byte("abcde")
	defEncoded := string(base64.RawURLEncoding.EncodeToString(bytes.Join([][]byte{defClientID[:], defPayload}, nil)))

	// Only GET is allowed.
	req := mustNewRequest("POST", "/0/XXXX/"+defEncoded)
	clientID, payload := decodeRequest(req)
	if payload != nil {
		t.Errorf("POST request → (%v, %+q)", clientID, payload)
	}

	for _, test := range []struct {
		path             string
		expectedClientID turbotunnel.ClientID
		expectedPayload  []byte
	}{
		// Good tests.
		{"/0/XXXX/" + defEncoded, defClientID, defPayload},
		{"/0/@@@@/" + defEncoded, defClientID, defPayload}, // non-base64 padding
		{"/0/XXXX/YYYY/" + defEncoded, defClientID, defPayload},
		{"/0" + defEncoded, defClientID, defPayload}, // no slash necessary after version

		// Bad tests.
		{"/0", turbotunnel.ClientID{}, nil},
		{"//0/XXXX/" + defEncoded, turbotunnel.ClientID{}, nil}, // extra slash at start
		{"0/XXXX/" + defEncoded, turbotunnel.ClientID{}, nil},   // no slash at start
		{"/0/@@@@" + defEncoded, turbotunnel.ClientID{}, nil},   // non-base64 in payload
		{"/0/XXXX/" + defEncoded + "/", turbotunnel.ClientID{}, nil},
		{"/1/XXXX/" + defEncoded, turbotunnel.ClientID{}, nil},         // unknown version
		{"/0/XXXX/Q0xJRU5USURhYmNkZQ===", turbotunnel.ClientID{}, nil}, // with padding characters
	} {
		req := mustNewRequest("GET", test.path)
		clientID, payload := decodeRequest(req)
		if !bytes.Equal(payload, test.expectedPayload) || clientID != test.expectedClientID {
			t.Errorf("%+q → (%v, %v), expected (%v, %v)",
				test.path, clientID, payload, test.expectedClientID, test.expectedPayload)
		}
	}
}
