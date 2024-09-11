package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/ioutil"
	"testing"
	"time"

	"www.bamsoftware.com/git/champa.git/turbotunnel"
)

// TestCloseCancelsPoll tests that calling Close cancels the context passed to
// the poll function.
func TestCloseCancelsPoll(t *testing.T) {
	beginCh := make(chan struct{})
	resultCh := make(chan error)
	// The poll function returns immediately with a nil error when its
	// context is canceled. It returns after a delay with a non-nil error if
	// its context is not canceled.
	var poll PollFunc = func(ctx context.Context, _ []byte) (io.ReadCloser, error) {
		defer close(resultCh)
		beginCh <- struct{}{}
		select {
		case <-ctx.Done():
			resultCh <- nil
		case <-time.After(5 * time.Second):
			resultCh <- errors.New("poll was not canceled")
		}
		return ioutil.NopCloser(bytes.NewReader(nil)), nil
	}
	pconn := NewPollingPacketConn(turbotunnel.DummyAddr{}, poll)
	// Wait until the poll function has been called.
	<-beginCh
	// Close the connection.
	err := pconn.Close()
	if err != nil {
		t.Fatal(err)
	}
	// Observe what happened inside the poll function. Closing the
	// connection should have canceled the context.
	err = <-resultCh
	if err != nil {
		t.Fatal(err)
	}
}

// TestCloseHaltsPollLoop tests that pollLoop terminates and stops calling its
// poll function after Close is called.
func TestCloseHaltsPollLoop(t *testing.T) {
	closedCh := make(chan struct{})
	resultCh := make(chan error)
	// The poll function returns immediately with a nil error as long as
	// closedCh is not closed. When closedCh is closed, poll returns
	// immediately with a non-nil error.
	var poll PollFunc = func(ctx context.Context, _ []byte) (io.ReadCloser, error) {
		select {
		case <-closedCh:
			resultCh <- errors.New("poll called after close")
		default:
		}
		return ioutil.NopCloser(bytes.NewReader(nil)), nil
	}
	pconn := NewPollingPacketConn(turbotunnel.DummyAddr{}, poll)
	// Close the connection.
	err := pconn.Close()
	if err != nil {
		t.Fatal(err)
	}
	// Tell the poll function to return an error if it is called after this
	// point.
	close(closedCh)
	// Wait a few seconds to see if the poll function is called after the
	// conn is closed.
	select {
	case err := <-resultCh:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
	}
}
