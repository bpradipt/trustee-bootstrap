package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/coder/websocket"

	"github.com/confidential-devhub/trustee-bootstrap/pkg/relay"
)

// Helper API paths (spec §4).
const (
	StatusPath = "/bootstrap/v1/status"
	RelayPath  = "/bootstrap/v1/relay"
)

// Relay close reasons. The close code carries the outcome: a normal closure
// means the helper accepted the Share. A relay holder can forge either, so
// the outcome informs the Security Operator; it protects nothing.
const (
	reasonAccepted    = "accepted"
	reasonNotAccepted = "Share not accepted"
)

// Handler serves the Helper API. For each relay it opens the guest-loopback
// proxy with listenProxy, asks the CDH for one Share through it, then closes
// the relay with the outcome. limits bound each relay.
func (h *Helper) Handler(listenProxy func() (net.Listener, error), limits relay.Limits) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+StatusPath, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(h.Status())
	})
	mux.HandleFunc("GET "+RelayPath, func(w http.ResponseWriter, r *http.Request) {
		h.serveRelay(w, r, listenProxy, limits)
	})
	return mux
}

func (h *Helper) serveRelay(w http.ResponseWriter, r *http.Request, listenProxy func() (net.Listener, error), limits relay.Limits) {
	if !h.relayMu.TryLock() {
		http.Error(w, "a relay is already open", http.StatusConflict)
		return
	}
	defer h.relayMu.Unlock()
	ws, err := websocket.Accept(w, r, nil)
	if err != nil {
		return // Accept has answered the request
	}
	proxy, err := listenProxy()
	if err != nil {
		log.Printf("relay: open guest proxy: %v", err)
		ws.Close(websocket.StatusInternalError, "guest proxy unavailable")
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	relayed := make(chan struct{})
	go func() {
		relay.Guest(ctx, ws, proxy, limits)
		cancel() // a dropped relay abandons the CDH call
		close(relayed)
	}()
	code, reason := websocket.StatusNormalClosure, reasonAccepted
	if _, err := h.CollectShare(ctx); err != nil {
		log.Printf("relay: %v", err)
		code, reason = websocket.StatusPolicyViolation, reasonNotAccepted
	}
	ws.Close(code, reason)
	<-relayed
}

// Serve serves the Helper API on l until the unlock ends, then stops. It
// returns nil once the tree is published. A positive deadline discards the
// accepted Shares and fails the unlock when it passes; zero means none. The
// deadline is cleanup, not a security control: the host sets the guest clock.
// limits bound each relay.
func (h *Helper) Serve(l net.Listener, listenProxy func() (net.Listener, error), deadline time.Duration, limits relay.Limits) error {
	srv := &http.Server{Handler: h.Handler(listenProxy, limits), ReadHeaderTimeout: time.Minute}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(l) }()
	var expired <-chan time.Time // nil: never
	if deadline > 0 {
		t := time.NewTimer(deadline)
		defer t.Stop()
		expired = t.C
	}
	select {
	case err := <-served:
		return fmt.Errorf("serve Helper API: %w", err)
	case <-h.done:
	case <-expired:
		h.expire()
	}
	srv.Close()
	<-served
	// Close does not wait for hijacked connections: wait for the last relay
	// to tell its Security Operator the outcome.
	h.relayMu.Lock()
	defer h.relayMu.Unlock()
	if h.Status().State != StatePublished {
		return errors.New("unlock failed")
	}
	return nil
}
