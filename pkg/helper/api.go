package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/confidential-devhub/trustee-bootstrap/internal/audit"
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
	var statusLimit rateLimit
	mux.HandleFunc("GET "+StatusPath, func(w http.ResponseWriter, _ *http.Request) {
		if !statusLimit.allow(time.Now()) {
			http.Error(w, "too many status requests", http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(h.Status())
	})
	mux.HandleFunc("GET "+RelayPath, func(w http.ResponseWriter, r *http.Request) {
		h.serveRelay(w, r, listenProxy, limits)
	})
	return mux
}

// StatusPerSecond is how many status requests the Helper API answers each
// second, from all clients together (spec §4).
const StatusPerSecond = 10

// rateLimit allows StatusPerSecond calls in each one-second window.
// ponytail: one global window, so a noisy client can crowd out the others
// for a second; key it by client address if that matters.
type rateLimit struct {
	mu    sync.Mutex
	start time.Time // the current window's start
	n     int       // calls in it
}

func (r *rateLimit) allow(now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if now.Sub(r.start) >= time.Second {
		r.start, r.n = now, 0
	}
	r.n++
	return r.n <= StatusPerSecond
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
	h.audit.Info(audit.RelayOpened, "remote", r.RemoteAddr)
	proxy, err := listenProxy()
	if err != nil {
		h.closeRelay(ws, websocket.StatusInternalError, "guest proxy unavailable", err)
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
	_, err = h.CollectShare(ctx)
	if err != nil {
		code, reason = websocket.StatusPolicyViolation, reasonNotAccepted
	}
	h.closeRelay(ws, code, reason, err)
	<-relayed
}

// closeRelay records the relay's outcome, then tells the Security Operator.
func (h *Helper) closeRelay(ws *websocket.Conn, code websocket.StatusCode, reason string, err error) {
	h.audit.Info(audit.RelayClosed, "code", int(code), "reason", reason, audit.Error(err))
	ws.Close(code, reason)
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
