package helper_test

import (
	"net"
	"net/http"
	"os"
	"slices"
	"testing"

	"github.com/coder/websocket"

	"github.com/confidential-devhub/trustee-bootstrap/internal/memnet"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/helper"
)

// serve runs h.Serve on an in-memory listener and returns its result channel.
func serve(t *testing.T, h *helper.Helper) (<-chan error, *memnet.Network) {
	t.Helper()
	var n memnet.Network
	l, err := n.Listen("tcp", "helper:8080")
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() {
		served <- h.Serve(l, func() (net.Listener, error) { return n.Listen("tcp", "127.0.0.1:8081") })
	}()
	return served, &n
}

// openRelay serves h's Helper API in memory, opens one relay and returns the
// code the helper closed it with.
func openRelay(t *testing.T, h *helper.Helper) websocket.StatusCode {
	t.Helper()
	var n memnet.Network
	l, err := n.Listen("tcp", "helper:8080")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h.Handler(func() (net.Listener, error) { return n.Listen("tcp", "127.0.0.1:8081") })}
	go srv.Serve(l)
	defer srv.Close()
	client := &http.Client{Transport: &http.Transport{DialContext: n.DialContext}}
	ws, _, err := websocket.Dial(t.Context(), "http://helper:8080"+helper.RelayPath, &websocket.DialOptions{HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	_, _, err = ws.Read(t.Context())
	return websocket.CloseStatus(err)
}

// The fake CDH here answers in process; pkg/cli's tracer sends it through the
// guest proxy and the relay.
func TestRelayClosesWithOutcome(t *testing.T) {
	manifest, bundle, payloads := ceremonyFixture(t)
	tests := []struct {
		name     string
		cdh      helper.CDH
		code     websocket.StatusCode
		accepted []int
	}{
		{"Share accepted", fakeCDH(t, payloads[1]), websocket.StatusNormalClosure, []int{2}},
		{"no Share from the CDH", fakeCDH(t), websocket.StatusPolicyViolation, []int{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, _ := newHelper(t, manifest, bundle, tt.cdh)
			if got := openRelay(t, h); got != tt.code {
				t.Errorf("relay closed with %v, want %v", got, tt.code)
			}
			if got := h.Status().Accepted; !slices.Equal(got, tt.accepted) {
				t.Errorf("accepted = %v, want %v", got, tt.accepted)
			}
		})
	}
}

func TestServeStopsOncePublished(t *testing.T) {
	manifest, bundle, payloads := ceremonyFixture(t)
	h, _ := newHelper(t, manifest, bundle, fakeCDH(t, payloads[0], payloads[1]))
	served, n := serve(t, h)

	for range 2 {
		if _, err := h.CollectShare(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if err := <-served; err != nil {
		t.Fatalf("Serve = %v, want nil once published", err)
	}
	if _, err := n.DialContext(t.Context(), "tcp", "helper:8080"); err == nil {
		t.Error("Helper API still listening after publication")
	}
	if got := h.Status().State; got != helper.StatePublished {
		t.Errorf("state = %s, want %s", got, helper.StatePublished)
	}
	if _, err := h.CollectShare(t.Context()); err == nil {
		t.Error("CollectShare counted a Share after publication")
	}
}

// Shares from another Key Ceremony rebuild a key that can't open the bundle.
func TestServeFailsWhenUnsealFails(t *testing.T) {
	manifest, bundle, _ := ceremonyFixture(t)
	_, _, otherPayloads := ceremonyFixture(t)
	h, out := newHelper(t, manifest, bundle, fakeCDH(t, otherPayloads[0], otherPayloads[1]))
	served, _ := serve(t, h)

	if _, err := h.CollectShare(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := h.CollectShare(t.Context()); err == nil {
		t.Fatal("unseal succeeded with the wrong key")
	}
	if err := <-served; err == nil {
		t.Fatal("Serve = nil, want the unlock failure")
	}
	if got := h.Status().State; got != helper.StateFailed {
		t.Errorf("state = %s, want %s", got, helper.StateFailed)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Error("tree published")
	}
}

func TestServeFailsWhenListenerDies(t *testing.T) {
	manifest, bundle, _ := ceremonyFixture(t)
	h, _ := newHelper(t, manifest, bundle, fakeCDH(t))
	var n memnet.Network
	l, err := n.Listen("tcp", "helper:8080")
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	if err := h.Serve(l, nil); err == nil {
		t.Fatal("Serve = nil on a closed listener")
	}
}
