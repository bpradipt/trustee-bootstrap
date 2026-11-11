package helper_test

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/coder/websocket"

	"github.com/confidential-devhub/trustee-bootstrap/internal/memnet"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/helper"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/relay"
)

// serve runs h.Serve on an in-memory listener and returns its result channel.
func serve(t *testing.T, h *helper.Helper, deadline time.Duration) (<-chan error, *memnet.Network) {
	t.Helper()
	var n memnet.Network
	l, err := n.Listen("tcp", "helper:8080")
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() {
		served <- h.Serve(l, func() (net.Listener, error) { return n.Listen("tcp", "127.0.0.1:8081") }, deadline, relay.DefaultLimits())
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
	srv := &http.Server{Handler: h.Handler(func() (net.Listener, error) { return n.Listen("tcp", "127.0.0.1:8081") }, relay.DefaultLimits())}
	go srv.Serve(l)
	defer srv.Close()
	return relayOn(t, &n)
}

// relayOn opens one relay to the Helper API at helper:8080 on n and returns
// the code the helper closed it with.
func relayOn(t *testing.T, n *memnet.Network) websocket.StatusCode {
	t.Helper()
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
	manifest, bundle, payloads, out := ceremonyFixture(t)
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
			h := newHelper(t, manifest, bundle, out, tt.cdh)
			if got := openRelay(t, h); got != tt.code {
				t.Errorf("relay closed with %v, want %v", got, tt.code)
			}
			if got := h.Status().Accepted; !slices.Equal(got, tt.accepted) {
				t.Errorf("accepted = %v, want %v", got, tt.accepted)
			}
		})
	}
}

// Status answers StatusPerSecond requests a second, from all clients
// together, and 429 to the rest.
func TestStatusIsRateLimited(t *testing.T) {
	manifest, bundle, _, out := ceremonyFixture(t)
	h := newHelper(t, manifest, bundle, out, fakeCDH(t))
	synctest.Test(t, func(t *testing.T) {
		api := h.Handler(nil, relay.DefaultLimits())
		get := func() int {
			rec := httptest.NewRecorder()
			api.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, helper.StatusPath, nil))
			return rec.Code
		}
		for i := range helper.StatusPerSecond {
			if code := get(); code != http.StatusOK {
				t.Fatalf("request %d: HTTP %d, want 200", i+1, code)
			}
		}
		if code := get(); code != http.StatusTooManyRequests {
			t.Fatalf("request %d in one second: HTTP %d, want 429", helper.StatusPerSecond+1, code)
		}
		time.Sleep(time.Second)
		if code := get(); code != http.StatusOK {
			t.Fatalf("a second later: HTTP %d, want 200", code)
		}
	})
}

func TestServeStopsOncePublished(t *testing.T) {
	manifest, bundle, payloads, out := ceremonyFixture(t)
	h := newHelper(t, manifest, bundle, out, fakeCDH(t, payloads[0], payloads[1]))
	served, n := serve(t, h, 0)

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

// AT-10, within one boot: with no --deadline, a Share released earlier stays
// valid, and a later Share for the same bundle completes the unlock.
func TestServeWithoutDeadlineKeepsAcceptedShares(t *testing.T) {
	manifest, bundle, payloads, out := ceremonyFixture(t)
	h := newHelper(t, manifest, bundle, out, fakeCDH(t, payloads[0], payloads[1]))
	served, n := serve(t, h, 0)

	if got := relayOn(t, n); got != websocket.StatusNormalClosure {
		t.Fatalf("relay closed with %v, want the Share accepted", got)
	}
	if published, err := h.CollectShare(t.Context()); err != nil || !published {
		t.Fatalf("later Share: CollectShare = %v, %v; want published", published, err)
	}
	if err := <-served; err != nil {
		t.Fatalf("Serve = %v, want nil once published", err)
	}
}

// A bundle sealed to another Key Ceremony's recipient can't be opened, even
// when the Shares name it.
func TestServeFailsWhenUnsealFails(t *testing.T) {
	manifest, _, payloads, out := ceremonyFixture(t)
	_, otherBundle, otherPayloads, _ := ceremonyFixture(t)
	for i := range payloads {
		payloads[i].BundleSHA256 = otherPayloads[i].BundleSHA256
	}
	h := newHelper(t, manifest, otherBundle, out, fakeCDH(t, payloads[0], payloads[1]))
	served, _ := serve(t, h, 0)

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

// --deadline is cleanup: when it expires, the helper discards the Shares it
// accepted and fails, and counts no Share after that.
func TestServeDeadlineDiscardsShares(t *testing.T) {
	manifest, bundle, payloads, out := ceremonyFixture(t)
	h := newHelper(t, manifest, bundle, out, fakeCDH(t, payloads[0], payloads[1]))
	if _, err := h.CollectShare(t.Context()); err != nil {
		t.Fatal(err)
	}
	served, _ := serve(t, h, time.Millisecond)

	if err := <-served; err == nil {
		t.Fatal("Serve = nil after the deadline")
	}
	if got := h.Status().State; got != helper.StateFailed {
		t.Errorf("state = %s, want %s", got, helper.StateFailed)
	}
	if _, err := h.CollectShare(t.Context()); err == nil {
		t.Error("CollectShare counted a Share after the deadline")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Error("tree published after the deadline")
	}
}

func TestServeFailsWhenListenerDies(t *testing.T) {
	manifest, bundle, _, out := ceremonyFixture(t)
	h := newHelper(t, manifest, bundle, out, fakeCDH(t))
	var n memnet.Network
	l, err := n.Listen("tcp", "helper:8080")
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	if err := h.Serve(l, nil, 0, relay.DefaultLimits()); err == nil {
		t.Fatal("Serve = nil on a closed listener")
	}
}

// AT-19: while one relay is open, a second gets 409. The open relay still
// ends at its idle limit.
func TestSecondConcurrentRelayGetsConflict(t *testing.T) {
	manifest, bundle, _, out := ceremonyFixture(t)
	cdhCalled := make(chan struct{})
	stalled := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(cdhCalled)
		<-r.Context().Done() // the CDH never answers
	})
	h := newHelper(t, manifest, bundle, out, helper.CDH{URL: "http://127.0.0.1:8006", Client: &http.Client{Transport: serveInProcess{stalled}}})
	var n memnet.Network
	l, err := n.Listen("tcp", "helper:8080")
	if err != nil {
		t.Fatal(err)
	}
	limits, err := relay.NewLimits(50*time.Millisecond, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h.Handler(func() (net.Listener, error) { return n.Listen("tcp", "127.0.0.1:8081") }, limits)}
	go srv.Serve(l)
	defer srv.Close()

	first := make(chan error, 1)
	client := &http.Client{Transport: &http.Transport{DialContext: n.DialContext}}
	go func() {
		ws, _, err := websocket.Dial(t.Context(), "http://helper:8080"+helper.RelayPath, &websocket.DialOptions{HTTPClient: client})
		if err != nil {
			first <- err
			return
		}
		_, _, err = ws.Read(t.Context())
		first <- err
	}()
	<-cdhCalled
	_, resp, err := websocket.Dial(t.Context(), "http://helper:8080"+helper.RelayPath, &websocket.DialOptions{HTTPClient: client})
	if err == nil || resp == nil || resp.StatusCode != http.StatusConflict {
		t.Errorf("second relay: %v, want 409", err)
	}
	var ce websocket.CloseError
	if err := <-first; !errors.As(err, &ce) || ce.Reason != "relay idle" {
		t.Errorf("first relay ended with %v, want the idle limit", err)
	}
}
