package relay_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/confidential-devhub/trustee-bootstrap/internal/memnet"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/relay"
)

func frame(typ byte, id uint64, payload ...byte) []byte {
	return append(binary.BigEndian.AppendUint64([]byte{typ}, id), payload...)
}

// drain reads ws's frames into a channel until the relay ends. Each read
// error is sent on ended.
func drain(ctx context.Context, ws *websocket.Conn) (frames <-chan []byte, ended <-chan error) {
	f, e := make(chan []byte, 64), make(chan error, 1)
	go func() {
		for {
			_, msg, err := ws.Read(ctx)
			if err != nil {
				e <- err
				return
			}
			f <- msg
		}
	}()
	return f, e
}

// operator runs relay.Operator against a raw guest end. Every Operator
// Verifier connection it makes arrives on verifier, as the verifier's end.
func operator(t *testing.T, limits relay.Limits) (guestWS *websocket.Conn, verifier <-chan net.Conn, done <-chan error) {
	t.Helper()
	guestWS, operatorWS := wsPair(t)
	v, d := make(chan net.Conn, 16), make(chan error, 1)
	go func() {
		d <- relay.Operator(t.Context(), operatorWS, func(context.Context) (net.Conn, error) {
			ours, theirs := net.Pipe()
			v <- theirs
			return ours, nil
		}, limits)
	}()
	return guestWS, v, d
}

func send(t *testing.T, ws *websocket.Conn, frames ...[]byte) {
	t.Helper()
	for _, f := range frames {
		if err := ws.Write(t.Context(), websocket.MessageBinary, f); err != nil {
			t.Fatal(err)
		}
	}
}

// AT-20: a relay holder that breaks the framing rules ends the relay, and the
// CLI dials no more than 8 Operator Verifier connections.
func TestOperatorEndsRelayOnFramingViolation(t *testing.T) {
	opens := func(ids ...uint64) (fs [][]byte) {
		for _, id := range ids {
			fs = append(fs, frame(1, id))
		}
		return fs
	}
	tests := []struct {
		name   string
		frames [][]byte
		dials  int
	}{
		{"conn_id zero", opens(0), 0},
		{"conn_id repeats", opens(1, 1), 1},
		{"conn_id goes back", opens(2, 1), 1},
		{"ninth connection", opens(1, 2, 3, 4, 5, 6, 7, 8, 9), 8},
		{"DATA over 64 KiB", [][]byte{frame(1, 1), frame(2, 1, make([]byte, 64<<10+1)...)}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			guestWS, verifier, done := operator(t, relay.DefaultLimits())
			drain(t.Context(), guestWS)
			go func() {
				for _, f := range tt.frames {
					guestWS.Write(t.Context(), websocket.MessageBinary, f) // fails once the relay ends
				}
			}()
			if err := <-done; err == nil {
				t.Fatal("Operator kept the relay open")
			}
			if got := len(verifier); got != tt.dials {
				t.Errorf("dialled the Operator Verifier %d times, want %d", got, tt.dials)
			}
		})
	}
}

// The full 64 KiB DATA payload and 8 connections stay within the limits.
func TestOperatorAcceptsTheLimits(t *testing.T) {
	guestWS, verifier, done := operator(t, relay.DefaultLimits())
	frames, _ := drain(t.Context(), guestWS)
	for id := range uint64(8) {
		send(t, guestWS, frame(1, id+1))
		c := <-verifier
		if id > 0 {
			<-frames // CLOSE for the older connection
		}
		big := bytes.Repeat([]byte{byte(id)}, 64<<10)
		send(t, guestWS, frame(2, id+1, big...))
		got := make([]byte, len(big))
		if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, big) {
			t.Fatalf("connection %d: read %v", id+1, err)
		}
	}
	guestWS.Close(websocket.StatusNormalClosure, "accepted")
	if err := <-done; websocket.CloseStatus(err) != websocket.StatusNormalClosure {
		t.Errorf("Operator returned %v, want the helper's normal closure", err)
	}
}

// The CDH opens its next connection just before it closes the last (ticket
// 05). A newer OPEN closes the older connection instead of breaking the
// unlock, so only one inner connection is ever open.
func TestOperatorClosesOlderConnectionOnNewerOpen(t *testing.T) {
	guestWS, verifier, _ := operator(t, relay.DefaultLimits())
	frames, _ := drain(t.Context(), guestWS)
	send(t, guestWS, frame(1, 1))
	first := <-verifier
	send(t, guestWS, frame(1, 2))
	if got, want := <-frames, frame(3, 1); !bytes.Equal(got, want) {
		t.Errorf("frame = %v, want CLOSE %v", got, want)
	}
	if _, err := first.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Errorf("older Operator Verifier connection: read %v, want EOF", err)
	}
	second := <-verifier
	send(t, guestWS, frame(2, 2, 'h', 'i'))
	got := make([]byte, 2)
	if _, err := io.ReadFull(second, got); err != nil || string(got) != "hi" {
		t.Errorf("newer connection read %q, %v; want \"hi\"", got, err)
	}
}

func TestGuestClosesOlderConnectionOnNewerOne(t *testing.T) {
	guestWS, operatorWS := wsPair(t)
	var cvm memnet.Network
	go relay.Guest(t.Context(), guestWS, listen(t, &cvm, proxyAddr), relay.DefaultLimits())
	first, err := cvm.DialContext(t.Context(), "tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	readFrame(t, operatorWS) // OPEN 1
	if _, err := cvm.DialContext(t.Context(), "tcp", proxyAddr); err != nil {
		t.Fatal(err)
	}
	for _, want := range [][]byte{frame(3, 1), frame(1, 2)} {
		if got := readFrame(t, operatorWS); !bytes.Equal(got, want) {
			t.Errorf("frame = %v, want %v", got, want)
		}
	}
	if _, err := first.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Errorf("older loopback connection: read %v, want EOF", err)
	}
}

// AT-20: the guest relays at most 8 loopback connections; the ninth ends the
// relay.
func TestGuestEndsRelayOnNinthConnection(t *testing.T) {
	guestWS, operatorWS := wsPair(t)
	var cvm memnet.Network
	proxy := listen(t, &cvm, proxyAddr)
	done := make(chan error, 1)
	go func() { done <- relay.Guest(t.Context(), guestWS, proxy, relay.DefaultLimits()) }()
	frames, ended := drain(t.Context(), operatorWS)
	for i := range 9 {
		if _, err := cvm.DialContext(t.Context(), "tcp", proxyAddr); err != nil {
			t.Fatal(i, err)
		}
	}
	err := <-ended
	if websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
		t.Errorf("relay ended with %v, want a policy violation", err)
	}
	opens := 0
	for len(frames) > 0 {
		if f := <-frames; f[0] == 1 {
			opens++
		}
	}
	if opens != 8 {
		t.Errorf("guest sent %d OPEN frames, want 8", opens)
	}
	<-done
}

// AT-20: each side ends the relay after the idle or total time, with a policy
// violation that names the limit.
func TestRelayEndsAtTimeLimits(t *testing.T) {
	idle := relay.Limits{Idle: 20 * time.Millisecond, Total: 2 * time.Minute}
	total := relay.Limits{Idle: 30 * time.Second, Total: 20 * time.Millisecond}
	sides := map[string]func(t *testing.T, l relay.Limits) (peer *websocket.Conn, done <-chan error){
		"guest": func(t *testing.T, l relay.Limits) (*websocket.Conn, <-chan error) {
			guestWS, operatorWS := wsPair(t)
			var cvm memnet.Network
			proxy := listen(t, &cvm, proxyAddr)
			done := make(chan error, 1)
			go func() { done <- relay.Guest(t.Context(), guestWS, proxy, l) }()
			return operatorWS, done
		},
		"operator": func(t *testing.T, l relay.Limits) (*websocket.Conn, <-chan error) {
			guestWS, _, done := operator(t, l)
			return guestWS, done
		},
	}
	for side, start := range sides {
		for _, tt := range []struct {
			limits relay.Limits
			reason string
		}{{idle, "relay idle"}, {total, "relay open too long"}} {
			t.Run(side+" "+tt.reason, func(t *testing.T) {
				peer, done := start(t, tt.limits)
				_, _, err := peer.Read(t.Context())
				var ce websocket.CloseError
				if !errors.As(err, &ce) || ce.Code != websocket.StatusPolicyViolation || ce.Reason != tt.reason {
					t.Errorf("relay ended with %v, want policy violation %q", err, tt.reason)
				}
				<-done
			})
		}
	}
}

// Frames in either direction keep a relay open past its idle time.
func TestTrafficKeepsRelayOpen(t *testing.T) {
	limits := relay.Limits{Idle: 100 * time.Millisecond, Total: 2 * time.Minute}
	t.Run("frames received", func(t *testing.T) {
		guestWS, _, _ := operator(t, limits)
		_, ended := drain(t.Context(), guestWS)
		for range 15 {
			send(t, guestWS, frame(3, 7)) // CLOSE for no connection: ignored
			time.Sleep(20 * time.Millisecond)
		}
		if len(ended) > 0 {
			t.Errorf("relay ended: %v", <-ended)
		}
	})
	t.Run("frames sent", func(t *testing.T) {
		guestWS, operatorWS := wsPair(t)
		var cvm memnet.Network
		go relay.Guest(t.Context(), guestWS, listen(t, &cvm, proxyAddr), limits)
		_, ended := drain(t.Context(), operatorWS)
		c, err := cvm.DialContext(t.Context(), "tcp", proxyAddr)
		if err != nil {
			t.Fatal(err)
		}
		for range 15 {
			if _, err := c.Write([]byte("x")); err != nil {
				t.Fatal(err)
			}
			time.Sleep(20 * time.Millisecond)
		}
		if len(ended) > 0 {
			t.Errorf("relay ended: %v", <-ended)
		}
	})
}

// The limits can be lowered, never raised or disabled.
func TestLimitsCheck(t *testing.T) {
	tests := []struct {
		name   string
		limits relay.Limits
		ok     bool
	}{
		{"defaults", relay.Limits{Idle: 30 * time.Second, Total: 120 * time.Second}, true},
		{"lowered", relay.Limits{Idle: time.Nanosecond, Total: time.Nanosecond}, true},
		{"idle zero", relay.Limits{Idle: 0, Total: time.Minute}, false},
		{"idle negative", relay.Limits{Idle: -time.Second, Total: time.Minute}, false},
		{"idle raised", relay.Limits{Idle: 30*time.Second + 1, Total: time.Minute}, false},
		{"total zero", relay.Limits{Idle: time.Second, Total: 0}, false},
		{"total negative", relay.Limits{Idle: time.Second, Total: -time.Minute}, false},
		{"total raised", relay.Limits{Idle: time.Second, Total: 120*time.Second + 1}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.limits.Check(); (err == nil) != tt.ok {
				t.Errorf("Check() = %v, want ok %v", err, tt.ok)
			}
		})
	}
	if relay.DefaultLimits() != (relay.Limits{Idle: 30 * time.Second, Total: 120 * time.Second}) {
		t.Errorf("DefaultLimits = %+v, want 30 s idle and 120 s total", relay.DefaultLimits())
	}
}

// Neither side runs a relay with disabled limits.
func TestRelayRefusesDisabledLimits(t *testing.T) {
	guestWS, operatorWS := wsPair(t)
	var cvm memnet.Network
	if err := relay.Guest(t.Context(), guestWS, listen(t, &cvm, proxyAddr), relay.Limits{}); err == nil {
		t.Error("Guest ran without limits")
	}
	if _, err := cvm.DialContext(t.Context(), "tcp", proxyAddr); err == nil {
		t.Error("guest proxy still listening")
	}
	dial := func(context.Context) (net.Conn, error) { return nil, errors.New("dialled") }
	if err := relay.Operator(t.Context(), operatorWS, dial, relay.Limits{}); err == nil {
		t.Error("Operator ran without limits")
	}
}
