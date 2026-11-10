package relay_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"net/http"
	"testing"

	"github.com/coder/websocket"

	"github.com/confidential-devhub/trustee-bootstrap/internal/memnet"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/relay"
)

const (
	proxyAddr    = "127.0.0.1:8081"
	verifierAddr = "127.0.0.1:9000"
)

// wsPair returns the two ends of one WebSocket over an in-memory network:
// the Bootstrap Helper's (accepted) and the Security Operator's (dialled).
func wsPair(t *testing.T) (guest, operator *websocket.Conn) {
	t.Helper()
	var n memnet.Network
	l, err := n.Listen("tcp", "helper:8080")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan *websocket.Conn, 1)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Error(err)
		}
		accepted <- c
	})}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	client := &http.Client{Transport: &http.Transport{DialContext: n.DialContext}}
	operator, _, err = websocket.Dial(t.Context(), "http://helper:8080/", &websocket.DialOptions{HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	guest = <-accepted
	t.Cleanup(func() {
		guest.CloseNow()
		operator.CloseNow()
	})
	return guest, operator
}

func listen(t *testing.T, n *memnet.Network, address string) net.Listener {
	t.Helper()
	l, err := n.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// Bytes the CDH sends through the guest proxy reach the Operator Verifier
// unchanged, its replies come back unchanged, and closing either end closes
// the other.
func TestInnerBytesCrossUnchanged(t *testing.T) {
	guestWS, operatorWS := wsPair(t)
	var cvm, workstation memnet.Network
	proxy := listen(t, &cvm, proxyAddr)
	verifier := listen(t, &workstation, verifierAddr)
	defer verifier.Close()

	echoed := make(chan error, 1)
	go func() {
		c, err := verifier.Accept()
		if err != nil {
			echoed <- err
			return
		}
		_, err = io.Copy(c, c) // until the relay closes the connection
		echoed <- err
	}()
	guestDone := make(chan error, 1)
	go func() { guestDone <- relay.Guest(t.Context(), guestWS, proxy) }()
	operatorDone := make(chan error, 1)
	go func() {
		operatorDone <- relay.Operator(t.Context(), operatorWS, func(ctx context.Context) (net.Conn, error) {
			return workstation.DialContext(ctx, "tcp", verifierAddr)
		})
	}()

	c, err := cvm.DialContext(t.Context(), "tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	want := make([]byte, 200<<10) // several 64 KiB DATA frames
	rand.Read(want)
	go func() {
		if _, err := c.Write(want); err != nil {
			t.Error(err)
		}
	}()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("bytes changed crossing the relay")
	}
	c.Close()
	if err := <-echoed; err != nil {
		t.Errorf("Operator Verifier connection: %v", err)
	}

	guestWS.Close(websocket.StatusNormalClosure, "accepted")
	if err := <-operatorDone; websocket.CloseStatus(err) != websocket.StatusNormalClosure {
		t.Errorf("Operator returned %v, want the helper's normal closure", err)
	}
	<-guestDone
	if _, err := cvm.DialContext(t.Context(), "tcp", proxyAddr); err == nil {
		t.Error("guest proxy still listening after the relay closed")
	}
}

func readFrame(t *testing.T, ws *websocket.Conn) []byte {
	t.Helper()
	typ, msg, err := ws.Read(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if typ != websocket.MessageBinary {
		t.Fatalf("message type %v, want binary", typ)
	}
	return msg
}

// Each loopback connection gets OPEN with a strictly increasing conn_id, its
// bytes as DATA, and CLOSE when it ends.
func TestGuestFramesEachConnection(t *testing.T) {
	guestWS, operatorWS := wsPair(t)
	var cvm memnet.Network
	go relay.Guest(t.Context(), guestWS, listen(t, &cvm, proxyAddr))

	for id := byte(1); id <= 2; id++ {
		c, err := cvm.DialContext(t.Context(), "tcp", proxyAddr)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := readFrame(t, operatorWS), []byte{1, 0, 0, 0, 0, 0, 0, 0, id}; !bytes.Equal(got, want) {
			t.Errorf("frame = %v, want OPEN %v", got, want)
		}
		if _, err := c.Write([]byte("hi")); err != nil {
			t.Fatal(err)
		}
		if got, want := readFrame(t, operatorWS), []byte{2, 0, 0, 0, 0, 0, 0, 0, id, 'h', 'i'}; !bytes.Equal(got, want) {
			t.Errorf("frame = %v, want DATA %v", got, want)
		}
		c.Close()
		if got, want := readFrame(t, operatorWS), []byte{3, 0, 0, 0, 0, 0, 0, 0, id}; !bytes.Equal(got, want) {
			t.Errorf("frame = %v, want CLOSE %v", got, want)
		}
	}
}

func TestGuestEndsRelayOnBadFrame(t *testing.T) {
	tests := []struct {
		name string
		typ  websocket.MessageType
		msg  []byte
	}{
		{"short header", websocket.MessageBinary, []byte{2, 0, 0, 0, 0, 0, 0, 1}},
		{"text message", websocket.MessageText, []byte{2, 0, 0, 0, 0, 0, 0, 0, 1}},
		{"unknown type", websocket.MessageBinary, []byte{4, 0, 0, 0, 0, 0, 0, 0, 1}},
		{"OPEN from the operator", websocket.MessageBinary, []byte{1, 0, 0, 0, 0, 0, 0, 0, 1}},
		{"DATA over 64 KiB", websocket.MessageBinary, append([]byte{2, 0, 0, 0, 0, 0, 0, 0, 1}, make([]byte, 64<<10+1)...)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			guestWS, operatorWS := wsPair(t)
			var cvm memnet.Network
			proxy := listen(t, &cvm, proxyAddr)
			done := make(chan error, 1)
			go func() { done <- relay.Guest(t.Context(), guestWS, proxy) }()
			operatorWS.CloseRead(t.Context()) // takes the guest's close frame
			go operatorWS.Write(t.Context(), tt.typ, tt.msg)
			if err := <-done; err == nil {
				t.Error("Guest kept the relay open")
			}
		})
	}
}
