// Package relay carries the Trustee CVM's guest-loopback connections to a
// Security Operator's Operator Verifier over one WebSocket (spec §4, relay
// framing). Each binary message is one frame: a 9-byte header, type (u8) and
// conn_id (u64 big-endian), then the payload. Inner bytes are copied, never
// parsed or logged.
package relay

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"

	"github.com/coder/websocket"
)

// Frame types.
const (
	frameOpen  byte = 1
	frameData  byte = 2
	frameClose byte = 3
)

const (
	headerLen = 9
	maxData   = 64 << 10 // largest DATA payload
)

var (
	errMalformedFrame = errors.New("relay: malformed frame")
	errUnexpectedOpen = errors.New("relay: the guest side does not accept OPEN")
)

// Guest runs the Bootstrap Helper's side of one relay. It sends OPEN for each
// connection the CDH/AA make to proxy and forwards its bytes both ways, until
// ws closes or ctx ends. It closes proxy and every inner connection before it
// returns.
func Guest(ctx context.Context, ws *websocket.Conn, proxy net.Listener) error {
	m := newMux(ws)
	var accepting sync.WaitGroup
	accepting.Go(func() { m.accept(ctx, proxy) })
	err := m.read(ctx, func(uint64) error { return errUnexpectedOpen })
	proxy.Close()
	accepting.Wait()
	m.closeAll()
	return err
}

// Operator runs the Security Operator's side of one relay. For each OPEN it
// calls dial, which reaches only the operator's own Operator Verifier: no
// address ever comes from a frame. It returns when ws closes or ctx ends,
// with the error that ended the relay; websocket.CloseStatus reads the
// Bootstrap Helper's close code from it.
func Operator(ctx context.Context, ws *websocket.Conn, dial func(context.Context) (net.Conn, error)) error {
	m := newMux(ws)
	err := m.read(ctx, func(id uint64) error {
		c, err := dial(ctx)
		if err != nil {
			m.send(ctx, frameClose, id, nil)
			return nil
		}
		m.start(ctx, id, c)
		return nil
	})
	m.closeAll()
	return err
}

// mux tracks one relay's inner connections by conn_id.
type mux struct {
	ws    *websocket.Conn
	pumps sync.WaitGroup

	mu    sync.Mutex
	conns map[uint64]net.Conn
}

func newMux(ws *websocket.Conn) *mux {
	ws.SetReadLimit(headerLen + maxData)
	return &mux{ws: ws, conns: make(map[uint64]net.Conn)}
}

// send writes one frame. A failed write closes the relay, which ends read
// and with it every inner connection.
func (m *mux) send(ctx context.Context, typ byte, id uint64, payload []byte) {
	msg := append(binary.BigEndian.AppendUint64([]byte{typ}, id), payload...)
	if err := m.ws.Write(ctx, websocket.MessageBinary, msg); err != nil {
		m.ws.CloseNow()
	}
}

// read handles the peer's frames until the relay ends. open handles OPEN.
func (m *mux) read(ctx context.Context, open func(id uint64) error) error {
	for {
		typ, msg, err := m.ws.Read(ctx)
		if err != nil {
			return err
		}
		if typ != websocket.MessageBinary || len(msg) < headerLen {
			return errMalformedFrame
		}
		id := binary.BigEndian.Uint64(msg[1:headerLen])
		switch msg[0] {
		case frameOpen:
			if err := open(id); err != nil {
				return err
			}
		case frameData:
			m.deliver(ctx, id, msg[headerLen:])
		case frameClose:
			m.drop(id)
		default:
			return errMalformedFrame
		}
	}
}

// accept announces each proxy connection with a new, increasing conn_id.
func (m *mux) accept(ctx context.Context, proxy net.Listener) {
	var id uint64
	for {
		c, err := proxy.Accept()
		if err != nil {
			return
		}
		id++
		m.add(id, c)
		m.send(ctx, frameOpen, id, nil)
		m.pumps.Go(func() { m.pump(ctx, id, c) })
	}
}

func (m *mux) start(ctx context.Context, id uint64, c net.Conn) {
	m.add(id, c)
	m.pumps.Go(func() { m.pump(ctx, id, c) })
}

func (m *mux) add(id uint64, c net.Conn) {
	m.mu.Lock()
	m.conns[id] = c
	m.mu.Unlock()
}

// pump sends c's bytes as DATA frames until c ends, then sends CLOSE.
func (m *mux) pump(ctx context.Context, id uint64, c net.Conn) {
	buf := make([]byte, maxData)
	for {
		n, err := c.Read(buf)
		if err != nil { // a net.Conn read that fails returns no bytes
			break
		}
		m.send(ctx, frameData, id, buf[:n])
	}
	m.closeInner(ctx, id)
}

// deliver writes a DATA payload to its inner connection. Data for a
// connection already closed here is dropped; the peer gets our CLOSE.
func (m *mux) deliver(ctx context.Context, id uint64, p []byte) {
	m.mu.Lock()
	c := m.conns[id]
	m.mu.Unlock()
	if c == nil {
		return
	}
	if _, err := c.Write(p); err != nil {
		m.closeInner(ctx, id)
	}
}

// closeInner closes inner connection id, if still open, and tells the peer.
func (m *mux) closeInner(ctx context.Context, id uint64) {
	if m.drop(id) {
		m.send(ctx, frameClose, id, nil)
	}
}

// drop closes and forgets inner connection id. It reports whether it was open.
func (m *mux) drop(id uint64) bool {
	m.mu.Lock()
	c, ok := m.conns[id]
	delete(m.conns, id)
	m.mu.Unlock()
	if ok {
		c.Close()
	}
	return ok
}

// closeAll closes every inner connection and waits for their pumps.
func (m *mux) closeAll() {
	m.mu.Lock()
	for _, c := range m.conns {
		c.Close()
	}
	clear(m.conns)
	m.mu.Unlock()
	m.pumps.Wait()
}
