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
	"fmt"
	"net"
	"sync"
	"time"

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
	maxConns  = 8        // inner connections per relay
)

var (
	errMalformedFrame = errors.New("relay: malformed frame")
	errUnexpectedOpen = errors.New("relay: the guest side does not accept OPEN")
	errConnOrder      = errors.New("relay: conn_id did not increase")
	errTooManyConns   = errors.New("relay: over 8 inner connections")
)

// Limits bound how long one relay stays open (spec §4). A deployment can
// lower them but not raise or disable them.
type Limits struct {
	Idle  time.Duration // longest time with no frame in either direction
	Total time.Duration // longest time a relay stays open
}

// DefaultLimits returns the spec's limits: 30 s idle, 120 s total.
func DefaultLimits() Limits {
	return Limits{Idle: 30 * time.Second, Total: 120 * time.Second}
}

// Check refuses a limit that is zero, negative or above its default.
func (l Limits) Check() error {
	maxLimits := DefaultLimits()
	if l.Idle <= 0 || l.Idle > maxLimits.Idle {
		return fmt.Errorf("relay idle timeout %v: want more than 0 and at most %v", l.Idle, maxLimits.Idle)
	}
	if l.Total <= 0 || l.Total > maxLimits.Total {
		return fmt.Errorf("relay total timeout %v: want more than 0 and at most %v", l.Total, maxLimits.Total)
	}
	return nil
}

// Guest runs the Bootstrap Helper's side of one relay. It sends OPEN for each
// connection the CDH/AA make to proxy and forwards its bytes both ways, until
// ws closes, ctx ends or a limit ends the relay. It closes proxy and every
// inner connection before it returns.
func Guest(ctx context.Context, ws *websocket.Conn, proxy net.Listener, limits Limits) error {
	m, err := newMux(ws, limits)
	if err != nil {
		proxy.Close()
		return err
	}
	var accepting sync.WaitGroup
	accepting.Go(func() { m.accept(ctx, proxy) })
	err = m.read(ctx, func(uint64) error { return errUnexpectedOpen })
	proxy.Close()
	accepting.Wait()
	m.closeAll()
	return err
}

// Operator runs the Security Operator's side of one relay. For each OPEN it
// calls dial, which reaches only the operator's own Operator Verifier: no
// address ever comes from a frame. It returns when ws closes, ctx ends or the
// relay breaks a limit, with the error that ended the relay;
// websocket.CloseStatus reads the Bootstrap Helper's close code from it.
func Operator(ctx context.Context, ws *websocket.Conn, dial func(context.Context) (net.Conn, error), limits Limits) error {
	m, err := newMux(ws, limits)
	if err != nil {
		return err
	}
	err = m.read(ctx, func(id uint64) error {
		if err := m.open(ctx, id, nil); err != nil {
			return err
		}
		c, err := dial(ctx)
		if err != nil {
			m.send(ctx, frameClose, id, nil)
			return nil
		}
		m.attach(c)
		m.pumps.Go(func() { m.pump(ctx, id, c) })
		return nil
	})
	m.closeAll()
	return err
}

// mux runs one relay. At most one inner connection is open at a time: the
// one with the newest conn_id.
type mux struct {
	ws          *websocket.Conn
	idleTimeout time.Duration
	idle, total *time.Timer
	pumps       sync.WaitGroup

	mu     sync.Mutex
	id     uint64   // newest conn_id
	opened int      // inner connections opened so far
	conn   net.Conn // inner connection id; nil once closed
}

func newMux(ws *websocket.Conn, limits Limits) (*mux, error) {
	if err := limits.Check(); err != nil {
		return nil, err
	}
	ws.SetReadLimit(headerLen + maxData)
	m := &mux{ws: ws, idleTimeout: limits.Idle}
	m.idle = time.AfterFunc(limits.Idle, func() { m.end("relay idle") })
	m.total = time.AfterFunc(limits.Total, func() { m.end("relay open too long") })
	return m, nil
}

// end closes the relay with reason. It closes the inner connection first, so
// a read loop blocked writing to it moves on and sees the relay close.
func (m *mux) end(reason string) {
	m.closeConn()
	m.ws.Close(websocket.StatusPolicyViolation, reason)
}

// send writes one frame. A failed write closes the relay, which ends read
// and with it every inner connection.
func (m *mux) send(ctx context.Context, typ byte, id uint64, payload []byte) {
	msg := append(binary.BigEndian.AppendUint64([]byte{typ}, id), payload...)
	if err := m.ws.Write(ctx, websocket.MessageBinary, msg); err != nil {
		m.ws.CloseNow()
		return
	}
	m.idle.Reset(m.idleTimeout)
}

// read handles the peer's frames until the relay ends. open handles OPEN.
func (m *mux) read(ctx context.Context, open func(id uint64) error) error {
	for {
		typ, msg, err := m.ws.Read(ctx)
		if err != nil {
			return err
		}
		m.idle.Reset(m.idleTimeout)
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

// accept announces each proxy connection with a new, increasing conn_id. The
// ninth connection ends the relay.
func (m *mux) accept(ctx context.Context, proxy net.Listener) {
	for id := uint64(1); ; id++ { // one id per iteration: each pump keeps its own
		c, err := proxy.Accept()
		if err != nil {
			return
		}
		if err := m.open(ctx, id, c); err != nil {
			c.Close()
			m.end("too many inner connections")
			return
		}
		m.send(ctx, frameOpen, id, nil)
		m.pumps.Go(func() { m.pump(ctx, id, c) })
	}
}

// open makes c, which may come later through attach, inner connection id.
// conn_id must increase and a relay opens at most maxConns. A newer
// connection closes the older one and tells the peer: the CDH opens its next
// connection just before it closes the last, so refusing the overlap would
// break every unlock.
func (m *mux) open(ctx context.Context, id uint64, c net.Conn) error {
	m.mu.Lock()
	if id <= m.id {
		m.mu.Unlock()
		return errConnOrder
	}
	if m.opened >= maxConns {
		m.mu.Unlock()
		return errTooManyConns
	}
	older, olderID := m.conn, m.id
	m.id, m.conn = id, c
	m.opened++
	m.mu.Unlock()
	if older != nil {
		older.Close()
		m.send(ctx, frameClose, olderID, nil)
	}
	return nil
}

// attach sets the newest inner connection once dialled.
func (m *mux) attach(c net.Conn) {
	m.mu.Lock()
	m.conn = c
	m.mu.Unlock()
}

// current returns inner connection id, or nil if it is closed or not the newest.
func (m *mux) current(id uint64) net.Conn {
	m.mu.Lock()
	defer m.mu.Unlock()
	if id != m.id {
		return nil
	}
	return m.conn
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
// connection already closed here is dropped; the peer gets our CLOSE. The
// write blocks the relay until the connection takes the bytes: that is the
// backpressure.
func (m *mux) deliver(ctx context.Context, id uint64, p []byte) {
	c := m.current(id)
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

// drop closes inner connection id. It reports whether it was open.
func (m *mux) drop(id uint64) bool {
	m.mu.Lock()
	c := m.conn
	open := id == m.id && c != nil
	if open {
		m.conn = nil
	}
	m.mu.Unlock()
	if open {
		c.Close()
	}
	return open
}

// closeConn closes the open inner connection, if any.
func (m *mux) closeConn() {
	m.mu.Lock()
	c := m.conn
	m.conn = nil
	m.mu.Unlock()
	if c != nil {
		c.Close()
	}
}

// closeAll closes the inner connection, waits for the pumps and stops the
// timers.
func (m *mux) closeAll() {
	m.closeConn()
	m.pumps.Wait()
	m.idle.Stop()
	m.total.Stop()
}
