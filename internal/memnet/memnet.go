// Package memnet is an in-memory stand-in for TCP, for tests. The development
// sandbox denies TCP listen, so tests inject these listeners and dialers where
// production code uses net.Listen and net.Dialer.
package memnet

import (
	"context"
	"net"
	"sync"
	"syscall"
)

// Network maps addresses to listeners. The zero value is an empty network.
type Network struct {
	listeners sync.Map // address -> *listener
}

// Listen binds a listener to address, taken literally: "127.0.0.1:0" stays
// port 0. A second Listen on a bound address fails, as net.Listen would.
func (n *Network) Listen(_, address string) (net.Listener, error) {
	l := &listener{network: n, addr: address, conns: make(chan net.Conn), done: make(chan struct{})}
	if _, bound := n.listeners.LoadOrStore(address, l); bound {
		return nil, &net.OpError{Op: "listen", Net: "tcp", Err: syscall.EADDRINUSE}
	}
	return l, nil
}

// DialContext connects to the listener bound at address over a net.Pipe.
func (n *Network) DialContext(ctx context.Context, _, address string) (net.Conn, error) {
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
	v, bound := n.listeners.Load(address)
	if !bound {
		return nil, refused
	}
	l := v.(*listener)
	client, server := net.Pipe()
	select {
	case l.conns <- server:
		return client, nil
	case <-l.done:
	case <-ctx.Done():
	}
	client.Close()
	server.Close()
	return nil, refused
}

type listener struct {
	network *Network
	addr    string
	conns   chan net.Conn
	done    chan struct{}
	once    sync.Once
}

func (l *listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

// Close unbinds the address.
func (l *listener) Close() error {
	l.once.Do(func() {
		l.network.listeners.CompareAndDelete(l.addr, l)
		close(l.done)
	})
	return nil
}

func (l *listener) Addr() net.Addr { return addr(l.addr) }

type addr string

func (addr) Network() string  { return "tcp" }
func (a addr) String() string { return string(a) }
