package netutil

import (
	"context"
	"crypto/tls"
	"net"
	"sync"

	"github.com/quic-go/quic-go"
)

var _ net.Conn = (*QUICStreamConn)(nil)

type QUICStreamConn struct {
	*quic.Stream
	localAddr       net.Addr
	remoteAddr      net.Addr
	connectionState tls.ConnectionState
}

func (c *QUICStreamConn) LocalAddr() net.Addr                  { return c.localAddr }
func (c *QUICStreamConn) RemoteAddr() net.Addr                 { return c.remoteAddr }
func (c *QUICStreamConn) ConnectionState() tls.ConnectionState { return c.connectionState }

var _ QUICListener = (*quic.Listener)(nil)
var _ QUICListener = (*quic.EarlyListener)(nil)

type QUICListener interface {
	Accept(ctx context.Context) (*quic.Conn, error)
	Addr() net.Addr
	Close() error
}

var _ net.Listener = (*QUICStreamListener)(nil)

type QUICStreamListener struct {
	ql     QUICListener
	ch     chan *QUICStreamConn
	ctx    context.Context
	cancel context.CancelCauseFunc
	closed chan struct{}
	conns  map[*quic.Conn]struct{}
	mu     sync.Mutex
}

func NewQUICStreamListener(quicListener QUICListener) *QUICStreamListener {
	ctx, cancel := context.WithCancelCause(context.Background())
	sl := &QUICStreamListener{
		ql:     quicListener,
		ch:     make(chan *QUICStreamConn),
		ctx:    ctx,
		cancel: cancel,
		closed: make(chan struct{}, 1),
		conns:  make(map[*quic.Conn]struct{}),
	}
	go func() {
		sl.acceptConns()
		sl.closed <- struct{}{}
		close(sl.closed)
	}()
	return sl
}

func (sl *QUICStreamListener) acceptConns() {
	for {
		conn, err := sl.ql.Accept(context.Background())
		if err != nil {
			sl.ql.Close()
			sl.cancel(err)
			return
		}
		sl.mu.Lock()
		sl.conns[conn] = struct{}{}
		sl.mu.Unlock()
		select {
		case <-sl.ctx.Done():
		default:
			go func() {
				sl.acceptStreams(conn)
				sl.mu.Lock()
				delete(sl.conns, conn)
				sl.mu.Unlock()
			}()
		}
	}
}

func (sl *QUICStreamListener) acceptStreams(conn *quic.Conn) {
	localAddr := conn.LocalAddr()
	remoteAddr := conn.RemoteAddr()
	connectionState := conn.ConnectionState()
	// hack: use TLSUnique, nil for TLS1.3, to store QUIC version
	switch connectionState.Version {
	case quic.Version1:
		connectionState.TLS.TLSUnique = []byte("QUICv1")
	case quic.Version2:
		connectionState.TLS.TLSUnique = []byte("QUICv2")
	default:
		connectionState.TLS.TLSUnique = []byte(connectionState.Version.String())
	}
	// hack: use NegotiatedProtocolIsMutual, deprecated, to store Used0RTT
	connectionState.TLS.NegotiatedProtocolIsMutual = connectionState.Used0RTT
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		select {
		case sl.ch <- &QUICStreamConn{stream, localAddr, remoteAddr, connectionState.TLS}:
		case <-sl.ctx.Done():
			return
		}
	}
}

func (sl *QUICStreamListener) Accept() (net.Conn, error) {
	select {
	case <-sl.ctx.Done():
		return nil, context.Cause(sl.ctx)
	default:
	}
	select {
	case streamConn := <-sl.ch:
		return streamConn, nil
	case <-sl.ctx.Done():
		return nil, context.Cause(sl.ctx)
	}
}

func (sl *QUICStreamListener) Close() error {
	sl.ql.Close()
	sl.cancel(net.ErrClosed)
	_, ok := <-sl.closed
	if ok {
		var wg sync.WaitGroup
		sl.mu.Lock()
		for conn := range sl.conns {
			wg.Go(func() {
				conn.CloseWithError(0, "going away")
			})
		}
		clear(sl.conns)
		sl.mu.Unlock()
		wg.Wait()
	}
	return nil
}

func (sl *QUICStreamListener) Addr() net.Addr {
	return sl.ql.Addr()
}
