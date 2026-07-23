package netutil

import (
	"context"
	"crypto/tls"
	"net"

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

var _ net.Listener = (*QUICStreamListener)(nil)

type QUICStreamListener struct {
	listener *quic.Listener
	ch       chan *QUICStreamConn
	ctx      context.Context
	cancel   context.CancelCauseFunc
}

func NewQUICStreamListener(listener *quic.Listener) *QUICStreamListener {
	ctx, cancel := context.WithCancelCause(context.Background())
	l := &QUICStreamListener{
		listener: listener,
		ch:       make(chan *QUICStreamConn),
		ctx:      ctx,
		cancel:   cancel,
	}
	go l.acceptConns()
	return l
}

func (l *QUICStreamListener) acceptConns() {
	for {
		conn, err := l.listener.Accept(l.ctx)
		if err != nil {
			l.cancel(err)
			return
		}
		go l.acceptStreams(conn)
	}
}

func (l *QUICStreamListener) acceptStreams(conn *quic.Conn) {
	localAddr := conn.LocalAddr()
	remoteAddr := conn.RemoteAddr()
	connectionState := conn.ConnectionState().TLS
	for {
		stream, err := conn.AcceptStream(l.ctx)
		if err != nil {
			return
		}
		select {
		case <-l.ctx.Done():
			stream.Close()
			return
		default:
		}
		select {
		case l.ch <- &QUICStreamConn{stream, localAddr, remoteAddr, connectionState}:
		case <-l.ctx.Done():
			stream.Close()
			return
		}
	}
}

func (l *QUICStreamListener) Accept() (net.Conn, error) {
	select {
	case <-l.ctx.Done():
		return nil, context.Cause(l.ctx)
	default:
	}
	select {
	case streamConn := <-l.ch:
		return streamConn, nil
	case <-l.ctx.Done():
		return nil, context.Cause(l.ctx)
	}
}

func (l *QUICStreamListener) Close() error {
	l.cancel(net.ErrClosed)
	return l.listener.Close()
}

func (l *QUICStreamListener) Addr() net.Addr {
	return l.listener.Addr()
}
