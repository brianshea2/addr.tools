package stun

import (
	"log"
	"net"
	"sync/atomic"

	"github.com/pion/stun/v3"
)

const (
	MTU = 1500
)

type Server struct {
	Addr  string
	count atomic.Uint64
}

func (srv *Server) RequestCount() uint64 {
	return srv.count.Load()
}

func (srv *Server) ListenAndServe() error {
	addr := srv.Addr
	if addr == "" {
		addr = ":3478"
	}
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	return srv.serve(conn)
}

func (srv *Server) serve(conn net.PacketConn) error {
	msg := &stun.Message{Raw: make([]byte, MTU)}
	for {
		msg.Raw = msg.Raw[:MTU]
		n, addr, err := conn.ReadFrom(msg.Raw)
		if err != nil {
			return err
		}
		msg.Raw = msg.Raw[:n]
		err = msg.Decode()
		if err != nil {
			// ignore unknown packets
			continue
		}
		srv.handleMessage(conn, addr, msg)
		srv.count.Add(1)
	}
}

func (srv *Server) handleMessage(conn net.PacketConn, addr net.Addr, msg *stun.Message) {
	if msg.Type.Method != stun.MethodBinding || msg.Type.Class != stun.ClassRequest {
		return
	}
	msg.Type.Class = stun.ClassSuccessResponse
	msg.Attributes = msg.Attributes[:0]
	msg.Raw = msg.Raw[:0]
	msg.Length = 0
	msg.WriteHeader()
	xor := &stun.XORMappedAddress{
		IP:   addr.(*net.UDPAddr).IP,
		Port: addr.(*net.UDPAddr).Port,
	}
	xor.AddTo(msg)
	_, err := conn.WriteTo(msg.Raw, addr)
	if err != nil {
		log.Printf("[warn] stun: Write: %v (%s)", err, addr)
	}
}
