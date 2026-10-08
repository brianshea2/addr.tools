package dnsutil

import (
	"crypto/tls"
	"log"
	"net"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

func MsgAcceptFunc(dh dns.Header) dns.MsgAcceptAction {
	// ignore messages with the response flag set
	if isResponse := dh.Bits&(1<<15) != 0; isResponse {
		return dns.MsgIgnore
	}
	// filter opcodes
	if opcode := int(dh.Bits>>11) & 0xF; !(opcode == dns.OpcodeQuery || opcode == dns.OpcodeUpdate) {
		return dns.MsgRejectNotImplemented
	}
	// must have exactly one question/zone
	if dh.Qdcount != 1 {
		return dns.MsgReject
	}
	return dns.MsgAccept
}

type LoggingResponseWriter struct {
	dns.ResponseWriter
	start     time.Time
	rcode     int
	anCount   int
	nsCount   int
	exCount   int
	connState *tls.ConnectionState
}

func (w *LoggingResponseWriter) ConnectionState() *tls.ConnectionState { return w.connState }

func (w *LoggingResponseWriter) WriteMsg(m *dns.Msg) error {
	w.rcode = m.Rcode
	w.anCount = len(m.Answer)
	w.nsCount = len(m.Ns)
	w.exCount = len(m.Extra)
	return w.ResponseWriter.WriteMsg(m)
}

type LoggingHandler struct {
	Next      dns.Handler
	Logger    *log.Logger
	ip4Count  atomic.Uint64
	ip6Count  atomic.Uint64
	udpCount  atomic.Uint64
	tcpCount  atomic.Uint64
	tlsCount  atomic.Uint64
	quicCount atomic.Uint64
}

func (h *LoggingHandler) IP4Count() uint64  { return h.ip4Count.Load() }
func (h *LoggingHandler) IP6Count() uint64  { return h.ip6Count.Load() }
func (h *LoggingHandler) UDPCount() uint64  { return h.udpCount.Load() }
func (h *LoggingHandler) TCPCount() uint64  { return h.tcpCount.Load() }
func (h *LoggingHandler) TLSCount() uint64  { return h.tlsCount.Load() }
func (h *LoggingHandler) QUICCount() uint64 { return h.quicCount.Load() }

func (h *LoggingHandler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	lw := &LoggingResponseWriter{
		ResponseWriter: w,
		start:          time.Now(),
		connState:      w.(dns.ConnectionStater).ConnectionState(),
	}
	w = lw
	h.Next.ServeDNS(w, req)
	switch a := w.RemoteAddr().(type) {
	case *net.UDPAddr:
		if a.IP.To4() == nil {
			h.ip6Count.Add(1)
		} else {
			h.ip4Count.Add(1)
		}
		if w.(dns.ConnectionStater).ConnectionState() != nil {
			h.quicCount.Add(1)
		} else {
			h.udpCount.Add(1)
		}
	case *net.TCPAddr:
		if a.IP.To4() == nil {
			h.ip6Count.Add(1)
		} else {
			h.ip4Count.Add(1)
		}
		if w.(dns.ConnectionStater).ConnectionState() != nil {
			h.tlsCount.Add(1)
		} else {
			h.tcpCount.Add(1)
		}
	}
	if h.Logger != nil {
		h.Logger.Printf(
			"%vms %s %s %s %s %s %s an:%v ns:%v ex:%v %s",
			time.Since(lw.start).Milliseconds(),
			GetProtocol(w),
			dns.RcodeToString[lw.rcode],
			dns.OpcodeToString[req.Opcode],
			dns.Class(req.Question[0].Qclass),
			dns.Type(req.Question[0].Qtype),
			req.Question[0].Name,
			lw.anCount,
			lw.nsCount,
			lw.exCount,
			w.RemoteAddr(),
		)
	}
}
