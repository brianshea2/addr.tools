package dnsutil

import (
	"crypto/tls"
	"log"
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
	Start     time.Time
	Rcode     int
	AnCount   int
	NsCount   int
	ExCount   int
	connState *tls.ConnectionState
}

func (w *LoggingResponseWriter) WriteMsg(m *dns.Msg) error {
	w.Rcode = m.Rcode
	w.AnCount = len(m.Answer)
	w.NsCount = len(m.Ns)
	w.ExCount = len(m.Extra)
	return w.ResponseWriter.WriteMsg(m)
}

func (w *LoggingResponseWriter) ConnectionState() *tls.ConnectionState {
	if w.connState == nil {
		w.connState = w.ResponseWriter.(dns.ConnectionStater).ConnectionState()
	}
	return w.connState
}

type LoggingHandler struct {
	Logger *log.Logger
	Next   dns.Handler
	count  atomic.Uint64
}

func (h *LoggingHandler) RequestCount() uint64 {
	return h.count.Load()
}

func (h *LoggingHandler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	lw := &LoggingResponseWriter{
		ResponseWriter: w,
		Start:          time.Now(),
	}
	h.Next.ServeDNS(lw, req)
	h.count.Add(1)
	if h.Logger != nil {
		h.Logger.Printf(
			"%vms %s %s %s %s %s %s an:%v ns:%v ex:%v %s",
			time.Since(lw.Start).Milliseconds(),
			GetProtocol(w),
			dns.RcodeToString[lw.Rcode],
			dns.OpcodeToString[req.Opcode],
			dns.Class(req.Question[0].Qclass),
			dns.Type(req.Question[0].Qtype),
			req.Question[0].Name,
			lw.AnCount,
			lw.NsCount,
			lw.ExCount,
			lw.RemoteAddr(),
		)
	}
}
