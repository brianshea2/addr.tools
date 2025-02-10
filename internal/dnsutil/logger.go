package dnsutil

import (
	"crypto/tls"
	"log"
	"sync/atomic"

	"github.com/miekg/dns"
)

type LoggingResponseWriter struct {
	dns.ResponseWriter
	Rcode   int
	AnCount int
	NsCount int
	ExCount int
	Written bool
}

func (w *LoggingResponseWriter) WriteMsg(m *dns.Msg) error {
	w.Rcode = m.Rcode
	w.AnCount = len(m.Answer)
	w.NsCount = len(m.Ns)
	w.ExCount = len(m.Extra)
	w.Written = true
	return w.ResponseWriter.WriteMsg(m)
}

func (w *LoggingResponseWriter) ConnectionState() *tls.ConnectionState {
	return w.ResponseWriter.(dns.ConnectionStater).ConnectionState()
}

type LoggingHandler struct {
	Logger *log.Logger
	count  atomic.Uint64
	dns.Handler
}

func (h *LoggingHandler) RequestCount() uint64 {
	return h.count.Load()
}

func (h *LoggingHandler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	lw := &LoggingResponseWriter{ResponseWriter: w}
	h.Handler.ServeDNS(lw, req)
	h.count.Add(1)
	var status string
	if lw.Written {
		status = dns.RcodeToString[lw.Rcode]
	} else {
		status = "NOREPLY"
	}
	logger := h.Logger
	if logger == nil {
		logger = log.Default()
	}
	logger.Printf(
		"%s %s %s %s %s %s an:%v ns:%v ex:%v %s",
		GetWriterProtocol(w),
		status,
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
