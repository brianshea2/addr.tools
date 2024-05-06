package dnsutil

import (
	"crypto/tls"
	"net"

	"github.com/miekg/dns"
)

func GetAddrProtocol(addr net.Addr, cstate *tls.ConnectionState) string {
	switch addr.Network() {
	case "udp":
		return "UDP"
	case "tcp":
		if cstate != nil {
			return "TLS"
		}
		return "TCP"
	}
	return ""
}

func GetWriterProtocol(w dns.ResponseWriter) string {
	return GetAddrProtocol(
		w.LocalAddr(),
		w.(dns.ConnectionStater).ConnectionState(),
	)
}
