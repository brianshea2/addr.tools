package dnsutil

import (
	"crypto/tls"
	"net"

	"github.com/miekg/dns"
)

const (
	ProtoUDP = "UDP"
	ProtoTCP = "TCP"
	ProtoTLS = "TLS"
)

func GetAddrProtocol(addr net.Addr, cstate *tls.ConnectionState) string {
	switch addr.Network() {
	case "udp":
		return ProtoUDP
	case "tcp":
		if cstate != nil {
			return ProtoTLS
		}
		return ProtoTCP
	}
	return ""
}

func GetWriterProtocol(w dns.ResponseWriter) string {
	switch w.LocalAddr().Network() {
	case "udp":
		return ProtoUDP
	case "tcp":
		if w.(dns.ConnectionStater).ConnectionState() != nil {
			return ProtoTLS
		}
		return ProtoTCP
	}
	return ""
}
