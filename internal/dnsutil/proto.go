package dnsutil

import (
	"github.com/miekg/dns"
)

const (
	ProtoUDP = "UDP"
	ProtoTCP = "TCP"
	ProtoTLS = "TLS"
)

func GetProtocol(w dns.ResponseWriter) string {
	switch w.Network() {
	case "udp", "udp4", "udp6":
		return ProtoUDP
	case "tcp", "tcp4", "tcp6":
		return ProtoTCP
	case "tcp-tls", "tcp4-tls", "tcp6-tls":
		return ProtoTLS
	}
	return ""
}
