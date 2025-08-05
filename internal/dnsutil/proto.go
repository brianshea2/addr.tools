package dnsutil

import (
	"net"

	"github.com/miekg/dns"
)

const (
	ProtoUDP = "UDP"
	ProtoTCP = "TCP"
	ProtoTLS = "TLS"
)

func GetProtocol(w dns.ResponseWriter) string {
	switch w.LocalAddr().(type) {
	case *net.UDPAddr:
		return ProtoUDP
	case *net.TCPAddr:
		if w.(dns.ConnectionStater).ConnectionState() != nil {
			return ProtoTLS
		}
		return ProtoTCP
	}
	return ""
}
