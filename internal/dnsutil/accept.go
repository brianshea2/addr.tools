package dnsutil

import (
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
