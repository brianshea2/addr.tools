package dnsutil

import (
	"fmt"

	"github.com/miekg/dns"
)

const (
	MaxUdpMsgSize              = 1400 // rfc9715
	ResponsePaddingBlockLength = 468  // rfc8467
)

// checks for edns0 in req, sets edns0 in resp
func CheckAndSetEdns(req, resp *dns.Msg) error {
	if opt := req.IsEdns0(); opt != nil {
		if opt.Version() != 0 {
			resp.SetEdns0(MaxUdpMsgSize, false) // can't rely on Do() here
			resp.Rcode = dns.RcodeBadVers
			return fmt.Errorf("bad edns version: %v", opt.Version())
		}
		resp.SetEdns0(MaxUdpMsgSize, opt.Do())
		// ecs
		for _, o := range opt.Option {
			if o.Option() == dns.EDNS0SUBNET {
				subnet := o.(*dns.EDNS0_SUBNET)
				respOpt := resp.IsEdns0()
				respOpt.Option = append(respOpt.Option, &dns.EDNS0_SUBNET{
					Code:          dns.EDNS0SUBNET,
					Family:        subnet.Family,
					Address:       subnet.Address,
					SourceNetmask: subnet.SourceNetmask,
					SourceScope:   0,
				})
				break
			}
		}
	}
	return nil
}

// determines max udp payload size
func GetMaxUdpSize(req *dns.Msg) int {
	opt := req.IsEdns0()
	if opt == nil {
		return dns.MinMsgSize
	}
	maxSize := int(opt.UDPSize())
	if maxSize < dns.MinMsgSize {
		return dns.MinMsgSize
	}
	if maxSize > MaxUdpMsgSize {
		return MaxUdpMsgSize
	}
	return maxSize
}

// checks if edns0 padding exists in msg
func HasPadding(msg *dns.Msg) bool {
	opt := msg.IsEdns0()
	if opt == nil {
		return false
	}
	for _, o := range opt.Option {
		if o.Option() == dns.EDNS0PADDING {
			return true
		}
	}
	return false
}

// adds edns0 padding to msg so that the padded length is a multiple of blockLength
func AddPadding(msg *dns.Msg, blockLength int) {
	opt := msg.IsEdns0()
	if opt == nil {
		return
	}
	packed, _ := msg.Pack()
	if packed == nil {
		return
	}
	msgLength := len(packed) + 4 // EDNS0PADDING option adds 4 bytes
	paddingLength := msgLength % blockLength
	if paddingLength > 0 {
		paddingLength = blockLength - paddingLength
	}
	opt.Option = append(opt.Option, &dns.EDNS0_PADDING{
		Padding: make([]byte, paddingLength),
	})
}

// truncates and/or pads if necessary
func ResizeForTransport(req, resp *dns.Msg, proto string) {
	switch proto {
	case ProtoUDP:
		forceCompress := resp.Compress
		resp.Truncate(GetMaxUdpSize(req))
		if forceCompress {
			resp.Compress = true
		}
	case ProtoTLS:
		if HasPadding(req) {
			AddPadding(resp, ResponsePaddingBlockLength)
		}
	}
}
