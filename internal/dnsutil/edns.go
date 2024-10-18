package dnsutil

import (
	"fmt"

	"github.com/miekg/dns"
)

const MaxUdpMsgSize = 1232

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

// determines max size, edns0 aware, truncates if necessary
func MaybeTruncate(req, resp *dns.Msg, net string) {
	if net != "udp" {
		return
	}
	var maxSize int
	if opt := req.IsEdns0(); opt != nil {
		maxSize = int(opt.UDPSize())
		if maxSize < dns.MinMsgSize {
			maxSize = dns.MinMsgSize
		} else if maxSize > MaxUdpMsgSize {
			maxSize = MaxUdpMsgSize
		}
	} else {
		maxSize = dns.MinMsgSize
	}
	resp.Truncate(maxSize)
}
