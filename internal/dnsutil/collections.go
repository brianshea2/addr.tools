package dnsutil

import (
	"encoding/json"
	"net"

	"github.com/miekg/dns"
)

type IPCollection struct {
	IPv4 []net.IP
	IPv6 []net.IP
}

func (c *IPCollection) Add(ip net.IP) {
	if ip4 := ip.To4(); ip4 != nil {
		c.IPv4 = append(c.IPv4, ip4)
		return
	}
	if len(ip) == net.IPv6len {
		c.IPv6 = append(c.IPv6, ip)
	}
}

type StaticRecords []dns.RR

func (s StaticRecords) Get(question *dns.Question) (rrs []dns.RR) {
	for _, rr := range s {
		hdr := rr.Header()
		if hdr.Class == question.Qclass && hdr.Rrtype == question.Qtype && EqualNames(hdr.Name, question.Name) {
			rrs = append(rrs, rr)
		}
	}
	if len(rrs) > 0 {
		FixNames(rrs, question)
	}
	return
}

func (s StaticRecords) MarshalJSON() ([]byte, error) {
	var strs []string
	for _, rr := range s {
		strs = append(strs, rr.String())
	}
	return json.Marshal(strs)
}

func (p *StaticRecords) UnmarshalJSON(data []byte) error {
	var strs []string
	err := json.Unmarshal(data, &strs)
	if err != nil {
		return err
	}
	s := make(StaticRecords, len(strs))
	for i, str := range strs {
		s[i], err = dns.NewRR(str)
		if err != nil {
			return err
		}
	}
	*p = s
	return nil
}
