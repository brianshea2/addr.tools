package cname

import (
	"net"

	"github.com/miekg/dns"
)

type RecordGenerator struct {
	IPv4 []net.IP
	IPv6 []net.IP
}

func (g *RecordGenerator) GenerateRecords(q *dns.Question, zone string) (rrs []dns.RR, validName bool) {
	if len(q.Name) == len(zone) {
		validName = true
		switch q.Qtype {
		case dns.TypeA:
			for _, ip := range g.IPv4 {
				rrs = append(rrs, &dns.A{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					A: ip,
				})
			}
		case dns.TypeAAAA:
			for _, ip := range g.IPv6 {
				rrs = append(rrs, &dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					AAAA: ip,
				})
			}
		}
		return
	}
	if len(q.Name) < len(zone) {
		return
	}
	validName = true
	rrs = append(rrs, &dns.CNAME{
		Hdr: dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeCNAME,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Target: q.Name[:len(q.Name)-len(zone)],
	})
	return
}
