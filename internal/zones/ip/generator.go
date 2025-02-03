package ip

import (
	"net"

	"github.com/brianshea2/addr.tools/internal/dnsutil"
	"github.com/brianshea2/addr.tools/internal/ttlstore"
	"github.com/miekg/dns"
)

type RecordGenerator struct {
	IPv4           []net.IP
	IPv6           []net.IP
	ChallengeStore ttlstore.TtlStore
}

func (g *RecordGenerator) GenerateRecords(q *dns.Question, zone string) (rrs []dns.RR, validName bool) {
	if len(q.Name) < len(zone) {
		return
	}
	sub := q.Name[:len(q.Name)-len(zone)]
	var ipv4Only, ipv6Only bool
	switch {
	case len(sub) == 0:
		validName = true
	case dnsutil.EqualNames(sub, "self."):
		validName = true
		ipv4Only = true
	case dnsutil.EqualNames(sub, "self6."):
		validName = true
		ipv6Only = true
	}
	if validName {
		switch q.Qtype {
		case dns.TypeA:
			if ipv6Only {
				break
			}
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
			if ipv4Only {
				break
			}
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
	if ip := ParseIP(sub, 0); ip != nil {
		validName = true
		switch q.Qtype {
		case dns.TypeA:
			if ip.To4() == nil {
				break
			}
			rrs = append(rrs, &dns.A{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: ip,
			})
		case dns.TypeAAAA:
			if ip.To4() != nil {
				break
			}
			rrs = append(rrs, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				AAAA: ip,
			})
		case dns.TypeTXT:
			if len(sub) > 16 && dnsutil.EqualNames(sub[:16], "_acme-challenge.") {
				for _, v := range g.ChallengeStore.Values(dnsutil.LowerName(q.Name)) {
					rrs = append(rrs, &dns.TXT{
						Hdr: dns.RR_Header{
							Name:   q.Name,
							Rrtype: dns.TypeTXT,
							Class:  dns.ClassINET,
							Ttl:    1,
						},
						Txt: dnsutil.SplitForTxt(string(v)),
					})
				}
			}
		}
	}
	return
}
