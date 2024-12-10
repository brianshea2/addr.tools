package dyn

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/brianshea2/addr.tools/internal/dnsutil"
	"github.com/brianshea2/addr.tools/internal/ttlstore"
	"github.com/miekg/dns"
)

type RecordGenerator struct {
	Addrs               dnsutil.IPCollection
	SelfChallengeTarget string
	DataStore           ttlstore.TtlStore
}

func IsValidSubdomain(sub string) bool {
	if len(sub) != 57 || sub[56] != '.' {
		return false
	}
	var c byte
	for i := 0; i < 56; i++ {
		c = sub[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'A' && c <= 'F':
		case c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
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
	case dnsutil.EqualNames(sub, "ipv4."):
		validName = true
		ipv4Only = true
	case dnsutil.EqualNames(sub, "ipv6."):
		validName = true
		ipv6Only = true
	}
	if validName {
		switch q.Qtype {
		case dns.TypeA:
			if ipv6Only {
				break
			}
			for _, ip := range g.Addrs.IPv4 {
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
			for _, ip := range g.Addrs.IPv6 {
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
	if dnsutil.EqualNames(sub, "_acme-challenge.") ||
		dnsutil.EqualNames(sub, "_acme-challenge.ipv4.") ||
		dnsutil.EqualNames(sub, "_acme-challenge.ipv6.") {
		validName = true
		if q.Qtype == dns.TypeTXT {
			rrs = append(rrs, &dns.CNAME{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeCNAME,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Target: g.SelfChallengeTarget,
			})
		}
		return
	}
	if IsValidSubdomain(sub) {
		validName = true
		switch q.Qtype {
		case dns.TypeA:
			if ip := g.DataStore.Get(dnsutil.LowerName(q.Name) + ":ip4"); ip != nil {
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
			if ip := g.DataStore.Get(dnsutil.LowerName(q.Name) + ":ip6"); ip != nil {
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
		case dns.TypeTXT:
			if mtime := g.DataStore.Get(dnsutil.LowerName(q.Name) + ":ip4mtime"); mtime != nil {
				rrs = append(rrs, &dns.TXT{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeTXT,
						Class:  dns.ClassINET,
						Ttl:    1,
					},
					Txt: []string{fmt.Sprintf("ipv4 last updated %s", time.Unix(int64(binary.BigEndian.Uint32(mtime)), 0).UTC())},
				})
			}
			if mtime := g.DataStore.Get(dnsutil.LowerName(q.Name) + ":ip6mtime"); mtime != nil {
				rrs = append(rrs, &dns.TXT{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeTXT,
						Class:  dns.ClassINET,
						Ttl:    1,
					},
					Txt: []string{fmt.Sprintf("ipv6 last updated %s", time.Unix(int64(binary.BigEndian.Uint32(mtime)), 0).UTC())},
				})
			}
		}
	}
	return
}
