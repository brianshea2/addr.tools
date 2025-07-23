package challenges

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
		case dns.TypeHTTPS:
			https := &dns.HTTPS{dns.SVCB{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeHTTPS,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Priority: 1,
				Target:   ".",
				Value:    []dns.SVCBKeyValue{&dns.SVCBAlpn{Alpn: []string{"h3", "h2"}}},
			}}
			if len(g.IPv4) > 0 {
				https.Value = append(https.Value, &dns.SVCBIPv4Hint{Hint: g.IPv4})
			}
			if len(g.IPv6) > 0 {
				https.Value = append(https.Value, &dns.SVCBIPv6Hint{Hint: g.IPv6})
			}
			rrs = append(rrs, https)
		}
		return
	}
	if IsValidSubdomain(q.Name[:len(q.Name)-len(zone)]) {
		validName = true
		if q.Qtype == dns.TypeTXT {
			for _, v := range g.ChallengeStore.Values(dnsutil.ToLowerAscii(q.Name)) {
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
	return
}
