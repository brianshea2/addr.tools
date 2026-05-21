package challenges

import (
	"github.com/brianshea2/addr.tools/internal/dnsutil"
	"github.com/brianshea2/addr.tools/internal/ttlstore"
	"github.com/miekg/dns"
)

type RecordGenerator struct {
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

func (g *RecordGenerator) GenerateRecords(q *dns.Question, zone string) (rrs []dns.RR, validName bool, err error) {
	if IsValidSubdomain(q.Name[:len(q.Name)-len(zone)]) {
		validName = true
		if q.Qtype == dns.TypeTXT {
			vals, err := g.ChallengeStore.Values(dnsutil.ToLowerAscii(q.Name))
			if err != nil {
				return nil, false, err
			}
			for _, v := range vals {
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
