package dyn

import (
	"fmt"
	"time"

	"github.com/brianshea2/addr.tools/internal/dnsutil"
	"github.com/brianshea2/addr.tools/internal/ttlstore"
	"github.com/miekg/dns"
)

type RecordGenerator struct {
	DataStore ttlstore.TtlStore
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
		switch q.Qtype {
		case dns.TypeA:
			ip, err := LoadIPv4(dnsutil.ToLowerAscii(q.Name), g.DataStore)
			if err != nil {
				return nil, false, err
			}
			if ip != nil {
				rrs = append(rrs, &dns.A{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					A: ip.IP,
				})
			}
		case dns.TypeAAAA:
			ip, err := LoadIPv6(dnsutil.ToLowerAscii(q.Name), g.DataStore)
			if err != nil {
				return nil, false, err
			}
			if ip != nil {
				rrs = append(rrs, &dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					AAAA: ip.IP,
				})
			}
		case dns.TypeTXT:
			txts := make([]string, 1, 3)
			txts[0] = "v=spf1 -all"
			name := dnsutil.ToLowerAscii(q.Name)
			ip, err := LoadIPv4(name, g.DataStore)
			if err != nil {
				return nil, false, err
			}
			if ip != nil {
				txts = append(txts, fmt.Sprintf("ipv4 last updated %s", time.Unix(int64(ip.Updated), 0).UTC()))
			}
			ip, err = LoadIPv6(name, g.DataStore)
			if err != nil {
				return nil, false, err
			}
			if ip != nil {
				txts = append(txts, fmt.Sprintf("ipv6 last updated %s", time.Unix(int64(ip.Updated), 0).UTC()))
			}
			for _, txt := range txts {
				rrs = append(rrs, &dns.TXT{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeTXT,
						Class:  dns.ClassINET,
						Ttl:    1,
					},
					Txt: dnsutil.SplitForTxt(txt),
				})
			}
		}
	}
	return
}
