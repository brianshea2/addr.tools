package myaddr

import (
	"fmt"
	"strings"
	"time"

	"github.com/brianshea2/addr.tools/internal/dnsutil"
	"github.com/brianshea2/addr.tools/internal/ttlstore"
	"github.com/brianshea2/addr.tools/internal/zones/dyn"
	"github.com/miekg/dns"
)

type RecordGenerator struct {
	DataStore      ttlstore.TtlStore
	ChallengeStore ttlstore.TtlStore
}

func (g *RecordGenerator) GenerateRecords(q *dns.Question, zone string) (rrs []dns.RR, validName bool, err error) {
	if len(q.Name) == len(zone) {
		return
	}
	name := q.Name[:len(q.Name)-len(zone)-1]
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		name = name[i+1:]
	}
	if IsValidName(name) {
		validName = true
		switch q.Qtype {
		case dns.TypeA:
			ip, err := dyn.LoadIPv4(dnsutil.ToLowerAscii(name), g.DataStore)
			if err != nil {
				return nil, false, err
			}
			if ip != nil {
				rrs = append(rrs, &dns.A{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					A: ip.IP,
				})
			}
		case dns.TypeAAAA:
			ip, err := dyn.LoadIPv6(dnsutil.ToLowerAscii(name), g.DataStore)
			if err != nil {
				return nil, false, err
			}
			if ip != nil {
				rrs = append(rrs, &dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					AAAA: ip.IP,
				})
			}
		case dns.TypeTXT:
			var txts []string
			if len(q.Name) == len(name)+1+len(zone) {
				txts = make([]string, 1, 5)
				txts[0] = "v=spf1 -all"
				name = dnsutil.ToLowerAscii(name)
				reg, err := LoadRegistration(name, g.DataStore)
				if err != nil {
					return nil, false, err
				}
				if reg != nil {
					txts = append(txts,
						fmt.Sprintf("registered %s", time.Unix(int64(reg.Created), 0).UTC()),
						fmt.Sprintf("expires %s", time.Unix(int64(reg.Expires()), 0).UTC()),
					)
				}
				ip, err := dyn.LoadIPv4(name, g.DataStore)
				if err != nil {
					return nil, false, err
				}
				if ip != nil {
					txts = append(txts, fmt.Sprintf("ipv4 last updated %s", time.Unix(int64(ip.Updated), 0).UTC()))
				}
				ip, err = dyn.LoadIPv6(name, g.DataStore)
				if err != nil {
					return nil, false, err
				}
				if ip != nil {
					txts = append(txts, fmt.Sprintf("ipv6 last updated %s", time.Unix(int64(ip.Updated), 0).UTC()))
				}
			} else if dnsutil.HasPrefixAsciiIgnoreCase(q.Name, "_acme-challenge.") {
				vals, err := g.ChallengeStore.Values(dnsutil.ToLowerAscii(name))
				if err != nil {
					return nil, false, err
				}
				if len(vals) > 0 {
					txts = make([]string, len(vals))
					for i, v := range vals {
						txts[i] = string(v)
					}
				}
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
