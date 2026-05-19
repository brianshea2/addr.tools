package dyn

import (
	"fmt"
	"net"
	"time"

	"github.com/brianshea2/addr.tools/internal/dnsutil"
	"github.com/brianshea2/addr.tools/internal/ttlstore"
	"github.com/miekg/dns"
)

type RecordGenerator struct {
	IPv4      []net.IP
	IPv6      []net.IP
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
	sub := q.Name[:len(q.Name)-len(zone)]
	var ipv4Only, ipv6Only bool
	switch {
	case len(sub) == 0:
		validName = true
	case dnsutil.EqualsAsciiIgnoreCase(sub, "ipv4."):
		validName = true
		ipv4Only = true
	case dnsutil.EqualsAsciiIgnoreCase(sub, "ipv6."):
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
			if !ipv6Only && len(g.IPv4) > 0 {
				https.Value = append(https.Value, &dns.SVCBIPv4Hint{Hint: g.IPv4})
			}
			if !ipv4Only && len(g.IPv6) > 0 {
				https.Value = append(https.Value, &dns.SVCBIPv6Hint{Hint: g.IPv6})
			}
			rrs = append(rrs, https)
		}
		return
	}
	if IsValidSubdomain(sub) {
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
						Ttl:    300,
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
						Ttl:    300,
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
