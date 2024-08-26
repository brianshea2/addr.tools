package myaddr

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/brianshea2/addr.tools/internal/dnsutil"
	"github.com/brianshea2/addr.tools/internal/ttlstore"
	"github.com/miekg/dns"
)

type RecordGenerator struct {
	Addrs               []net.IP
	SelfChallengeTarget string
	DataStore           ttlstore.TtlStore
	ChallengeStore      ttlstore.TtlStore
	KeyPrefix           string
}

func GetName(sub string) string {
	if len(sub) == 0 || sub[0] == '.' || sub[len(sub)-1] != '.' {
		return ""
	}
	name := sub[:len(sub)-1]                         // remove trailing dot
	name = name[strings.LastIndexByte(name, '.')+1:] // remove subdomains
	if !IsValidName(name) {
		return ""
	}
	return dnsutil.LowerName(name) // all names stored in lowercase
}

func (g *RecordGenerator) GenerateRecords(q *dns.Question, zone string) (rrs []dns.RR, validName bool) {
	defer func() {
		if validName && q.Qtype == dns.TypeTXT {
			rrs = append(rrs, &dns.TXT{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Txt: []string{"v=spf1 -all"},
			})
		}
	}()
	if len(q.Name) < len(zone) {
		return
	}
	sub := q.Name[:len(q.Name)-len(zone)]
	var ipv4Only, ipv6Only bool
	switch {
	case len(sub) == 0, dnsutil.EqualNames(sub, "dns."), dnsutil.EqualNames(sub, "www."):
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
			for _, ip := range g.Addrs {
				if len(ip) != net.IPv4len {
					continue
				}
				rrs = append(rrs, &dns.A{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    3600,
					},
					A: ip,
				})
			}
		case dns.TypeAAAA:
			if ipv4Only {
				break
			}
			for _, ip := range g.Addrs {
				if len(ip) != net.IPv6len {
					continue
				}
				rrs = append(rrs, &dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    3600,
					},
					AAAA: ip,
				})
			}
		}
		return
	}
	if dnsutil.EqualNames(sub, "_acme-challenge.") ||
		dnsutil.EqualNames(sub, "_acme-challenge.dns.") ||
		dnsutil.EqualNames(sub, "_acme-challenge.www.") ||
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
	if name := GetName(sub); len(name) > 0 {
		validName = true
		switch q.Qtype {
		case dns.TypeA:
			if ip := g.DataStore.Get(g.KeyPrefix + name + ":ip4"); ip != nil {
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
			if ip := g.DataStore.Get(g.KeyPrefix + name + ":ip6"); ip != nil {
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
			if len(sub) > 16 && dnsutil.EqualNames(sub[:16], "_acme-challenge.") {
				for _, v := range g.ChallengeStore.Values(g.KeyPrefix + name) {
					rrs = append(rrs, &dns.TXT{
						Hdr: dns.RR_Header{
							Name:   q.Name,
							Rrtype: dns.TypeTXT,
							Class:  dns.ClassINET,
							Ttl:    1,
						},
						Txt: []string{string(v)},
					})
				}
			}
			if len(sub) == len(name)+1 {
				created, _, expires := GetRegistrationInfo(name, g.DataStore, g.KeyPrefix)
				if created > 0 {
					txts := []string{
						fmt.Sprintf("registered %s", time.Unix(int64(created), 0).UTC()),
						fmt.Sprintf("expires %s", time.Unix(int64(expires), 0).UTC()),
					}
					if mtime := g.DataStore.Get(g.KeyPrefix + name + ":ip4mtime"); mtime != nil {
						txts = append(txts, fmt.Sprintf("ipv4 last updated %s", time.Unix(int64(binary.BigEndian.Uint32(mtime)), 0).UTC()))
					}
					if mtime := g.DataStore.Get(g.KeyPrefix + name + ":ip6mtime"); mtime != nil {
						txts = append(txts, fmt.Sprintf("ipv6 last updated %s", time.Unix(int64(binary.BigEndian.Uint32(mtime)), 0).UTC()))
					}
					for _, txt := range txts {
						rrs = append(rrs, &dns.TXT{
							Hdr: dns.RR_Header{
								Name:   q.Name,
								Rrtype: dns.TypeTXT,
								Class:  dns.ClassINET,
								Ttl:    1,
							},
							Txt: []string{txt},
						})
					}
				}
			}
		}
	}
	return
}
