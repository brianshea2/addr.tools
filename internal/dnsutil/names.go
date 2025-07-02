package dnsutil

import (
	"github.com/miekg/dns"
)

// fast, ascii-only, case-insensitive equality check
func EqualNames(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var ac, bc byte
	for i := 0; i < len(a); i++ {
		ac = a[i]
		bc = b[i]
		if ac == bc {
			continue
		}
		if ac > bc {
			ac, bc = bc, ac
		}
		if ac >= 'A' && ac <= 'Z' && bc == ac+'a'-'A' {
			continue
		}
		return false
	}
	return true
}

// fast, ascii-only string case lower-er
func LowerName(s string) string {
	var i int
	for i = 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			break
		}
	}
	if i == len(s) {
		return s
	}
	bs := []byte(s)
	bs[i] += 'a' - 'A'
	for i++; i < len(bs); i++ {
		if bs[i] >= 'A' && bs[i] <= 'Z' {
			bs[i] += 'a' - 'A'
		}
	}
	return string(bs)
}

// make names of rrs match case of name in question
func FixNames(rrs []dns.RR, question *dns.Question) {
	var rname, qname string
	for i, rr := range rrs {
		rname = rr.Header().Name
		qname = question.Name
		if len(rname) < len(qname) {
			if qname[len(qname)-len(rname)-1] != '.' {
				continue
			}
			qname = qname[len(qname)-len(rname):]
		} else if len(rname) > len(qname) {
			if rname[len(rname)-len(qname)-1] != '.' {
				continue
			}
			qname = rname[:len(rname)-len(qname)] + qname
		}
		if rname == qname || !EqualNames(rname, qname) {
			continue
		}
		rrs[i] = dns.Copy(rr)
		rrs[i].Header().Name = qname
	}
}
