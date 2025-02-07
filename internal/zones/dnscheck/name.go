package dnscheck

import (
	"strconv"
	"strings"

	"github.com/brianshea2/addr.tools/internal/dnsutil"
	"github.com/miekg/dns"
)

type Options struct {
	//
	Random     string // hex
	Compress   bool
	Truncate   bool
	NoTruncate bool
	//
	Rcode    int
	NullIP   bool
	IPv4Only bool
	IPv6Only bool
	//
	Padding int // 1 - 4000
	TxtFill int // 1 - 4000
	//
	NoSig      bool
	BadSig     bool
	ExpiredSig int // 1 - 99999999; default 86400
}

func ParseOptions(qname string, suffixLength int) *Options {
	if len(qname) < suffixLength {
		return nil
	}
	o := new(Options)
	if len(qname) == suffixLength {
		return o
	}
	qname = qname[:len(qname)-suffixLength-1]
	if start := strings.LastIndexByte(qname, '.'); start > -1 && start < len(qname)-1 {
		qname = qname[start+1:]
	}
	var i int
	var v string
	for {
		i = strings.IndexByte(qname, '-')
		if i < 0 {
			v = qname
		} else {
			v = qname[:i]
			qname = qname[i+1:]
		}
		switch {
		case dnsutil.EqualNames(v, "compress"):
			if o.Compress {
				return nil
			}
			o.Compress = true
		case dnsutil.EqualNames(v, "truncate"):
			if o.Truncate || o.NoTruncate {
				return nil
			}
			o.Truncate = true
		case dnsutil.EqualNames(v, "notruncate"):
			if o.Truncate || o.NoTruncate {
				return nil
			}
			o.NoTruncate = true
		case dnsutil.EqualNames(v, "nxdomain"):
			if o.Rcode != 0 || o.NullIP || o.IPv4Only || o.IPv6Only {
				return nil
			}
			o.Rcode = dns.RcodeNameError
		case dnsutil.EqualNames(v, "refused"):
			if o.Rcode != 0 || o.NullIP || o.IPv4Only || o.IPv6Only {
				return nil
			}
			o.Rcode = dns.RcodeRefused
		case dnsutil.EqualNames(v, "nullip"):
			if o.Rcode != 0 || o.NullIP || o.IPv4Only || o.IPv6Only {
				return nil
			}
			o.NullIP = true
		case dnsutil.EqualNames(v, "ipv4"):
			if o.Rcode != 0 || o.NullIP || o.IPv4Only || o.IPv6Only {
				return nil
			}
			o.IPv4Only = true
		case dnsutil.EqualNames(v, "ipv6"):
			if o.Rcode != 0 || o.NullIP || o.IPv4Only || o.IPv6Only {
				return nil
			}
			o.IPv6Only = true
		case len(v) > 7 && dnsutil.EqualNames(v[:7], "padding"):
			if o.Padding != 0 || o.TxtFill != 0 {
				return nil
			}
			o.Padding, _ = strconv.Atoi(v[7:])
			if o.Padding < 1 || o.Padding > 4000 {
				return nil
			}
		case len(v) > 7 && dnsutil.EqualNames(v[:7], "txtfill"):
			if o.Padding != 0 || o.TxtFill != 0 {
				return nil
			}
			o.TxtFill, _ = strconv.Atoi(v[7:])
			if o.TxtFill < 1 || o.TxtFill > 4000 {
				return nil
			}
		case dnsutil.EqualNames(v, "nosig"):
			if o.NoSig || o.BadSig || o.ExpiredSig != 0 {
				return nil
			}
			o.NoSig = true
		case dnsutil.EqualNames(v, "badsig"):
			if o.NoSig || o.BadSig || o.ExpiredSig != 0 {
				return nil
			}
			o.BadSig = true
		case len(v) >= 10 && dnsutil.EqualNames(v[:10], "expiredsig"):
			if o.NoSig || o.BadSig || o.ExpiredSig != 0 {
				return nil
			}
			if len(v) > 10 {
				o.ExpiredSig, _ = strconv.Atoi(v[10:])
				if o.ExpiredSig < 1 || o.ExpiredSig > 99999999 {
					return nil
				}
			} else {
				o.ExpiredSig = 86400
			}
		default:
			if len(o.Random) > 0 {
				return nil
			}
			if len(v) == 0 || len(v) > 8 {
				return nil
			}
			for j := 0; j < len(v); j++ {
				if v[j] < '0' || v[j] > 'f' || (v[j] > '9' && v[j] < 'A') || (v[j] > 'F' && v[j] < 'a') {
					return nil
				}
			}
			o.Random = dnsutil.LowerName(v)
		}
		if i < 0 {
			break
		}
	}
	return o
}
