package dnscheck

import (
	"strconv"
	"strings"

	"github.com/brianshea2/addr.tools/internal/dnsutil"
	"github.com/miekg/dns"
)

type Options struct {
	Random     string // hex
	Compress   bool
	Truncate   bool
	NoTruncate bool
	BadSig     bool
	ExpiredSig int // 1 - 99999999; default 86400
	NoSig      bool
	Rcode      int // nxdomain, refused
	IPv4Only   bool
	IPv6Only   bool
	NullIP     bool
	TxtFill    int // 1 - 4096
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
		case dnsutil.EqualNames(v, "badsig"):
			if o.BadSig || o.ExpiredSig != 0 || o.NoSig {
				return nil
			}
			o.BadSig = true
		case len(v) >= 10 && dnsutil.EqualNames(v[:10], "expiredsig"):
			if o.BadSig || o.ExpiredSig != 0 || o.NoSig {
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
		case dnsutil.EqualNames(v, "nosig"):
			if o.BadSig || o.ExpiredSig != 0 || o.NoSig {
				return nil
			}
			o.NoSig = true
		case dnsutil.EqualNames(v, "nxdomain"):
			if o.Rcode != 0 || o.IPv4Only || o.IPv6Only || o.NullIP || o.TxtFill != 0 {
				return nil
			}
			o.Rcode = dns.RcodeNameError
		case dnsutil.EqualNames(v, "refused"):
			if o.Rcode != 0 || o.IPv4Only || o.IPv6Only || o.NullIP || o.TxtFill != 0 {
				return nil
			}
			o.Rcode = dns.RcodeRefused
		case dnsutil.EqualNames(v, "ipv4"):
			if o.Rcode != 0 || o.IPv4Only || o.IPv6Only || o.NullIP || o.TxtFill != 0 {
				return nil
			}
			o.IPv4Only = true
		case dnsutil.EqualNames(v, "ipv6"):
			if o.Rcode != 0 || o.IPv4Only || o.IPv6Only || o.NullIP || o.TxtFill != 0 {
				return nil
			}
			o.IPv6Only = true
		case dnsutil.EqualNames(v, "nullip"):
			if o.Rcode != 0 || o.IPv4Only || o.IPv6Only || o.NullIP || o.TxtFill != 0 {
				return nil
			}
			o.NullIP = true
		case len(v) > 7 && dnsutil.EqualNames(v[:7], "txtfill"):
			if o.Rcode != 0 || o.IPv4Only || o.IPv6Only || o.NullIP || o.TxtFill != 0 {
				return nil
			}
			o.TxtFill, _ = strconv.Atoi(v[7:])
			if o.TxtFill < 1 || o.TxtFill > 4096 {
				return nil
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
