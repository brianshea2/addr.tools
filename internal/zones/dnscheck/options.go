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

func (o *Options) ParseOptions(s string) bool {
	s = dnsutil.LowerName(s)
	var i int
	var t string
	for {
		i = strings.IndexByte(s, '-')
		if i < 0 {
			t = s
		} else {
			t = s[:i]
			s = s[i+1:]
		}
		switch {
		case t == "compress":
			if o.Compress {
				return false
			}
			o.Compress = true
		case t == "truncate":
			if o.Truncate || o.NoTruncate {
				return false
			}
			o.Truncate = true
		case t == "notruncate":
			if o.Truncate || o.NoTruncate {
				return false
			}
			o.NoTruncate = true
		case t == "nxdomain":
			if o.Rcode != 0 || o.NullIP || o.IPv4Only || o.IPv6Only {
				return false
			}
			o.Rcode = dns.RcodeNameError
		case t == "refused":
			if o.Rcode != 0 || o.NullIP || o.IPv4Only || o.IPv6Only {
				return false
			}
			o.Rcode = dns.RcodeRefused
		case t == "nullip":
			if o.Rcode != 0 || o.NullIP || o.IPv4Only || o.IPv6Only {
				return false
			}
			o.NullIP = true
		case t == "ipv4":
			if o.Rcode != 0 || o.NullIP || o.IPv4Only || o.IPv6Only {
				return false
			}
			o.IPv4Only = true
		case t == "ipv6":
			if o.Rcode != 0 || o.NullIP || o.IPv4Only || o.IPv6Only {
				return false
			}
			o.IPv6Only = true
		case len(t) > 7 && t[:7] == "padding":
			if o.Padding != 0 || o.TxtFill != 0 {
				return false
			}
			o.Padding, _ = strconv.Atoi(t[7:])
			if o.Padding < 1 || o.Padding > 4000 {
				return false
			}
		case len(t) > 7 && t[:7] == "txtfill":
			if o.Padding != 0 || o.TxtFill != 0 {
				return false
			}
			o.TxtFill, _ = strconv.Atoi(t[7:])
			if o.TxtFill < 1 || o.TxtFill > 4000 {
				return false
			}
		case t == "nosig":
			if o.NoSig || o.BadSig || o.ExpiredSig != 0 {
				return false
			}
			o.NoSig = true
		case t == "badsig":
			if o.NoSig || o.BadSig || o.ExpiredSig != 0 {
				return false
			}
			o.BadSig = true
		case len(t) >= 10 && t[:10] == "expiredsig":
			if o.NoSig || o.BadSig || o.ExpiredSig != 0 {
				return false
			}
			if len(t) > 10 {
				o.ExpiredSig, _ = strconv.Atoi(t[10:])
				if o.ExpiredSig < 1 || o.ExpiredSig > 99999999 {
					return false
				}
			} else {
				o.ExpiredSig = 86400
			}
		default:
			if len(o.Random) > 0 {
				return false
			}
			if len(t) == 0 || len(t) > 8 {
				return false
			}
			for j := 0; j < len(t); j++ {
				if t[j] < '0' || t[j] > 'f' || (t[j] > '9' && t[j] < 'a') {
					return false
				}
			}
			o.Random = t
		}
		if i < 0 {
			break
		}
	}
	return true
}
