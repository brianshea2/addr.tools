package dnscheck

import (
	"iter"
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
	NullIP     bool
	TxtFill    int // 1 - 4096
}

func ParseOptions(sub string) *Options {
	o := new(Options)
	if len(sub) > 0 && sub[len(sub)-1] == '.' {
		sub = sub[:len(sub)-1]
	}
	if len(sub) == 0 {
		return o
	}
	if i := strings.LastIndexByte(sub, '.'); i >= 0 {
		sub = sub[i+1:]
	}
	var seq iter.Seq[string] = func(yield func(string) bool) {
		for {
			i := strings.IndexByte(sub, '-')
			if i < 0 {
				break
			}
			if !yield(sub[:i]) {
				return
			}
			sub = sub[i+1:]
		}
		yield(sub)
	}
	for s := range seq {
		switch {
		case dnsutil.EqualsAsciiIgnoreCase(s, "compress"):
			if o.Compress {
				return nil
			}
			o.Compress = true
		case dnsutil.EqualsAsciiIgnoreCase(s, "truncate"):
			if o.Truncate || o.NoTruncate {
				return nil
			}
			o.Truncate = true
		case dnsutil.EqualsAsciiIgnoreCase(s, "notruncate"):
			if o.Truncate || o.NoTruncate {
				return nil
			}
			o.NoTruncate = true
		case dnsutil.EqualsAsciiIgnoreCase(s, "badsig"):
			if o.BadSig || o.ExpiredSig != 0 || o.NoSig {
				return nil
			}
			o.BadSig = true
		case len(s) >= 10 && dnsutil.EqualsAsciiIgnoreCase(s[:10], "expiredsig"):
			if o.BadSig || o.ExpiredSig != 0 || o.NoSig {
				return nil
			}
			if len(s) > 10 {
				o.ExpiredSig, _ = strconv.Atoi(s[10:])
				if o.ExpiredSig < 1 || o.ExpiredSig > 99999999 {
					return nil
				}
			} else {
				o.ExpiredSig = 86400
			}
		case dnsutil.EqualsAsciiIgnoreCase(s, "nosig"):
			if o.BadSig || o.ExpiredSig != 0 || o.NoSig {
				return nil
			}
			o.NoSig = true
		case dnsutil.EqualsAsciiIgnoreCase(s, "nxdomain"):
			if o.Rcode != 0 || o.NullIP || o.TxtFill != 0 {
				return nil
			}
			o.Rcode = dns.RcodeNameError
		case dnsutil.EqualsAsciiIgnoreCase(s, "refused"):
			if o.Rcode != 0 || o.NullIP || o.TxtFill != 0 {
				return nil
			}
			o.Rcode = dns.RcodeRefused
		case dnsutil.EqualsAsciiIgnoreCase(s, "nullip"):
			if o.Rcode != 0 || o.NullIP || o.TxtFill != 0 {
				return nil
			}
			o.NullIP = true
		case len(s) > 7 && dnsutil.EqualsAsciiIgnoreCase(s[:7], "txtfill"):
			if o.Rcode != 0 || o.NullIP || o.TxtFill != 0 {
				return nil
			}
			o.TxtFill, _ = strconv.Atoi(s[7:])
			if o.TxtFill < 1 || o.TxtFill > 4096 {
				return nil
			}
		default:
			if len(o.Random) > 0 || len(s) < 1 || len(s) > 8 {
				return nil
			}
			var c byte
			for i := 0; i < len(s); i++ {
				c = s[i]
				switch {
				case c >= '0' && c <= '9':
				case c >= 'A' && c <= 'F':
				case c >= 'a' && c <= 'f':
				default:
					return nil
				}
			}
			o.Random = dnsutil.ToLowerAscii(s)
		}
	}
	return o
}
