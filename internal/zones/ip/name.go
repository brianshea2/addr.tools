package ip

import (
	"net"
)

func ParseIP(qname string, suffixLength int) net.IP {
	end := len(qname) - suffixLength - 1
	if end < 1 || qname[end] != '.' {
		return nil
	}
	var hasDoubleDash, hasHighHex bool
	var i, dotSeps, dashSeps int
	var c, d byte
loop:
	for i = end; i > 0; i-- {
		c, d = qname[i-1], qname[i]
		switch {
		case c == '.':
			if d == '.' || i == 1 {
				return nil
			}
			if dashSeps > 0 || hasHighHex || dotSeps == 3 {
				break loop
			}
			dotSeps++
		case c == '-':
			if dotSeps > 0 {
				return nil
			}
			if d == '-' {
				if hasDoubleDash {
					return nil
				}
				hasDoubleDash = true
			} else {
				dashSeps++
				if dashSeps > 7 {
					return nil
				}
			}
		case c >= '0' && c <= '9':
		case c >= 'A' && c <= 'F':
			fallthrough
		case c >= 'a' && c <= 'f':
			if dotSeps > 0 {
				return nil
			}
			hasHighHex = true
		default:
			return nil
		}
	}
	if dotSeps == 3 {
		return net.ParseIP(qname[i:end])
	}
	if dashSeps == 3 && !hasDoubleDash && !hasHighHex {
		b := []byte(qname[i:end])
		for i, c = range b {
			if c == '-' {
				b[i] = '.'
			}
		}
		return net.ParseIP(string(b))
	}
	if (hasDoubleDash && dashSeps > 0) || dashSeps == 7 {
		b := []byte(qname[i:end])
		for i, c = range b {
			if c == '-' {
				b[i] = ':'
			}
		}
		return net.ParseIP(string(b))
	}
	return nil
}
