package dnscheck

import "github.com/brianshea2/addr.tools/internal/dnsutil"

type NameProperties struct {
	IsApex          bool
	IsAcmeChallenge bool
	Options
}

func (h *DnscheckHandler) ParseName(name string) *NameProperties {
	if len(name) == len(h.Zone) {
		return &NameProperties{IsApex: true}
	}
	end := len(name) - len(h.Zone) - 1
	if end < 1 || name[end] != '.' {
		return nil
	}
	name = name[:end]
	if dnsutil.EqualNames(name, "_acme-challenge") {
		return &NameProperties{IsAcmeChallenge: true}
	}
	n := new(NameProperties)
	if !n.ParseOptions(name) {
		return nil
	}
	return n
}
