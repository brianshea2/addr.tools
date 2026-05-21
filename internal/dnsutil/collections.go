package dnsutil

import (
	"encoding/json"

	"github.com/miekg/dns"
)

type StaticRecords []dns.RR

func (s StaticRecords) Get(question *dns.Question) (rrs []dns.RR, nameExists bool) {
	for _, rr := range s {
		hdr := rr.Header()
		if hdr.Class != question.Qclass {
			continue
		}
		if !EqualsAsciiIgnoreCase(hdr.Name, question.Name) {
			continue
		}
		nameExists = true
		if hdr.Rrtype == question.Qtype || hdr.Rrtype == dns.TypeCNAME {
			rrs = append(rrs, dns.Copy(rr))
			rrs[len(rrs)-1].Header().Name = question.Name
		}
	}
	return
}

func (s StaticRecords) MarshalJSON() ([]byte, error) {
	var strs []string
	for _, rr := range s {
		strs = append(strs, rr.String())
	}
	return json.Marshal(strs)
}

func (p *StaticRecords) UnmarshalJSON(data []byte) error {
	var strs []string
	err := json.Unmarshal(data, &strs)
	if err != nil {
		return err
	}
	s := make(StaticRecords, len(strs))
	for i, str := range strs {
		s[i], err = dns.NewRR(str)
		if err != nil {
			return err
		}
	}
	*p = s
	return nil
}
