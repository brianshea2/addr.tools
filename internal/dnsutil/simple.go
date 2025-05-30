package dnsutil

import (
	"log"

	"github.com/miekg/dns"
)

type RecordGenerator interface {
	GenerateRecords(question *dns.Question, zone string) (rrs []dns.RR, validName bool)
}

type UpdateHandler interface {
	HandleUpdate(w dns.ResponseWriter, req *dns.Msg, zone string)
}

type SimpleHandler struct {
	Zone           string
	Ns             []string
	HostMasterMbox string
	StaticRecords  StaticRecords
	RecordGenerator
	UpdateHandler
	*DnssecProvider
}

func (h *SimpleHandler) Init(privKeyBytes []byte) *SimpleHandler {
	if len(h.HostMasterMbox) == 0 {
		h.HostMasterMbox = "hostmaster." + h.Zone
	}
	if h.DnssecProvider != nil {
		for _, rr := range []dns.RR{h.DnssecProvider.Ksk, h.DnssecProvider.Zsk, h.DnssecProvider.KeySig} {
			hdr := rr.Header()
			hdr.Name = h.Zone
			hdr.Class = dns.ClassINET
			hdr.Ttl = 300
		}
		for _, rr := range []*dns.DNSKEY{h.DnssecProvider.Ksk, h.DnssecProvider.Zsk} {
			rr.Hdr.Rrtype = dns.TypeDNSKEY
			rr.Flags = 256
			rr.Protocol = 3 // DNSSEC
		}
		h.DnssecProvider.Ksk.Flags |= 1 // Secure Entry Point
		h.DnssecProvider.KeySig.Hdr.Rrtype = dns.TypeRRSIG
		h.DnssecProvider.KeySig.TypeCovered = dns.TypeDNSKEY
		h.DnssecProvider.KeySig.Labels = uint8(dns.CountLabel(h.Zone))
		h.DnssecProvider.KeySig.OrigTtl = h.DnssecProvider.Ksk.Hdr.Ttl
		h.DnssecProvider.KeySig.SignerName = h.Zone
		err := h.DnssecProvider.SetPrivKeyBytes(privKeyBytes)
		if err != nil {
			log.Fatal(err)
		}
	}
	return h
}

func (h *SimpleHandler) SOA(q *dns.Question) dns.RR {
	rrs := []dns.RR{&dns.SOA{
		Hdr: dns.RR_Header{
			Name:   h.Zone,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Ns:      h.Ns[0],
		Mbox:    h.HostMasterMbox,
		Serial:  1,
		Refresh: 9000,
		Retry:   9000,
		Expire:  18000,
		Minttl:  300,
	}}
	FixNames(rrs, q)
	return rrs[0]
}

func (h *SimpleHandler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	// handle updates
	if req.Opcode == dns.OpcodeUpdate && h.UpdateHandler != nil {
		h.HandleUpdate(w, req, h.Zone)
		return
	}
	// queries only
	if req.Opcode != dns.OpcodeQuery {
		w.WriteMsg(new(dns.Msg).SetRcode(req, dns.RcodeNotImplemented))
		return
	}
	q := &req.Question[0]
	// prepare response, defer send
	resp := new(dns.Msg).SetReply(req)
	resp.Authoritative = true
	defer func() {
		w.WriteMsg(resp)
	}()
	// edns
	err := CheckAndSetEdns(req, resp)
	if err != nil {
		// Rcode already set by CheckAndSetEdns
		return
	}
	// class IN only
	if q.Qclass != dns.ClassINET {
		resp.Rcode = dns.RcodeNotImplemented
		return
	}
	// allowed types only
	if q.Qtype == dns.TypeRRSIG || q.Qtype == dns.TypeNSEC {
		resp.Rcode = dns.RcodeRefused
		return
	}
	// defer compress, truncate, padding
	defer func() {
		ResizeForTransport(req, resp, GetProtocol(w))
	}()
	// provide dnssec keys, defer dnssec proof
	if h.ProvideKeys(req, resp) {
		return // no further answers
	}
	defer func() {
		err := h.Prove(req, resp, 0, 0)
		if err != nil {
			log.Printf("[error] DnssecProvider.Prove: %v", err)
			resp = new(dns.Msg).SetRcode(req, dns.RcodeServerFailure)
		}
	}()
	// defer adding SOA if no answers
	defer func() {
		if (resp.Rcode == dns.RcodeSuccess && len(resp.Answer) == 0) || resp.Rcode == dns.RcodeNameError {
			resp.Ns = append(resp.Ns, h.SOA(q))
		}
	}()
	// defer adding default ANY response
	defer func() {
		if q.Qtype == dns.TypeANY && resp.Rcode == dns.RcodeSuccess && len(resp.Answer) == 0 {
			resp.Answer = append(resp.Answer, &dns.HINFO{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeHINFO,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Cpu: "RFC8482",
				Os:  "",
			})
		}
	}()
	// assume domain does not exist until validated below
	resp.Rcode = dns.RcodeNameError
	// apex records
	if len(q.Name) == len(h.Zone) {
		resp.Rcode = dns.RcodeSuccess
		switch q.Qtype {
		case dns.TypeSOA:
			resp.Answer = append(resp.Answer, h.SOA(q))
		case dns.TypeNS:
			for _, ns := range h.Ns {
				resp.Answer = append(resp.Answer, &dns.NS{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeNS,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					Ns: ns,
				})
			}
		}
	}
	// static records
	if h.StaticRecords != nil {
		rrs, validName := h.StaticRecords.Get(q)
		if len(rrs) > 0 {
			resp.Answer = append(resp.Answer, rrs...)
		}
		if validName {
			resp.Rcode = dns.RcodeSuccess
		}
	}
	// generate records
	if h.RecordGenerator != nil {
		rrs, validName := h.GenerateRecords(q, h.Zone)
		if len(rrs) > 0 {
			resp.Answer = append(resp.Answer, rrs...)
		}
		if validName {
			resp.Rcode = dns.RcodeSuccess
		}
	}
}
