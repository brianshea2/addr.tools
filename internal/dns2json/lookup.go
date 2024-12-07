package dns2json

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	LookupTimeout        = 5 * time.Second
	LookupResponseMaxTtl = 86400
)

type LookupHandler struct {
	Upstream string
}

func (h *LookupHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	qname := req.PathValue("name")
	if _, ok := dns.IsDomainName(qname); !ok {
		http.Error(w, "invalid name", http.StatusBadRequest)
		return
	}
	qtype := dns.StringToType[strings.ToUpper(req.PathValue("type"))]
	if qtype == 0 {
		http.Error(w, "invalid type", http.StatusBadRequest)
		return
	}
	msg := new(dns.Msg).SetQuestion(dns.Fqdn(qname), qtype)
	client := &dns.Client{Timeout: LookupTimeout}
	received, _, err := client.Exchange(msg, h.Upstream)
	if err != nil || received.Truncated {
		// retry over tcp
		client.Net = "tcp"
		received, _, err = client.Exchange(msg, h.Upstream)
	}
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			http.Error(w, "dns timeout", http.StatusGatewayTimeout)
		} else {
			log.Printf("[error] dns2json.LookupHandler.ServeHTTP: Exchange: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
		}
		return
	}
	type record struct {
		Name string `json:"name"`
		Type uint16 `json:"type"`
		Data string `json:"data"`
	}
	type response struct {
		Status    int
		Answer    []record `json:",omitempty"`
		Authority []record `json:",omitempty"`
	}
	maxAge := uint32(LookupResponseMaxTtl)
	resp := &response{Status: received.Rcode}
	if len(received.Answer) > 0 {
		resp.Answer = make([]record, len(received.Answer))
		for i, rr := range received.Answer {
			hdr := rr.Header()
			if hdr.Ttl < maxAge {
				maxAge = hdr.Ttl
			}
			resp.Answer[i] = record{hdr.Name, hdr.Rrtype, rr.String()[len(hdr.String()):]}
		}
	}
	if len(received.Ns) > 0 {
		resp.Authority = make([]record, len(received.Ns))
		for i, rr := range received.Ns {
			hdr := rr.Header()
			if hdr.Ttl < maxAge {
				maxAge = hdr.Ttl
			}
			if hdr.Rrtype == dns.TypeSOA && len(received.Answer) == 0 {
				if rr.(*dns.SOA).Minttl < maxAge {
					maxAge = rr.(*dns.SOA).Minttl
				}
			}
			resp.Authority[i] = record{hdr.Name, hdr.Rrtype, rr.String()[len(hdr.String()):]}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if (resp.Status == dns.RcodeSuccess || resp.Status == dns.RcodeNameError) &&
		(len(resp.Answer) > 0 || len(resp.Authority) > 0) {
		w.Header().Set("Cache-Control", "max-age="+strconv.FormatUint(uint64(maxAge), 10))
	}
	json.NewEncoder(w).Encode(resp)
}
