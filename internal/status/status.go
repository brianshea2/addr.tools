package status

import (
	"fmt"
	"net/http"
	"time"

	"github.com/brianshea2/addr.tools/internal/dnsutil"
	"github.com/miekg/dns"
)

type Status struct {
	Title string
	Value string
}

func (s *Status) String() string {
	return s.Title + ": " + s.Value
}

type StatusProvider interface {
	GetStatus() []Status
}

type StatusProviderFunc func() []Status

func (f StatusProviderFunc) GetStatus() []Status { return f() }

type StatusHandler struct {
	Providers []StatusProvider
}

func (h *StatusHandler) Add(p StatusProvider) {
	h.Providers = append(h.Providers, p)
}

func (h *StatusHandler) GetStatus() (ss []Status) {
	for _, p := range h.Providers {
		ss = append(ss, p.GetStatus()...)
	}
	return
}

func (h *StatusHandler) GenerateRecords(q *dns.Question, zone string) (rrs []dns.RR, validName bool) {
	if dnsutil.EqualNames(q.Name, zone) {
		validName = true
		if q.Qtype == dns.TypeTXT {
			ss := h.GetStatus()
			rrs = make([]dns.RR, len(ss))
			for i, s := range ss {
				rrs[i] = &dns.TXT{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeTXT,
						Class:  dns.ClassINET,
						Ttl:    1,
					},
					Txt: []string{s.String()},
				}
			}
		}
	}
	return
}

func (h *StatusHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Content-Type", "text/plain")
	for _, s := range h.GetStatus() {
		fmt.Fprintf(w, "%s\n", s)
	}
}

type UptimeProvider struct {
	boot time.Time
}

func NewUptimeProvider() *UptimeProvider {
	return &UptimeProvider{time.Now()}
}

func (p *UptimeProvider) GetStatus() []Status {
	return []Status{{"uptime", time.Since(p.boot).Truncate(time.Second).String()}}
}
