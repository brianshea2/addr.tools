package dns2json

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

const (
	LookupTimeout        = 5 * time.Second
	LookupResponseMaxTtl = 86400
	LookupResponseMinTtl = 1
	MaxCacheLength       = 100000
	MaxUdpMsgSize        = 1400
)

type Record struct {
	Name string `json:"name"`
	Type uint16 `json:"type"`
	Data string `json:"data"`
}

type Response struct {
	Status    int
	Answer    []Record `json:",omitempty"`
	Authority []Record `json:",omitempty"`
}

type cacheEntry struct {
	key     string
	prev    *cacheEntry
	next    *cacheEntry
	expires time.Time
	ready   chan struct{}
	resp    *Response
	err     error
}

func (c *cacheEntry) ttl() uint32 {
	t := time.Until(c.expires)
	if t < 0 {
		return 0
	}
	return uint32(math.Ceil(t.Seconds()))
}

func expires(ttl uint32) time.Time {
	return time.Now().Add(time.Duration(ttl) * time.Second)
}

type LookupHandler struct {
	Upstream    string
	cache       map[string]*cacheEntry
	leastRecent *cacheEntry
	mostRecent  *cacheEntry
	mu          sync.Mutex
	hitCount    atomic.Uint64
	missCount   atomic.Uint64
}

func (h *LookupHandler) HitCount() uint64  { return h.hitCount.Load() }
func (h *LookupHandler) MissCount() uint64 { return h.missCount.Load() }

func (h *LookupHandler) CacheSize() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.cache)
}

func (h *LookupHandler) Lookup(qname string, qtype uint16) (resp *Response, ttl uint32, hit bool, err error) {
	qname = dns.CanonicalName(qname)
	key := fmt.Sprintf("%s:%d", qname, qtype)

	h.mu.Lock()

	if h.cache == nil {
		h.cache = make(map[string]*cacheEntry)
	}

	var cached *cacheEntry
	cached, hit = h.cache[key]

	if !hit && len(h.cache) >= MaxCacheLength {
		log.Printf("[warn] dns2json.LookupHandler.Lookup: at max cache size (%v)", len(h.cache))
		delete(h.cache, h.leastRecent.key)
		h.removeFromRecentList(h.leastRecent)
	}

	now := time.Now()
	if hit {
		h.removeFromRecentList(cached)   // to be re-added as mostRecent below
		hit = now.Before(cached.expires) // check expiration
	}
	if !hit {
		cached = &cacheEntry{
			key:     key,
			expires: now.Add(LookupTimeout),
			ready:   make(chan struct{}),
		}
		h.cache[key] = cached
	}

	if h.leastRecent == nil {
		h.leastRecent = cached
	}
	if h.mostRecent != nil {
		cached.prev = h.mostRecent
		cached.prev.next = cached
	}
	h.mostRecent = cached

	h.mu.Unlock()

	if hit {
		h.hitCount.Add(1)
		<-cached.ready
		resp, ttl, err = cached.resp, cached.ttl(), cached.err
	} else {
		h.missCount.Add(1)
		resp, ttl, err = h.lookup(qname, qtype)
		cached.resp, cached.expires, cached.err = resp, expires(ttl), err
		close(cached.ready)
	}

	return
}

func (h *LookupHandler) lookup(qname string, qtype uint16) (resp *Response, ttl uint32, err error) {
	msg := new(dns.Msg)
	msg.SetQuestion(qname, qtype)
	msg.SetEdns0(MaxUdpMsgSize, false)

	var received *dns.Msg
	client := &dns.Client{Timeout: LookupTimeout}
	received, _, err = client.Exchange(msg, h.Upstream)
	if err == nil && received.Truncated {
		client.Net = "tcp"
		received, _, err = client.Exchange(msg, h.Upstream)
	}
	if err != nil {
		return
	}

	ok := received.Rcode == dns.RcodeSuccess || received.Rcode == dns.RcodeNameError
	if ok && (len(received.Answer) > 0 || len(received.Ns) > 0) {
		ttl = LookupResponseMaxTtl
	}

	resp = &Response{Status: received.Rcode}
	if len(received.Answer) > 0 {
		resp.Answer = make([]Record, len(received.Answer))
		for i, rr := range received.Answer {
			hdr := rr.Header()
			if hdr.Ttl < ttl {
				ttl = hdr.Ttl
			}
			resp.Answer[i] = Record{hdr.Name, hdr.Rrtype, rr.String()[len(hdr.String()):]}
		}
	}
	if len(received.Ns) > 0 {
		resp.Authority = make([]Record, len(received.Ns))
		for i, rr := range received.Ns {
			hdr := rr.Header()
			if hdr.Ttl < ttl {
				ttl = hdr.Ttl
			}
			if hdr.Rrtype == dns.TypeSOA && len(received.Answer) == 0 {
				if rr.(*dns.SOA).Minttl < ttl {
					ttl = rr.(*dns.SOA).Minttl
				}
			}
			resp.Authority[i] = Record{hdr.Name, hdr.Rrtype, rr.String()[len(hdr.String()):]}
		}
	}

	if ok && ttl < LookupResponseMinTtl {
		ttl = LookupResponseMinTtl
	}
	return
}

func (h *LookupHandler) removeFromRecentList(cached *cacheEntry) {
	if cached.prev == nil {
		h.leastRecent = cached.next
	} else {
		cached.prev.next = cached.next
	}
	if cached.next == nil {
		h.mostRecent = cached.prev
	} else {
		cached.next.prev = cached.prev
	}
	cached.prev = nil
	cached.next = nil
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

	resp, ttl, hit, err := h.Lookup(qname, qtype)
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			http.Error(w, "dns timeout", http.StatusGatewayTimeout)
		} else {
			log.Printf("[error] dns2json.LookupHandler.ServeHTTP: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if ttl > 0 {
		w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", ttl))
	}
	if hit {
		w.Header().Set("Cache-Status", "addrd; hit")
	} else {
		w.Header().Set("Cache-Status", "addrd; fwd=miss")
	}
	json.NewEncoder(w).Encode(resp)
}
