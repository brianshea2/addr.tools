package dns2json

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
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
	MaxCacheLength       = 50000
	MaxUdpMsgSize        = 1400
)

func isTimeout(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	if netErr, ok := errors.AsType[net.Error](err); ok && netErr.Timeout() {
		return true
	}
	return false
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
	expires   time.Time
}

func (r *response) ok() bool {
	return r.Status == dns.RcodeSuccess || r.Status == dns.RcodeNameError
}

func (r *response) fresh() bool {
	return time.Now().Before(r.expires)
}

func (r *response) ttl() uint32 {
	t := time.Until(r.expires)
	if t < 0 {
		return 0
	}
	return uint32(math.Ceil(t.Seconds()))
}

func (r *response) setTtl(ttl uint32) {
	r.expires = time.Now().Add(time.Duration(ttl) * time.Second)
}

type cacheNode struct {
	key string

	visited atomic.Bool
	prev    *cacheNode // must hold LookupHandler.cacheMu
	next    *cacheNode // must hold LookupHandler.cacheMu

	respMu sync.RWMutex
	resp   *response // must hold respMu
	err    error     // must hold respMu
}

type LookupHandler struct {
	Upstream string
	hitCount atomic.Uint64
	fwdCount atomic.Uint64

	cacheMu sync.RWMutex
	cache   map[string]*cacheNode // must hold cacheMu
	head    *cacheNode            // must hold cacheMu
	tail    *cacheNode            // must hold cacheMu
	hand    *cacheNode            // must hold cacheMu
}

func (h *LookupHandler) HitCount() uint64 { return h.hitCount.Load() }
func (h *LookupHandler) FwdCount() uint64 { return h.fwdCount.Load() }

func (h *LookupHandler) CacheSize() int {
	h.cacheMu.RLock()
	defer h.cacheMu.RUnlock()
	return len(h.cache)
}

func (h *LookupHandler) add(node *cacheNode) {
	if h.cache == nil {
		h.cache = make(map[string]*cacheNode, MaxCacheLength)
	}
	node.next = h.head
	node.prev = nil
	if h.head != nil {
		h.head.prev = node
	}
	h.head = node
	if h.tail == nil {
		h.tail = node
	}
	h.cache[node.key] = node
}

func (h *LookupHandler) evict() {
	node := h.hand
	if node == nil {
		node = h.tail
	}
	for node.visited.CompareAndSwap(true, false) {
		node = node.prev
		if node == nil {
			node = h.tail
		}
	}
	h.hand = node.prev
	if node.prev == nil {
		h.head = node.next
	} else {
		node.prev.next = node.next
	}
	if node.next == nil {
		h.tail = node.prev
	} else {
		node.next.prev = node.prev
	}
	delete(h.cache, node.key)
}

func (h *LookupHandler) getOrAdd(key string) *cacheNode {
	h.cacheMu.RLock()

	node, hit := h.cache[key]
	if hit {
		defer h.cacheMu.RUnlock()
		node.visited.Store(true)
		return node
	}

	h.cacheMu.RUnlock()
	h.cacheMu.Lock()
	defer h.cacheMu.Unlock()

	node, hit = h.cache[key]
	if hit {
		node.visited.Store(true)
		return node
	}

	if len(h.cache) >= MaxCacheLength {
		h.evict()
	}

	node = &cacheNode{key: key}
	h.add(node)
	return node
}

func (h *LookupHandler) lookup(qname string, qtype uint16) (resp *response, hit bool, err error) {
	defer func() {
		if hit {
			h.hitCount.Add(1)
		} else {
			h.fwdCount.Add(1)
		}
	}()

	qname = dns.CanonicalName(qname)
	node := h.getOrAdd(fmt.Sprintf("%s:%d", qname, qtype))

	if !node.respMu.TryRLock() {
		// in-flight
		node.respMu.RLock()
		defer node.respMu.RUnlock()
		return node.resp, true, node.err
	}

	if node.resp != nil && node.resp.fresh() {
		defer node.respMu.RUnlock()
		return node.resp, true, nil
	}

	node.respMu.RUnlock()
	node.respMu.Lock()
	defer node.respMu.Unlock()

	if node.resp != nil && node.resp.fresh() {
		return node.resp, true, nil
	}

	node.resp, node.err = h.forward(qname, qtype)
	return node.resp, false, node.err
}

func (h *LookupHandler) forward(qname string, qtype uint16) (*response, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(qname, qtype)
	msg.SetEdns0(MaxUdpMsgSize, false)

	client := &dns.Client{Timeout: LookupTimeout}
	received, _, err := client.Exchange(msg, h.Upstream)
	if err == nil && received.Truncated {
		client.Net = "tcp"
		received, _, err = client.Exchange(msg, h.Upstream)
	}
	if err != nil {
		return nil, err
	}

	resp := &response{Status: received.Rcode}

	var ttl uint32
	if len(received.Answer) > 0 || len(received.Ns) > 0 {
		ttl = LookupResponseMaxTtl
	}
	if len(received.Answer) > 0 {
		resp.Answer = make([]record, len(received.Answer))
		for i, rr := range received.Answer {
			hdr := rr.Header()
			if hdr.Ttl < ttl {
				ttl = hdr.Ttl
			}
			resp.Answer[i] = record{hdr.Name, hdr.Rrtype, rr.String()[len(hdr.String()):]}
		}
	}
	if len(received.Ns) > 0 {
		resp.Authority = make([]record, len(received.Ns))
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
			resp.Authority[i] = record{hdr.Name, hdr.Rrtype, rr.String()[len(hdr.String()):]}
		}
	}

	if !resp.ok() || ttl < LookupResponseMinTtl {
		ttl = LookupResponseMinTtl
	}
	resp.setTtl(ttl)

	return resp, nil
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

	resp, hit, err := h.lookup(qname, qtype)
	if err != nil && isTimeout(err) {
		http.Error(w, "dns timeout", http.StatusGatewayTimeout)
		return
	}
	if err != nil {
		log.Printf("[error] dns2json.LookupHandler.ServeHTTP: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if ttl := resp.ttl(); ttl > 0 {
		w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", ttl))
	}
	if hit {
		w.Header().Set("Cache-Status", "addrd; hit")
	} else {
		w.Header().Set("Cache-Status", "addrd; fwd=miss")
	}
	json.NewEncoder(w).Encode(resp)
}
