package ip

import (
	"log"
	"net"
	"time"

	"github.com/brianshea2/addr.tools/internal/dnsutil"
	"github.com/brianshea2/addr.tools/internal/ttlstore"
	"github.com/brianshea2/addr.tools/internal/zones/challenges"
	"github.com/miekg/dns"
	"golang.org/x/time/rate"
)

const (
	ChallengeTtl         = 120
	MaxUpdatesPerRequest = 10
	// not really a secret, published for client compatibility, not enforced
	TsigSecret = "ipL40QrEy8cSwmP6OqCihGlYNmE="
)

type UpdateHandler struct {
	ChallengeStore ttlstore.TtlStore
	UpdateLimiter  *rate.Limiter
}

// adheres loosely to [rfc 2136](https://datatracker.ietf.org/doc/html/rfc2136)
func (h *UpdateHandler) HandleUpdate(w dns.ResponseWriter, req *dns.Msg, zone string) {
	// 3.8	- At the end of UPDATE processing, a response code will be known.  A
	//        response message is generated by copying the ID and Opcode fields
	//        from the request, and either copying the ZOCOUNT, PRCOUNT, UPCOUNT,
	//        and ADCOUNT fields and associated sections, or placing zeros (0) in
	//        the these "count" fields and not including any part of the original
	//        update.  The QR bit is set to one (1), and the response is sent back
	//        to the requestor.
	resp := new(dns.Msg)
	resp.Id = req.Id
	resp.Opcode = req.Opcode
	resp.Response = true
	defer func() {
		w.WriteMsg(resp)
	}()
	// 2	- The overall format of an UPDATE message is
	//
	// 			+---------------------+
	// 			|        Header       |
	//			+---------------------+
	// 			|         Zone        | specifies the zone to be updated
	// 			+---------------------+
	// 			|     Prerequisite    | RRs or RRsets which must (not) preexist
	// 			+---------------------+
	// 			|        Update       | RRs or RRsets to be added or deleted
	// 			+---------------------+
	// 			|   Additional Data   | additional data
	// 			+---------------------+
	//
	zoneSection := req.Question
	prereqSection := req.Answer
	updateSection := req.Ns
	// 3.1	- 3.1.1. The Zone Section is checked to see that there is exactly one
	//    	  RR therein and that the RR's ZTYPE is SOA, else signal FORMERR to the
	// 	      requestor.  Next, the ZNAME and ZCLASS are checked to see if the zone
	//  	  so named is one of this server's authority zones, else signal NOTAUTH
	//   	  to the requestor.
	if len(zoneSection) != 1 || zoneSection[0].Qtype != dns.TypeSOA {
		resp.Rcode = dns.RcodeFormatError
		return
	}
	if !dnsutil.EqualsAsciiIgnoreCase(zoneSection[0].Name, zone) || zoneSection[0].Qclass != dns.ClassINET {
		resp.Rcode = dns.RcodeNotAuth
		return
	}
	// 3.2	- Process Prerequisite Section
	//        (not implementing this)
	if len(prereqSection) > 0 {
		resp.Rcode = dns.RcodeNotImplemented
		return
	}
	// 3.4	- Process Update Section
	if len(updateSection) > MaxUpdatesPerRequest {
		resp.Rcode = dns.RcodeRefused
		return
	}
	toProcess := make([]*dns.TXT, 0, len(updateSection))
	for _, rr := range updateSection {
		hdr := rr.Header()
		// only accept class IN (add) and NONE (delete)
		if hdr.Class != dns.ClassINET && hdr.Class != dns.ClassNONE {
			resp.Rcode = dns.RcodeRefused
			return
		}
		// only accept type TXT
		if hdr.Rrtype != dns.TypeTXT {
			resp.Rcode = dns.RcodeRefused
			return
		}
		txtRr := rr.(*dns.TXT)
		// only accept valid challenge strings
		if len(txtRr.Txt) != 1 || !challenges.IsValidChallenge(txtRr.Txt[0]) {
			resp.Rcode = dns.RcodeRefused
			return
		}
		// only for _acme-challenge subdomains of this zone
		if len(hdr.Name) < len(zone)+18 ||
			!dnsutil.EqualsAsciiIgnoreCase(hdr.Name[:16], "_acme-challenge.") ||
			!dnsutil.EqualsAsciiIgnoreCase(hdr.Name[len(hdr.Name)-len(zone)-1:], "."+zone) {
			resp.Rcode = dns.RcodeRefused
			return
		}
		// only for valid ip subdomains
		ip := ParseIP(hdr.Name[:len(hdr.Name)-len(zone)])
		if ip == nil {
			resp.Rcode = dns.RcodeRefused
			return
		}
		// check permission to update this ip
		switch {
		// allow all: 10/8, 172.16/12, 192.168/16, fc00::/7
		case ip.IsPrivate():
		// allow all: 127/8, ::1
		case ip.IsLoopback():
		// allow all: 100.64/10 (cgnat, also used by tailscale, etc.)
		case (&net.IPNet{IP: net.IP{0x64, 0x40, 0x0, 0x0}, Mask: net.IPMask{0xff, 0xc0, 0x0, 0x0}}).Contains(ip):
		default:
			// require tcp
			if w.RemoteAddr().Network() != "tcp" {
				resp.Rcode = dns.RcodeRefused
				return
			}
			// require matching client ip
			if addr, ok := w.RemoteAddr().(*net.TCPAddr); !ok || !ip.Equal(addr.IP) {
				resp.Rcode = dns.RcodeRefused
				return
			}
		}
		toProcess = append(toProcess, txtRr)
	}
	for _, txtRr := range toProcess {
		// check rate
		if !h.UpdateLimiter.Allow() {
			log.Printf("[warn] ipzone.UpdateHandler.HandleUpdate: update rate limited for %s", w.RemoteAddr())
			resp.Rcode = dns.RcodeRefused
			return
		}
		switch txtRr.Hdr.Class {
		case dns.ClassINET:
			// add
			err := h.ChallengeStore.Add(dnsutil.ToLowerAscii(txtRr.Hdr.Name), []byte(txtRr.Txt[0]), ChallengeTtl)
			if err != nil {
				log.Printf("[error] ipzone.UpdateHandler.HandleUpdate: add client challenge: %v", err)
				resp.Rcode = dns.RcodeServerFailure
				return
			}
		case dns.ClassNONE:
			// delete
			h.ChallengeStore.Remove(dnsutil.ToLowerAscii(txtRr.Hdr.Name), []byte(txtRr.Txt[0]))
		}
	}
	// TSIG [rfc 2845](https://datatracker.ietf.org/doc/html/rfc2845)
	// (not enforced, here for client compatibility only)
	if req.IsTsig() != nil && w.TsigStatus() == nil {
		resp.SetTsig(zone, dns.HmacSHA1, 300, time.Now().Unix())
	}
}
