package dnscheck

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/brianshea2/addr.tools/internal/dnsutil"
	"github.com/brianshea2/addr.tools/internal/httputil"
	"github.com/miekg/dns"
	"golang.org/x/time/rate"
)

type BadDnssecProvider struct {
	KeyTagOverride uint16
	*dnsutil.DnssecProvider
}

func (p *BadDnssecProvider) Prove(req, resp *dns.Msg, validFrom, validTo uint32) error {
	if p == nil {
		return nil
	}
	err := p.DnssecProvider.Prove(req, resp, validFrom, validTo)
	if err != nil {
		return err
	}
	ourKeyTag := p.Zsk.KeyTag()
	for _, rr := range resp.Answer {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			if rr.(*dns.RRSIG).KeyTag == ourKeyTag {
				rr.(*dns.RRSIG).KeyTag = p.KeyTagOverride
			}
		}
	}
	for _, rr := range resp.Ns {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			if rr.(*dns.RRSIG).KeyTag == ourKeyTag {
				rr.(*dns.RRSIG).KeyTag = p.KeyTagOverride
			}
		}
	}
	return nil
}

type DnscheckHandler struct {
	Zone                 string
	Ns                   []string
	HostMasterMbox       string
	IPv4                 []net.IP
	IPv6                 []net.IP
	StaticRecords        dnsutil.StaticRecords
	LargeResponseLimiter *rate.Limiter
	Watchers             WatcherHub
	IPInfoClient         *httputil.IPInfoClient
	BadDnssecProvider    *BadDnssecProvider
	*dnsutil.DnssecProvider
}

func (h *DnscheckHandler) Init(privKeyBytes []byte) *DnscheckHandler {
	h.Zone = dns.CanonicalName(h.Zone)
	for i, ns := range h.Ns {
		h.Ns[i] = dns.CanonicalName(ns)
	}
	if len(h.HostMasterMbox) == 0 {
		h.HostMasterMbox = "hostmaster." + h.Zone
	} else {
		h.HostMasterMbox = dns.CanonicalName(h.HostMasterMbox)
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
		h.BadDnssecProvider = &BadDnssecProvider{KeyTagOverride: h.DnssecProvider.Zsk.KeyTag()}
		h.BadDnssecProvider.DnssecProvider, err = dnsutil.GenerateDnssecProvider(
			h.Zone,
			h.DnssecProvider.Zsk.Algorithm,
			h.DnssecProvider.Zsk.Hdr.Ttl,
			h.DnssecProvider.KeySig.Inception,
			h.DnssecProvider.KeySig.Expiration,
		)
		if err != nil {
			log.Fatal(err)
		}
	}
	return h
}

func (h *DnscheckHandler) SOA(q *dns.Question) *dns.SOA {
	return &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   q.Name[len(q.Name)-len(h.Zone):],
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
	}
}

func (h *DnscheckHandler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	q := &req.Question[0]
	sub := q.Name[:len(q.Name)-len(h.Zone)]
	opts := ParseOptions(sub)
	// send to watcher
	if opts != nil && len(opts.Random) > 0 {
		watcher := h.Watchers.Get(opts.Random)
		if watcher != nil {
			watcher.Send(req, dnsutil.GetProtocol(w), w.RemoteAddr(), w.(dns.ConnectionStater).ConnectionState())
		}
	}
	// queries only
	if req.Opcode != dns.OpcodeQuery {
		w.WriteMsg(new(dns.Msg).SetRcode(req, dns.RcodeNotImplemented))
		return
	}
	// prepare response, defer send
	resp := new(dns.Msg).SetReply(req)
	resp.Authoritative = true
	defer func() {
		if resp != nil {
			w.WriteMsg(resp)
		}
	}()
	// edns
	err := dnsutil.CheckAndSetEdns(req, resp)
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
		if opts != nil && opts.Compress {
			resp.Compress = true
		}
		switch dnsutil.GetProtocol(w) {
		case dnsutil.ProtoUDP:
			if opts != nil && opts.NoTruncate {
				break
			}
			if opts != nil && opts.Truncate {
				resp.Truncated = true
				resp.Answer = nil
				resp.Ns = nil
				break
			}
			resp.Truncate(dnsutil.GetMaxUdpSize(req))
			if opts != nil && opts.Compress {
				resp.Compress = true
			}
		case dnsutil.ProtoTLS:
			if dnsutil.HasPadding(req) {
				dnsutil.AddPadding(resp, dnsutil.ResponsePaddingBlockLength)
			}
		}
	}()
	// provide dnssec keys, defer dnssec proof
	if h.ProvideKeys(req, resp) {
		return // no further answers
	}
	defer func() {
		if opts != nil && opts.NoSig {
			return
		}
		var validFrom, validTo uint32
		if opts != nil && opts.ExpiredSig != 0 {
			validTo = uint32(time.Now().Unix()) - uint32(opts.ExpiredSig)
			validFrom = validTo - 7200
			if len(resp.Answer) > 0 {
				validFrom -= resp.Answer[0].Header().Ttl
			} else if len(resp.Ns) > 0 {
				validFrom -= resp.Ns[0].Header().Ttl
			}
		}
		var provider interface {
			Prove(req, resp *dns.Msg, validFrom, validTo uint32) error
		}
		if opts != nil && opts.BadSig {
			provider = h.BadDnssecProvider
		} else {
			provider = h.DnssecProvider
		}
		err := provider.Prove(req, resp, validFrom, validTo)
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
	// validate options
	if opts == nil {
		if resp.Rcode == dns.RcodeNameError {
			if opt := resp.IsEdns0(); opt != nil {
				opt.Option = append(opt.Option, &dns.EDNS0_EDE{
					InfoCode:  dns.ExtendedErrorCodeOther,
					ExtraText: "invalid subdomain options",
				})
			}
		}
		return
	}
	resp.Rcode = dns.RcodeSuccess
	// error response requested
	if opts.Rcode != 0 {
		resp.Rcode = opts.Rcode
		return
	}
	// handle ANY queries
	if q.Qtype == dns.TypeANY && len(resp.Answer) == 0 {
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
		return
	}
	// other records
	switch q.Qtype {
	case dns.TypeA:
		if opts.NullIP {
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    1,
				},
				A: net.IPv4zero,
			})
		} else {
			for _, ip := range h.IPv4 {
				resp.Answer = append(resp.Answer, &dns.A{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    1,
					},
					A: ip,
				})
			}
		}
	case dns.TypeAAAA:
		if opts.NullIP {
			resp.Answer = append(resp.Answer, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    1,
				},
				AAAA: net.IPv6zero,
			})
		} else {
			for _, ip := range h.IPv6 {
				resp.Answer = append(resp.Answer, &dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    1,
					},
					AAAA: ip,
				})
			}
		}
	case dns.TypeHTTPS:
		if opts.NullIP {
			break
		}
		https := &dns.HTTPS{dns.SVCB{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeHTTPS,
				Class:  dns.ClassINET,
				Ttl:    1,
			},
			Priority: 1,
			Target:   ".",
			Value:    []dns.SVCBKeyValue{&dns.SVCBAlpn{Alpn: []string{"h3", "h2"}}},
		}}
		if len(h.IPv4) > 0 {
			https.Value = append(https.Value, &dns.SVCBIPv4Hint{Hint: h.IPv4})
		}
		if len(h.IPv6) > 0 {
			https.Value = append(https.Value, &dns.SVCBIPv6Hint{Hint: h.IPv6})
		}
		resp.Answer = append(resp.Answer, https)
	case dns.TypeTXT:
		if opts.TxtFill != 0 {
			if !h.LargeResponseLimiter.Allow() {
				log.Printf("[warn] DnscheckHandler.ServeDNS: txtfill request rate limited for %s", w.RemoteAddr())
				if opt := resp.IsEdns0(); opt != nil {
					opt.Option = append(opt.Option, &dns.EDNS0_EDE{
						InfoCode:  dns.ExtendedErrorCodeOther,
						ExtraText: "too busy, try again later",
					})
				}
				resp.Rcode = dns.RcodeRefused
				return
			}
			resp.Answer = append(resp.Answer, &dns.TXT{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    1,
				},
				Txt: dnsutil.SplitForTxt(strings.Repeat("0", opts.TxtFill)),
			})
			break // no more txts
		}
		var ip string
		var port int
		switch a := w.RemoteAddr().(type) {
		case *net.UDPAddr:
			ip = a.IP.String()
			port = a.Port
		case *net.TCPAddr:
			ip = a.IP.String()
			port = a.Port
		}
		txts := []string{
			fmt.Sprintf("id: %d", req.Id),
			"proto: " + dnsutil.GetProtocol(w),
			"remoteIp: " + ip,
			fmt.Sprintf("remotePort: %d", port),
		}
		if h.IPInfoClient != nil {
			info, err := h.IPInfoClient.GetIPInfo(ip)
			if err != nil {
				log.Printf("[error] DnscheckHandler.ServeDNS: IPInfoClient.GetIPInfo(%s): %v", ip, err)
			}
			if info != nil {
				if geo := info.GeoString(); len(geo) > 0 {
					txts = append(txts, "remoteGeo: "+dnsutil.ToPrintableAscii(geo))
				}
				if len(info.Org) > 0 {
					txts = append(txts, "remoteOrg: "+dnsutil.ToPrintableAscii(info.Org))
				}
			}
		}
		if opt := req.IsEdns0(); opt != nil {
			var flags string
			if opt.Do() {
				flags = " do"
			}
			txts = append(txts, fmt.Sprintf(
				"edns: version: %d, flags:%s; udp: %d",
				opt.Version(),
				flags,
				opt.UDPSize(),
			))
			for _, o := range opt.Option {
				if o.Option() == dns.EDNS0SUBNET {
					subnet := o.(*dns.EDNS0_SUBNET)
					txts = append(txts, fmt.Sprintf("clientSubnet: %s/%d", subnet.Address, subnet.SourceNetmask))
					break
				}
			}
		}
		if cstate := w.(dns.ConnectionStater).ConnectionState(); cstate != nil {
			txts = append(
				txts,
				"tlsVersion: "+tls.VersionName(cstate.Version),
				"tlsCipherSuite: "+tls.CipherSuiteName(cstate.CipherSuite),
			)
			if len(cstate.ServerName) > 0 {
				txts = append(txts, "tlsServerName: "+dnsutil.ToPrintableAscii(cstate.ServerName))
			}
			if len(cstate.NegotiatedProtocol) > 0 {
				txts = append(txts, "tlsNegotiatedProtocol: "+dnsutil.ToPrintableAscii(cstate.NegotiatedProtocol))
			}
			if cstate.DidResume {
				txts = append(txts, "tlsDidResume: true")
			}
		}
		for _, txt := range txts {
			resp.Answer = append(resp.Answer, &dns.TXT{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    1,
				},
				Txt: dnsutil.SplitForTxt(txt),
			})
		}
	case dns.TypeMX:
		resp.Answer = append(resp.Answer, &dns.MX{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeMX,
				Class:  dns.ClassINET,
				Ttl:    1,
			},
			Preference: 0,
			Mx:         ".",
		})
	}
}
