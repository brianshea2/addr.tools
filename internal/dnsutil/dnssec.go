package dnsutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/base64"
	"fmt"
	"math/big"
	"time"

	"github.com/miekg/dns"
)

var DefaultNsecTypes = []uint16{
	dns.TypeA,
	dns.TypeNS,
	dns.TypeSOA,
	dns.TypeMX,
	dns.TypeTXT,
	dns.TypeAAAA,
	dns.TypeRRSIG,
	dns.TypeNSEC,
	dns.TypeDNSKEY,
	dns.TypeHTTPS,
}

type DnssecProvider struct {
	Ksk        *dns.DNSKEY
	Zsk        *dns.DNSKEY
	ZskPrivKey crypto.Signer
	KeySig     *dns.RRSIG
	NsecTypes  []uint16
}

func GenerateDnssecProvider(name string, algo uint8, rrTtl, validFrom, validTo uint32) (*DnssecProvider, error) {
	var bits int
	switch algo {
	case dns.ECDSAP256SHA256, dns.ED25519:
		bits = 256
	case dns.ECDSAP384SHA384:
		bits = 384
	default:
		return nil, fmt.Errorf("unsupported algorithm: %v", algo)
	}
	p := &DnssecProvider{
		Ksk: &dns.DNSKEY{
			Hdr: dns.RR_Header{
				Name:   name,
				Rrtype: dns.TypeDNSKEY,
				Class:  dns.ClassINET,
				Ttl:    rrTtl,
			},
			Flags:     257, // Secure Entry Point (SEP) set for KSK
			Protocol:  3,   // DNSSEC
			Algorithm: algo,
		},
		Zsk: &dns.DNSKEY{
			Hdr: dns.RR_Header{
				Name:   name,
				Rrtype: dns.TypeDNSKEY,
				Class:  dns.ClassINET,
				Ttl:    rrTtl,
			},
			Flags:     256, // Secure Entry Point (SEP) not set for ZSK
			Protocol:  3,   // DNSSEC
			Algorithm: algo,
		},
		KeySig: &dns.RRSIG{
			Hdr:        dns.RR_Header{Ttl: rrTtl},
			Algorithm:  algo,
			Expiration: validTo,
			Inception:  validFrom,
			SignerName: name,
		},
	}
	kskPrivateKey, err := p.Ksk.Generate(bits)
	if err != nil {
		return nil, err
	}
	zskPrivateKey, err := p.Zsk.Generate(bits)
	if err != nil {
		return nil, err
	}
	var keySigner crypto.Signer
	switch algo {
	case dns.ECDSAP256SHA256, dns.ECDSAP384SHA384:
		keySigner = kskPrivateKey.(*ecdsa.PrivateKey)
		p.ZskPrivKey = zskPrivateKey.(*ecdsa.PrivateKey)
	case dns.ED25519:
		keySigner = kskPrivateKey.(ed25519.PrivateKey)
		p.ZskPrivKey = zskPrivateKey.(ed25519.PrivateKey)
	}
	p.KeySig.KeyTag = p.Ksk.KeyTag()
	err = p.KeySig.Sign(keySigner, []dns.RR{p.Ksk, p.Zsk})
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (p *DnssecProvider) DS() (*dns.DS, error) {
	if p == nil || p.Ksk == nil {
		return nil, fmt.Errorf("ksk must be populated")
	}
	var h uint8
	switch p.Ksk.Algorithm {
	case dns.ECDSAP256SHA256, dns.ED25519:
		h = dns.SHA256
	case dns.ECDSAP384SHA384:
		h = dns.SHA384
	default:
		return nil, fmt.Errorf("unsupported ksk algorithm: %v", p.Ksk.Algorithm)
	}
	return p.Ksk.ToDS(h), nil
}

func (p *DnssecProvider) PrivKeyBytes() ([]byte, error) {
	if p == nil || p.Zsk == nil {
		return nil, fmt.Errorf("zsk must be populated")
	}
	var b []byte
	switch p.Zsk.Algorithm {
	case dns.ECDSAP256SHA256, dns.ECDSAP384SHA384:
		b = p.ZskPrivKey.(*ecdsa.PrivateKey).D.Bytes()
	case dns.ED25519:
		b = p.ZskPrivKey.(ed25519.PrivateKey).Seed()
	default:
		return nil, fmt.Errorf("unsupported zsk algorithm: %v", p.Zsk.Algorithm)
	}
	return b, nil
}

func (p *DnssecProvider) SetPrivKeyBytes(b []byte) error {
	if p == nil || p.Zsk == nil {
		return fmt.Errorf("zsk must be populated")
	}
	switch p.Zsk.Algorithm {
	case dns.ECDSAP256SHA256, dns.ECDSAP384SHA384:
		pubBytes, err := base64.StdEncoding.DecodeString(p.Zsk.PublicKey)
		if err != nil {
			return fmt.Errorf("cannot decode zsk public key: %w", err)
		}
		var curve elliptic.Curve
		switch p.Zsk.Algorithm {
		case dns.ECDSAP256SHA256:
			if len(pubBytes) != 64 {
				return fmt.Errorf("wrong zsk public key length: %v", len(pubBytes))
			}
			curve = elliptic.P256()
		case dns.ECDSAP384SHA384:
			if len(pubBytes) != 96 {
				return fmt.Errorf("wrong zsk public key length: %v", len(pubBytes))
			}
			curve = elliptic.P384()
		}
		p.ZskPrivKey = &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: curve,
				X:     new(big.Int).SetBytes(pubBytes[:len(pubBytes)/2]),
				Y:     new(big.Int).SetBytes(pubBytes[len(pubBytes)/2:]),
			},
			D: new(big.Int).SetBytes(b),
		}
	case dns.ED25519:
		p.ZskPrivKey = ed25519.NewKeyFromSeed(b)
	default:
		return fmt.Errorf("unsupported zsk algorithm: %v", p.Zsk.Algorithm)
	}
	return nil
}

func (p *DnssecProvider) Sign(rrs []dns.RR, validFrom, validTo uint32) (sigs []dns.RR, err error) {
	if p == nil || p.Zsk == nil {
		return nil, fmt.Errorf("zsk must be populated")
	}
	if len(rrs) == 0 {
		return
	}
	var now uint32
	if validFrom == 0 || validTo == 0 {
		now = uint32(time.Now().Unix())
		if validFrom == 0 {
			validFrom = now - 3600
		}
	}
	rrsByType := make(map[uint16][]dns.RR)
	for _, rr := range rrs {
		rrtype := rr.Header().Rrtype
		rrsByType[rrtype] = append(rrsByType[rrtype], rr)
	}
	for _, rrsOfSameType := range rrsByType {
		expiration := validTo
		if expiration == 0 {
			expiration = now + 3600 + rrsOfSameType[0].Header().Ttl
		}
		sig := &dns.RRSIG{
			Hdr:        dns.RR_Header{Ttl: rrsOfSameType[0].Header().Ttl},
			Algorithm:  p.Zsk.Algorithm,
			Expiration: expiration,
			Inception:  validFrom,
			KeyTag:     p.Zsk.KeyTag(),
			SignerName: p.Zsk.Hdr.Name,
		}
		err = sig.Sign(p.ZskPrivKey, rrsOfSameType)
		if err != nil {
			return
		}
		sigs = append(sigs, sig)
	}
	return
}

// adds DNSSEC keys (and keysig) to resp if requested by req, returns true iff keys were added
func (p *DnssecProvider) ProvideKeys(req, resp *dns.Msg) bool {
	if p == nil || p.Ksk == nil || p.Zsk == nil {
		return false
	}
	q := &req.Question[0]
	if q.Qclass == dns.ClassINET && q.Qtype == dns.TypeDNSKEY && EqualsAsciiIgnoreCase(q.Name, p.Ksk.Hdr.Name) {
		resp.Answer = append(resp.Answer, dns.Copy(p.Ksk), dns.Copy(p.Zsk))
		resp.Answer[len(resp.Answer)-2].Header().Name = q.Name
		resp.Answer[len(resp.Answer)-1].Header().Name = q.Name
		if opt := req.IsEdns0(); opt != nil && opt.Do() {
			resp.Answer = append(resp.Answer, dns.Copy(p.KeySig))
			resp.Answer[len(resp.Answer)-1].Header().Name = q.Name
		}
		return true
	}
	return false
}

// adds DNSSEC signatures to resp
func (p *DnssecProvider) Prove(req, resp *dns.Msg, validFrom, validTo uint32) error {
	if p == nil || p.ZskPrivKey == nil {
		return nil
	}
	// only prove successful answers (including non-existence)
	if !(resp.Rcode == dns.RcodeSuccess || resp.Rcode == dns.RcodeNameError) {
		return nil
	}
	q := &req.Question[0]
	// only class IN
	if q.Qclass != dns.ClassINET {
		return nil
	}
	// stop here if answer section already contains RRSIG
	for _, rr := range resp.Answer {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			return nil
		}
	}
	// stop here if signing isn't requested
	if opt := req.IsEdns0(); opt == nil || !opt.Do() {
		return nil
	}
	// sign answer section
	if len(resp.Answer) == 0 {
		// prove non-existence
		var types []uint16
		if resp.Rcode == dns.RcodeNameError {
			resp.Rcode = dns.RcodeSuccess
			types = []uint16{dns.TypeRRSIG, dns.TypeNSEC}
		} else {
			if p.NsecTypes == nil {
				types = make([]uint16, len(DefaultNsecTypes))
				copy(types, DefaultNsecTypes)
			} else {
				types = make([]uint16, len(p.NsecTypes))
				copy(types, p.NsecTypes)
			}
			isApex := EqualsAsciiIgnoreCase(q.Name, p.Ksk.Hdr.Name)
			for i := 0; i < len(types); {
				if types[i] == q.Qtype || (!isApex && (types[i] == dns.TypeNS ||
					types[i] == dns.TypeSOA || types[i] == dns.TypeDNSKEY)) {
					types = append(types[:i], types[i+1:]...) // remove
					continue
				}
				i++
			}
		}
		resp.Ns = append(resp.Ns, &dns.NSEC{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeNSEC,
				Class:  dns.ClassINET,
				Ttl:    p.Ksk.Hdr.Ttl,
			},
			NextDomain: "\\000." + ToLowerAscii(q.Name),
			TypeBitMap: types,
		})
	} else {
		sigs, err := p.Sign(resp.Answer, validFrom, validTo)
		if err != nil {
			return err
		}
		resp.Answer = append(resp.Answer, sigs...)
	}
	// sign authority section
	if len(resp.Ns) > 0 {
		sigs, err := p.Sign(resp.Ns, validFrom, validTo)
		if err != nil {
			return err
		}
		resp.Ns = append(resp.Ns, sigs...)
	}
	return nil
}
