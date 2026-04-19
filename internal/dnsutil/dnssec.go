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
	SigningKey *dns.DNSKEY
	PrivateKey crypto.Signer
	NsecTypes  []uint16
}

func GenerateDnssecProvider(name string, algo uint8, rrTtl uint32) (*DnssecProvider, error) {
	p := &DnssecProvider{
		SigningKey: &dns.DNSKEY{
			Hdr: dns.RR_Header{
				Name:   name,
				Rrtype: dns.TypeDNSKEY,
				Class:  dns.ClassINET,
				Ttl:    rrTtl,
			},
			Flags:     257, // Secure Entry Point
			Protocol:  3,   // DNSSEC
			Algorithm: algo,
		},
	}
	switch algo {
	case dns.ECDSAP256SHA256:
		key, err := p.SigningKey.Generate(256)
		if err != nil {
			return nil, err
		}
		p.PrivateKey = key.(*ecdsa.PrivateKey)
	case dns.ECDSAP384SHA384:
		key, err := p.SigningKey.Generate(384)
		if err != nil {
			return nil, err
		}
		p.PrivateKey = key.(*ecdsa.PrivateKey)
	case dns.ED25519:
		key, err := p.SigningKey.Generate(256)
		if err != nil {
			return nil, err
		}
		p.PrivateKey = key.(ed25519.PrivateKey)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %v", algo)
	}
	return p, nil
}

func (p *DnssecProvider) DS() (*dns.DS, error) {
	if p == nil || p.SigningKey == nil {
		return nil, fmt.Errorf("missing signing key")
	}
	switch p.SigningKey.Algorithm {
	case dns.ECDSAP256SHA256, dns.ED25519:
		return p.SigningKey.ToDS(dns.SHA256), nil
	case dns.ECDSAP384SHA384:
		return p.SigningKey.ToDS(dns.SHA384), nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %v", p.SigningKey.Algorithm)
	}
}

func (p *DnssecProvider) PrivKeyBytes() ([]byte, error) {
	if p == nil || p.SigningKey == nil {
		return nil, fmt.Errorf("missing signing key")
	}
	switch p.SigningKey.Algorithm {
	case dns.ECDSAP256SHA256, dns.ECDSAP384SHA384:
		return p.PrivateKey.(*ecdsa.PrivateKey).D.Bytes(), nil
	case dns.ED25519:
		return p.PrivateKey.(ed25519.PrivateKey).Seed(), nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %v", p.SigningKey.Algorithm)
	}
}

func (p *DnssecProvider) SetPrivKeyBytes(b []byte) error {
	if p == nil || p.SigningKey == nil {
		return fmt.Errorf("missing signing key")
	}
	switch p.SigningKey.Algorithm {
	case dns.ECDSAP256SHA256, dns.ECDSAP384SHA384:
		pubBytes, err := base64.StdEncoding.DecodeString(p.SigningKey.PublicKey)
		if err != nil {
			return fmt.Errorf("cannot decode public key: %w", err)
		}
		var curve elliptic.Curve
		switch p.SigningKey.Algorithm {
		case dns.ECDSAP256SHA256:
			if len(pubBytes) != 64 {
				return fmt.Errorf("wrong public key length: %v", len(pubBytes))
			}
			curve = elliptic.P256()
		case dns.ECDSAP384SHA384:
			if len(pubBytes) != 96 {
				return fmt.Errorf("wrong public key length: %v", len(pubBytes))
			}
			curve = elliptic.P384()
		}
		p.PrivateKey = &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: curve,
				X:     new(big.Int).SetBytes(pubBytes[:len(pubBytes)/2]),
				Y:     new(big.Int).SetBytes(pubBytes[len(pubBytes)/2:]),
			},
			D: new(big.Int).SetBytes(b),
		}
	case dns.ED25519:
		p.PrivateKey = ed25519.NewKeyFromSeed(b)
	default:
		return fmt.Errorf("unsupported algorithm: %v", p.SigningKey.Algorithm)
	}
	return nil
}

func (p *DnssecProvider) Sign(rrs []dns.RR, validFrom, validTo uint32) (sigs []dns.RR, err error) {
	if p == nil || p.SigningKey == nil {
		return nil, fmt.Errorf("missing signing key")
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
	typesAlreadySigned := make(map[uint16]struct{})
	for _, rr := range rrs {
		rrtype := rr.Header().Rrtype
		if rrtype == dns.TypeRRSIG {
			typesAlreadySigned[rr.(*dns.RRSIG).TypeCovered] = struct{}{}
		} else {
			rrsByType[rrtype] = append(rrsByType[rrtype], rr)
		}
	}
	for rrtype, rrsOfSameType := range rrsByType {
		if _, alreadySigned := typesAlreadySigned[rrtype]; alreadySigned {
			continue
		}
		expiration := validTo
		if expiration == 0 {
			expiration = now + 3600 + rrsOfSameType[0].Header().Ttl
		}
		sig := &dns.RRSIG{
			Hdr:        dns.RR_Header{Ttl: rrsOfSameType[0].Header().Ttl},
			Algorithm:  p.SigningKey.Algorithm,
			Expiration: expiration,
			Inception:  validFrom,
			KeyTag:     p.SigningKey.KeyTag(),
			SignerName: p.SigningKey.Hdr.Name,
		}
		err = sig.Sign(p.PrivateKey, rrsOfSameType)
		if err != nil {
			return
		}
		sigs = append(sigs, sig)
	}
	return
}

// adds DNSKEY to resp if requested by req, returns true iff key was added
func (p *DnssecProvider) ProvideKeys(req, resp *dns.Msg) bool {
	if p == nil || p.SigningKey == nil {
		return false
	}
	q := &req.Question[0]
	if q.Qclass == dns.ClassINET && q.Qtype == dns.TypeDNSKEY && EqualsAsciiIgnoreCase(q.Name, p.SigningKey.Hdr.Name) {
		resp.Answer = append(resp.Answer, dns.Copy(p.SigningKey))
		resp.Answer[len(resp.Answer)-1].Header().Name = q.Name
		return true
	}
	return false
}

// adds DNSSEC signatures to resp
func (p *DnssecProvider) Prove(req, resp *dns.Msg, validFrom, validTo uint32) error {
	if p == nil || p.PrivateKey == nil {
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
	// stop here if signing isn't requested
	opt := req.IsEdns0()
	if opt == nil || !opt.Do() {
		return nil
	}
	// sign answer section
	if len(resp.Answer) == 0 {
		// prove non-existence
		var types []uint16
		if resp.Rcode == dns.RcodeNameError {
			if !opt.Co() {
				resp.Rcode = dns.RcodeSuccess
			}
			types = []uint16{dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNXNAME}
		} else {
			if p.NsecTypes == nil {
				types = make([]uint16, len(DefaultNsecTypes))
				copy(types, DefaultNsecTypes)
			} else {
				types = make([]uint16, len(p.NsecTypes))
				copy(types, p.NsecTypes)
			}
			isApex := EqualsAsciiIgnoreCase(q.Name, p.SigningKey.Hdr.Name)
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
				Ttl:    p.SigningKey.Hdr.Ttl,
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
