package httputil

import (
	"errors"
	"net"
	"net/url"
	"strings"
)

const MaxLookupLength = 253

var ErrInvalidLookup = errors.New("invalid lookup value")

// LookupValue validates an IP address, hostname, or CIDR value without
// resolving attacker-controlled input.
func LookupValue(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > MaxLookupLength || strings.ContainsAny(value, "\r\n") {
		return "", ErrInvalidLookup
	}
	if ip := net.ParseIP(value); ip != nil {
		return ip.String(), nil
	}
	if _, network, err := net.ParseCIDR(value); err == nil && network != nil {
		return network.String(), nil
	}
	name := strings.TrimSuffix(strings.ToLower(value), ".")
	if strings.Contains(name, "/") || strings.Contains(name, "@") {
		return "", ErrInvalidLookup
	}
	if _, err := url.Parse("https://" + name); err != nil {
		return "", ErrInvalidLookup
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrInvalidLookup
		}
		for _, r := range label {
			if !(r == '-' || r == '_' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
				return "", ErrInvalidLookup
			}
		}
	}
	return name, nil
}
