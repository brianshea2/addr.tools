package httputil

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"time"
)

const IPInfoTimeout = time.Second

type IPInfo struct {
	City    string `json:"city"`
	Region  string `json:"region"`
	Country string `json:"country"`
	Org     string `json:"org"`
}

func (i *IPInfo) GeoString() string {
	str := i.City
	if len(i.Region) > 0 {
		if len(str) > 0 {
			str += ", "
		}
		str += i.Region
	}
	if len(i.Country) > 0 {
		if len(str) > 0 {
			str += ", "
		}
		str += i.Country
	}
	return str
}

type IPInfoClient struct {
	BaseURL    string
	httpClient *http.Client
}

func (c *IPInfoClient) Get(ip string) (*IPInfo, error) {
	if c.httpClient == nil {
		c.httpClient = &http.Client{Timeout: IPInfoTimeout}
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, err
	}
	if a.Is6() {
		// all ipv6 of the same /64 should have the same info
		p, _ := a.Prefix(64)
		a = p.Addr()
	}
	url, err := url.JoinPath(c.BaseURL, a.StringExpanded())
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("received HTTP status code %d", resp.StatusCode)
	}
	var info IPInfo
	err = json.NewDecoder(resp.Body).Decode(&info)
	if err != nil {
		return nil, err
	}
	return &info, nil
}
