package httputil

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

type IPInfo struct {
	City    string `json:"city"`
	Region  string `json:"region"`
	Country string `json:"country"`
	Org     string `json:"org"`
}

func (i *IPInfo) GeoString() string {
	return strings.Join(
		slices.DeleteFunc(
			[]string{
				i.City,
				i.Region,
				i.Country,
			},
			func(s string) bool {
				return len(s) == 0
			},
		),
		", ",
	)
}

type IPInfoClient struct {
	BaseURL    string
	HttpClient http.Client
}

func (c *IPInfoClient) GetIPInfo(ip string) (*IPInfo, error) {
	url, err := url.JoinPath(c.BaseURL, ip)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := c.HttpClient.Do(req)
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
