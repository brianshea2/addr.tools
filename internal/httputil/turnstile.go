package httputil

import (
	"encoding/json"
	"net/http"
	"net/url"
)

type TurnstileClient struct {
	Secret     string
	HttpClient http.Client
}

func (c *TurnstileClient) Verify(token string) (bool, error) {
	values := url.Values{
		"secret":   []string{c.Secret},
		"response": []string{token},
	}
	resp, err := c.HttpClient.PostForm("https://challenges.cloudflare.com/turnstile/v0/siteverify", values)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	var body struct {
		Success bool `json:"success"`
	}
	err = json.NewDecoder(resp.Body).Decode(&body)
	if err != nil {
		return false, err
	}
	return body.Success, nil
}
