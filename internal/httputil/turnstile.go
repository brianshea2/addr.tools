package httputil

import (
	"encoding/json"
	"net/http"
	"net/url"
	"time"
)

const TurnstileVerifyTimeout = 5 * time.Second

type TurnstileSite struct {
	Secret     string
	httpClient *http.Client
}

func (ts *TurnstileSite) Verify(token string) (bool, error) {
	if ts.httpClient == nil {
		ts.httpClient = &http.Client{Timeout: TurnstileVerifyTimeout}
	}
	values := url.Values{
		"secret":   []string{ts.Secret},
		"response": []string{token},
	}
	resp, err := ts.httpClient.PostForm("https://challenges.cloudflare.com/turnstile/v0/siteverify", values)
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
