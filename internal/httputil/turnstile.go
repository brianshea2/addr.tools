package httputil

import (
	"encoding/json"
	"net/http"
	"net/url"
	"time"
)

const TurnstileVerifyTimeout = 5 * time.Second

type TurnstileSite struct {
	Secret string
}

func (ts *TurnstileSite) Verify(token string) (bool, error) {
	values := url.Values{
		"secret":   []string{ts.Secret},
		"response": []string{token},
	}
	client := &http.Client{Timeout: TurnstileVerifyTimeout}
	resp, err := client.PostForm("https://challenges.cloudflare.com/turnstile/v0/siteverify", values)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	var body struct {
		Success bool `json:"success"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return false, err
	}
	return body.Success, nil
}
