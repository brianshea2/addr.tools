package challenges

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/brianshea2/addr.tools/internal/httputil"
	"github.com/brianshea2/addr.tools/internal/ttlstore"
)

const ChallengeTtl = 120

type HTTPHandler struct {
	ChallengeStore ttlstore.TtlStore
	Zone           string
}

func IsValidChallenge(s string) bool {
	if len(s) < 1 || len(s) > 255 {
		return false
	}
	var c byte
	for i := 0; i < len(s); i++ {
		c = s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'A' && c <= 'Z':
		case c >= 'a' && c <= 'z':
		case c == '-':
		case c == '_':
		// reminder: do not allow '='
		default:
			return false
		}
	}
	return true
}

func (h *HTTPHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// validate method
	switch req.Method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete:
	default:
		w.Header().Set("Allow", "GET, POST, PUT, DELETE")
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}
	// parse request
	values := httputil.ParseRequest(req)
	// require "secret" (any string is valid)
	secret, err := values.GetString("secret")
	if len(secret) == 0 || err != nil {
		switch {
		case err == nil:
			http.Error(w, "must specify \"secret\"", http.StatusBadRequest)
		case errors.Is(err, httputil.ErrAmbiguousValues):
			http.Error(w, "multiple values found for \"secret\"", http.StatusBadRequest)
		case errors.Is(err, httputil.ErrValueUnexpectedType):
			http.Error(w, "\"secret\" must be a string", http.StatusBadRequest)
		default:
			log.Printf("[error] challenges.HTTPHandler.ServeHTTP: get secret: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
		}
		return
	}
	// get "txt"
	txt, err := values.GetString("txt")
	if err != nil {
		switch {
		case errors.Is(err, httputil.ErrAmbiguousValues):
			http.Error(w, "multiple values found for \"txt\"", http.StatusBadRequest)
		case errors.Is(err, httputil.ErrValueUnexpectedType):
			http.Error(w, "\"txt\" must be a string", http.StatusBadRequest)
		default:
			log.Printf("[error] challenges.HTTPHandler.ServeHTTP: get txt: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
		}
		return
	}
	// make sure "txt" is a valid challenge string
	if len(txt) > 0 && !IsValidChallenge(txt) {
		http.Error(w, "invalid value for \"txt\"", http.StatusBadRequest)
		return
	}
	// try to use the entire body as the "txt" value if not found
	// warning: could contain form values (i.e., "secret=..."), do not allow '=' in "txt" values
	if len(txt) == 0 && req.Method != http.MethodGet {
		if bodyText, _ := values.BodyText(); IsValidChallenge(bodyText) {
			txt = bodyText
		}
	}
	// calculate domain
	domain := fmt.Sprintf("%x.%s", sha256.Sum224([]byte(secret)), h.Zone)
	switch req.Method {
	case http.MethodDelete:
		// require "txt"
		if len(txt) == 0 {
			http.Error(w, "must specify \"txt\"", http.StatusBadRequest)
			return
		}
		// delete
		h.ChallengeStore.Remove(domain, []byte(txt))
		w.WriteHeader(http.StatusNoContent)
	default:
		// write domain if "txt" not specified
		if len(txt) == 0 {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintln(w, domain)
			return
		}
		// add
		err = h.ChallengeStore.Add(domain, []byte(txt), ChallengeTtl)
		if err != nil {
			log.Printf("[error] challenges.HTTPHandler.ServeHTTP: add challenge: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintln(w, "OK")
	}
}
