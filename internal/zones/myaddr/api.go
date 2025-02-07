package myaddr

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/brianshea2/addr.tools/internal/dnsutil"
	"github.com/brianshea2/addr.tools/internal/httputil"
	"github.com/brianshea2/addr.tools/internal/ttlstore"
	"github.com/brianshea2/addr.tools/internal/zones/challenges"
)

const (
	PendingTtl      = 3600
	RegistrationTtl = 120 * 86400
	AddressTtl      = 90 * 86400
	ChallengeTtl    = 120
)

func IsValidName(s string) bool {
	// Names must:
	// - be 6 to 40 characters long
	// - start with a letter
	// - end with a letter or number
	// - consist of only letters, numbers, and hyphens
	if len(s) < 6 || len(s) > 40 {
		return false
	}
	var c byte
	for i := 0; i < len(s); i++ {
		c = s[i]
		switch {
		case c >= '0' && c <= '9' && i > 0:
		case c >= 'A' && c <= 'Z':
		case c >= 'a' && c <= 'z':
		case c == '-' && i > 0 && i < len(s)-1:
		default:
			return false
		}
	}
	return true
}

func UpdateRegistration(hash, name string, store ttlstore.TtlStore, prefix string) error {
	var ttl uint32
	now := uint32(time.Now().Unix())
	// get ctime
	ctime := store.Get(prefix + name + ":ctime")
	if ctime == nil {
		// new
		ttl = PendingTtl
		ctime = make([]byte, 4)
		binary.BigEndian.PutUint32(ctime, now)
	} else {
		// update
		ttl = RegistrationTtl
	}
	// (re-)set hash -> name
	err := store.Set(prefix+"hash:"+hash, []byte(name), ttl)
	if err != nil {
		return err
	}
	// (re-)set ctime
	err = store.Set(prefix+name+":ctime", ctime, ttl)
	if err != nil {
		return err
	}
	// set new mtime
	mtime := make([]byte, 4)
	binary.BigEndian.PutUint32(mtime, now)
	return store.Set(prefix+name+":mtime", mtime, ttl)
}

func GetRegistrationInfo(name string, store ttlstore.TtlStore, prefix string) (created, updated, expires uint32) {
	if ctime := store.Get(prefix + name + ":ctime"); ctime != nil {
		created = binary.BigEndian.Uint32(ctime)
		if mtime := store.Get(prefix + name + ":mtime"); mtime != nil {
			updated = binary.BigEndian.Uint32(mtime)
			if created == updated {
				expires = updated + PendingTtl
			} else {
				expires = updated + RegistrationTtl
			}
		}
	}
	return
}

type RegistrationHandler struct {
	DataStore       ttlstore.TtlStore
	ChallengeStore  ttlstore.TtlStore
	KeyPrefix       string
	TurnstileClient *httputil.TurnstileClient
}

func (h *RegistrationHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// validate method
	switch req.Method {
	case http.MethodGet, http.MethodPost, http.MethodDelete:
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}
	// parse request
	values := httputil.ParseRequest(req)
	switch req.Method {
	case http.MethodGet, http.MethodDelete:
		// require "key"
		key, err := values.GetString("key")
		if len(key) == 0 || err != nil {
			switch {
			case err == nil:
				http.Error(w, "must specify \"key\"", http.StatusBadRequest)
			case errors.Is(err, httputil.ErrAmbiguousValues):
				http.Error(w, "multiple values found for \"key\"", http.StatusBadRequest)
			case errors.Is(err, httputil.ErrValueUnexpectedType):
				http.Error(w, "\"key\" must be a string", http.StatusBadRequest)
			default:
				log.Printf("[error] myaddr.RegistrationHandler.ServeHTTP: get key: %v", err)
				http.Error(w, "server error", http.StatusInternalServerError)
			}
			return
		}
		if len(key) != 64 {
			http.Error(w, "invalid value for \"key\"", http.StatusBadRequest)
			return
		}
		// find name
		hash := fmt.Sprintf("%x", sha256.Sum256([]byte(key)))
		name := string(h.DataStore.Get(h.KeyPrefix + "hash:" + hash))
		if len(name) == 0 {
			http.Error(w, "registration not found", http.StatusNotFound)
			return
		}
		w.Header().Set("myaddr-name", name)
		switch req.Method {
		case http.MethodGet:
			// get
			w.Header().Set("Content-Type", "application/json")
			created, updated, expires := GetRegistrationInfo(name, h.DataStore, h.KeyPrefix)
			json.NewEncoder(w).Encode(
				struct {
					Name       string `json:"name"`
					Registered uint32 `json:"registered"`
					Updated    uint32 `json:"updated"`
					Expires    uint32 `json:"expires"`
				}{
					Name:       name,
					Registered: created,
					Updated:    updated,
					Expires:    expires,
				},
			)
		case http.MethodDelete:
			// delete
			h.DataStore.Delete(h.KeyPrefix + "hash:" + hash)
			h.DataStore.Delete(h.KeyPrefix + name + ":ctime")
			h.DataStore.Delete(h.KeyPrefix + name + ":mtime")
			h.DataStore.Delete(h.KeyPrefix + name + ":ip4")
			h.DataStore.Delete(h.KeyPrefix + name + ":ip4mtime")
			h.DataStore.Delete(h.KeyPrefix + name + ":ip6")
			h.DataStore.Delete(h.KeyPrefix + name + ":ip6mtime")
			h.ChallengeStore.Delete(h.KeyPrefix + name)
			w.WriteHeader(http.StatusNoContent)
		}
	case http.MethodPost:
		// require "name"
		name, err := values.GetString("name")
		if len(name) == 0 || err != nil {
			switch {
			case err == nil:
				http.Error(w, "must specify \"name\"", http.StatusBadRequest)
			case errors.Is(err, httputil.ErrAmbiguousValues):
				http.Error(w, "multiple values found for \"name\"", http.StatusBadRequest)
			case errors.Is(err, httputil.ErrValueUnexpectedType):
				http.Error(w, "\"name\" must be a string", http.StatusBadRequest)
			default:
				log.Printf("[error] myaddr.RegistrationHandler.ServeHTTP: get name: %v", err)
				http.Error(w, "server error", http.StatusInternalServerError)
			}
			return
		}
		if !IsValidName(name) {
			http.Error(w, "invalid value for \"name\"", http.StatusBadRequest)
			return
		}
		// require "challenge"
		challenge, err := values.GetString("challenge")
		if len(challenge) == 0 || err != nil {
			switch {
			case err == nil:
				http.Error(w, "must specify \"challenge\"", http.StatusBadRequest)
			case errors.Is(err, httputil.ErrAmbiguousValues):
				http.Error(w, "multiple values found for \"challenge\"", http.StatusBadRequest)
			case errors.Is(err, httputil.ErrValueUnexpectedType):
				http.Error(w, "\"challenge\" must be a string", http.StatusBadRequest)
			default:
				log.Printf("[error] myaddr.RegistrationHandler.ServeHTTP: get challenge: %v", err)
				http.Error(w, "server error", http.StatusInternalServerError)
			}
			return
		}
		// verify challenge with cloudflare
		if verified, err := h.TurnstileClient.Verify(challenge); err != nil {
			log.Printf("[error] myaddr.RegistrationHandler.ServeHTTP: verify challenge: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		} else if !verified {
			http.Error(w, "invalid value for \"challenge\"", http.StatusBadRequest)
			return
		}
		// check if name already exists
		name = dnsutil.LowerName(name) // all names stored in lowercase
		if ctime := h.DataStore.Get(h.KeyPrefix + name + ":ctime"); ctime != nil {
			http.Error(w, "name already exists", http.StatusConflict)
			return
		}
		// add registration
		keyBytes := make([]byte, 32)
		_, err = rand.Read(keyBytes)
		if err != nil {
			log.Printf("[error] myaddr.RegistrationHandler.ServeHTTP: generate key: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		key := fmt.Sprintf("%x", keyBytes)
		hash := fmt.Sprintf("%x", sha256.Sum256([]byte(key)))
		err = UpdateRegistration(hash, name, h.DataStore, h.KeyPrefix)
		if err != nil {
			log.Printf("[error] myaddr.RegistrationHandler.ServeHTTP: UpdateRegistration: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		// success
		w.Header().Set("myaddr-name", name)
		w.Header().Set("Content-Type", "application/json")
		created, updated, expires := GetRegistrationInfo(name, h.DataStore, h.KeyPrefix)
		json.NewEncoder(w).Encode(
			struct {
				Name       string `json:"name"`
				Key        string `json:"key"`
				Registered uint32 `json:"registered"`
				Updated    uint32 `json:"updated"`
				Expires    uint32 `json:"expires"`
			}{
				Name:       name,
				Key:        key,
				Registered: created,
				Updated:    updated,
				Expires:    expires,
			},
		)
	}
}

type UpdateHandler struct {
	DataStore      ttlstore.TtlStore
	ChallengeStore ttlstore.TtlStore
	KeyPrefix      string
}

func (h *UpdateHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
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
	// require "key"
	key, err := values.GetString("key")
	if len(key) == 0 || err != nil {
		switch {
		case err == nil:
			http.Error(w, "must specify \"key\"", http.StatusBadRequest)
		case errors.Is(err, httputil.ErrAmbiguousValues):
			http.Error(w, "multiple values found for \"key\"", http.StatusBadRequest)
		case errors.Is(err, httputil.ErrValueUnexpectedType):
			http.Error(w, "\"key\" must be a string", http.StatusBadRequest)
		default:
			log.Printf("[error] myaddr.UpdateHandler.ServeHTTP: get key: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
		}
		return
	}
	if len(key) != 64 {
		http.Error(w, "invalid value for \"key\"", http.StatusBadRequest)
		return
	}
	// get "ip"
	ipStr, err := values.GetString("ip")
	if err != nil {
		switch {
		case errors.Is(err, httputil.ErrAmbiguousValues):
			http.Error(w, "multiple values found for \"ip\"", http.StatusBadRequest)
		case errors.Is(err, httputil.ErrValueUnexpectedType):
			http.Error(w, "\"ip\" must be a string", http.StatusBadRequest)
		default:
			log.Printf("[error] myaddr.UpdateHandler.ServeHTTP: get ip: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
		}
		return
	}
	// parse "ip"
	var ip net.IP
	if len(ipStr) > 0 {
		if ipStr == "self" {
			ipStr = req.Header.Get("X-Real-IP")
		}
		ip = net.ParseIP(ipStr)
		if ip == nil {
			http.Error(w, "invalid value for \"ip\"", http.StatusBadRequest)
			return
		}
	}
	// get "acme_challenge"
	challenge, err := values.GetString("acme_challenge")
	if err != nil {
		switch {
		case errors.Is(err, httputil.ErrAmbiguousValues):
			http.Error(w, "multiple values found for \"acme_challenge\"", http.StatusBadRequest)
		case errors.Is(err, httputil.ErrValueUnexpectedType):
			http.Error(w, "\"acme_challenge\" must be a string", http.StatusBadRequest)
		default:
			log.Printf("[error] myaddr.UpdateHandler.ServeHTTP: get acme_challenge: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
		}
		return
	}
	// make sure "acme_challenge" is a valid challenge string
	if len(challenge) > 0 && !challenges.IsValidChallenge(challenge) {
		http.Error(w, "invalid value for \"acme_challenge\"", http.StatusBadRequest)
		return
	}
	// find name
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(key)))
	name := string(h.DataStore.Get(h.KeyPrefix + "hash:" + hash))
	if len(name) == 0 {
		http.Error(w, "registration not found", http.StatusNotFound)
		return
	}
	w.Header().Set("myaddr-name", name)
	switch req.Method {
	case http.MethodDelete:
		// prohibit "ip" and "acme_challenge"
		if ip != nil || len(challenge) > 0 {
			http.Error(w, "delete removes all ip addresses, do not specify \"ip\" or \"acme_challenge\"", http.StatusBadRequest)
			return
		}
		// delete
		h.DataStore.Delete(h.KeyPrefix + name + ":ip4")
		h.DataStore.Delete(h.KeyPrefix + name + ":ip4mtime")
		h.DataStore.Delete(h.KeyPrefix + name + ":ip6")
		h.DataStore.Delete(h.KeyPrefix + name + ":ip6mtime")
		w.WriteHeader(http.StatusNoContent)
	default:
		// require "ip" xor "acme_challenge"
		if (ip == nil && len(challenge) == 0) || (ip != nil && len(challenge) > 0) {
			http.Error(w, "must specify either \"ip\" or \"acme_challenge\"", http.StatusBadRequest)
			return
		}
		switch {
		case ip != nil:
			// set ip
			now := make([]byte, 4)
			binary.BigEndian.PutUint32(now, uint32(time.Now().Unix()))
			var ipKey, mtimeKey string
			if ip4 := ip.To4(); ip4 != nil {
				ip = ip4
				ipKey, mtimeKey = h.KeyPrefix+name+":ip4", h.KeyPrefix+name+":ip4mtime"
			} else {
				ipKey, mtimeKey = h.KeyPrefix+name+":ip6", h.KeyPrefix+name+":ip6mtime"
			}
			err = h.DataStore.Set(ipKey, ip, AddressTtl)
			if err == nil {
				err = h.DataStore.Set(mtimeKey, now, AddressTtl)
			}
			if err != nil {
				log.Printf("[error] myaddr.UpdateHandler.ServeHTTP: set ip: %v", err)
				http.Error(w, "server error", http.StatusInternalServerError)
				return
			}
		case len(challenge) > 0:
			// add challenge
			err = h.ChallengeStore.Add(h.KeyPrefix+name, []byte(challenge), ChallengeTtl)
			if err != nil {
				log.Printf("[error] myaddr.UpdateHandler.ServeHTTP: add challenge: %v", err)
				http.Error(w, "server error", http.StatusInternalServerError)
				return
			}
		}
		// update registration
		err = UpdateRegistration(hash, name, h.DataStore, h.KeyPrefix)
		if err != nil {
			log.Printf("[error] myaddr.UpdateHandler.ServeHTTP: UpdateRegistration: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "OK")
	}
}
