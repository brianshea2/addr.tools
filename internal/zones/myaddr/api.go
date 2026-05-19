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
	"strings"
	"time"

	"github.com/brianshea2/addr.tools/internal/dnsutil"
	"github.com/brianshea2/addr.tools/internal/httputil"
	"github.com/brianshea2/addr.tools/internal/ttlstore"
	"github.com/brianshea2/addr.tools/internal/zones/challenges"
	"github.com/brianshea2/addr.tools/internal/zones/dyn"
)

const (
	PendingTtl      = 3600
	RegistrationTtl = 120 * 86400
)

type RegistrationRecord struct {
	Created uint32
	Updated uint32
	Hash    string
}

func (r *RegistrationRecord) Expires() uint32 {
	if r.Created == r.Updated {
		return r.Updated + PendingTtl
	}
	return r.Updated + RegistrationTtl
}

func (r *RegistrationRecord) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 4+4+len(r.Hash))
	binary.BigEndian.PutUint32(data, r.Created)
	binary.BigEndian.PutUint32(data[4:], r.Updated)
	copy(data[8:], r.Hash)
	return
}

func (r *RegistrationRecord) UnmarshalBinary(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("invalid RegistrationRecord length (%d)", len(data))
	}
	r.Created = binary.BigEndian.Uint32(data)
	r.Updated = binary.BigEndian.Uint32(data[4:])
	r.Hash = string(data[8:])
	return nil
}

func LoadRegistration(name string, store ttlstore.TtlStore) (reg *RegistrationRecord, err error) {
	var data []byte
	data, err = store.Get(name + ":reg")
	if err == nil && data != nil {
		reg = new(RegistrationRecord)
		err = reg.UnmarshalBinary(data)
	}
	return
}

func UpdateRegistration(hash, name string, store ttlstore.TtlStore) error {
	now := uint32(time.Now().Unix())
	reg, err := LoadRegistration(name, store)
	if err != nil {
		return err
	}
	var ttl uint32
	if reg == nil {
		reg = new(RegistrationRecord)
		reg.Created = now
		ttl = PendingTtl
	} else {
		ttl = RegistrationTtl
	}
	reg.Updated = now
	reg.Hash = hash
	data, err := reg.MarshalBinary()
	if err != nil {
		return err
	}
	err = store.Set(name+":reg", data, ttl)
	if err == nil && len(hash) > 0 {
		err = store.Set("hash:"+hash, []byte(name), ttl)
	}
	return err
}

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

type AdminHandler struct {
	DataStore      ttlstore.TtlStore
	ChallengeStore ttlstore.TtlStore
}

func (h *AdminHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		name := req.URL.Query().Get("name")
		if len(name) > 0 {
			reg, err := LoadRegistration(name, h.DataStore)
			if err != nil {
				log.Printf("[error] myaddr.AdminHandler.ServeHTTP: LoadRegistration: %v", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(reg)
			return
		}
		keys, err := h.DataStore.List("")
		if err != nil {
			log.Printf("[error] myaddr.AdminHandler.ServeHTTP: List: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var names []string
		for _, key := range keys {
			if strings.HasSuffix(key, ":reg") {
				names = append(names, key[:len(key)-4])
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(names)
	case http.MethodDelete, "SUSPEND":
		name := req.URL.Query().Get("name")
		if len(name) == 0 {
			http.Error(w, "missing \"name\"", http.StatusBadRequest)
			return
		}
		reg, err := LoadRegistration(name, h.DataStore)
		if err != nil {
			log.Printf("[error] myaddr.AdminHandler.ServeHTTP: LoadRegistration: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if reg == nil {
			http.Error(w, "registration not found", http.StatusBadRequest)
			return
		}
		if len(reg.Hash) > 0 {
			err = h.DataStore.Delete("hash:" + reg.Hash)
		}
		if err == nil {
			err = h.DataStore.Delete(name + ":ip4")
		}
		if err == nil {
			err = h.DataStore.Delete(name + ":ip6")
		}
		if err == nil {
			err = h.ChallengeStore.Delete(name)
		}
		if err == nil {
			if req.Method == "SUSPEND" {
				err = UpdateRegistration("", name, h.DataStore)
			} else {
				err = h.DataStore.Delete(name + ":reg")
			}
		}
		if err != nil {
			log.Printf("[error] myaddr.AdminHandler.ServeHTTP: %v: %v", req.Method, err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET, DELETE, SUSPEND")
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
	}
}

type RegistrationHandler struct {
	DataStore       ttlstore.TtlStore
	ChallengeStore  ttlstore.TtlStore
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
		nameBytes, err := h.DataStore.Get("hash:" + hash)
		if err != nil {
			log.Printf("[error] myaddr.RegistrationHandler.ServeHTTP: find name: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		if nameBytes == nil {
			http.Error(w, "invalid value for \"key\"", http.StatusBadRequest)
			return
		}
		name := string(nameBytes)
		switch req.Method {
		case http.MethodGet:
			// get
			out := struct {
				Name       string `json:"name"`
				Registered uint32 `json:"registered"`
				Updated    uint32 `json:"updated"`
				Expires    uint32 `json:"expires"`
				IPv4       net.IP `json:"ip4,omitempty"`
				IPv6       net.IP `json:"ip6,omitempty"`
			}{
				Name: name,
			}
			reg, err := LoadRegistration(name, h.DataStore)
			if err != nil {
				log.Printf("[error] myaddr.RegistrationHandler.ServeHTTP: LoadRegistration: %v", err)
				http.Error(w, "server error", http.StatusInternalServerError)
				return
			}
			if reg != nil {
				out.Registered = reg.Created
				out.Updated = reg.Updated
				out.Expires = reg.Expires()
			}
			ip, err := dyn.LoadIPv4(name, h.DataStore)
			if err != nil {
				log.Printf("[error] myaddr.RegistrationHandler.ServeHTTP: LoadIPv4: %v", err)
				http.Error(w, "server error", http.StatusInternalServerError)
				return
			}
			if ip != nil {
				out.IPv4 = ip.IP
			}
			ip, err = dyn.LoadIPv6(name, h.DataStore)
			if err != nil {
				log.Printf("[error] myaddr.RegistrationHandler.ServeHTTP: LoadIPv6: %v", err)
				http.Error(w, "server error", http.StatusInternalServerError)
				return
			}
			if ip != nil {
				out.IPv6 = ip.IP
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(out)
		case http.MethodDelete:
			// delete
			err = h.DataStore.Delete(name + ":ip4")
			if err == nil {
				err = h.DataStore.Delete(name + ":ip6")
			}
			if err == nil {
				err = h.DataStore.Delete(name + ":reg")
			}
			if err == nil {
				err = h.DataStore.Delete("hash:" + hash)
			}
			if err == nil {
				err = h.ChallengeStore.Delete(name)
			}
			if err != nil {
				log.Printf("[error] myaddr.RegistrationHandler.ServeHTTP: Delete: %v", err)
				http.Error(w, "server error", http.StatusInternalServerError)
				return
			}
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
			log.Printf("[warn] myaddr.RegistrationHandler.ServeHTTP: invalid challenge from %s", req.Header.Get("X-Real-IP"))
			http.Error(w, "invalid value for \"challenge\"", http.StatusBadRequest)
			return
		}
		// check if name already exists
		name = dnsutil.ToLowerAscii(name) // all names stored in lowercase
		if exists, err := h.DataStore.Exists(name + ":reg"); err != nil {
			log.Printf("[error] myaddr.RegistrationHandler.ServeHTTP: name exists: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		} else if exists {
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
		err = UpdateRegistration(hash, name, h.DataStore)
		if err != nil {
			log.Printf("[error] myaddr.RegistrationHandler.ServeHTTP: UpdateRegistration: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		// success
		log.Printf("[info] myaddr.RegistrationHandler.ServeHTTP: new registration: %s (%s)", name, req.Header.Get("X-Real-IP"))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(
			struct {
				Name string `json:"name"`
				Key  string `json:"key"`
			}{
				Name: name,
				Key:  key,
			},
		)
	}
}

type UpdateHandler struct {
	DataStore      ttlstore.TtlStore
	ChallengeStore ttlstore.TtlStore
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
	nameBytes, err := h.DataStore.Get("hash:" + hash)
	if err != nil {
		log.Printf("[error] myaddr.UpdateHandler.ServeHTTP: find name: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	if nameBytes == nil {
		http.Error(w, "invalid value for \"key\"", http.StatusBadRequest)
		return
	}
	name := string(nameBytes)
	switch req.Method {
	case http.MethodDelete:
		// prohibit "ip" and "acme_challenge"
		if ip != nil || len(challenge) > 0 {
			http.Error(w, "delete removes all ip addresses, do not specify \"ip\" or \"acme_challenge\"", http.StatusBadRequest)
			return
		}
		// delete
		err = h.DataStore.Delete(name + ":ip4")
		if err == nil {
			err = h.DataStore.Delete(name + ":ip6")
		}
		if err != nil {
			log.Printf("[error] myaddr.UpdateHandler.ServeHTTP: Delete: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		// require "ip" xor "acme_challenge"
		if (ip == nil && len(challenge) == 0) || (ip != nil && len(challenge) > 0) {
			http.Error(w, "must specify either \"ip\" or \"acme_challenge\"", http.StatusBadRequest)
			return
		}
		switch {
		case ip != nil:
			// update ip
			err = dyn.UpdateIP(name, ip, h.DataStore)
			if err != nil {
				log.Printf("[error] myaddr.UpdateHandler.ServeHTTP: UpdateIP: %v", err)
				http.Error(w, "server error", http.StatusInternalServerError)
				return
			}
		case len(challenge) > 0:
			// add challenge
			err = h.ChallengeStore.Add(name, []byte(challenge), challenges.ChallengeTtl)
			if err != nil {
				log.Printf("[error] myaddr.UpdateHandler.ServeHTTP: add challenge: %v", err)
				http.Error(w, "server error", http.StatusInternalServerError)
				return
			}
		}
		// update registration
		err = UpdateRegistration(hash, name, h.DataStore)
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
