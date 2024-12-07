package ttlstore

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
)

type TtlStore interface {
	// appends val to any other values associated with key
	Add(key string, val []byte, ttl uint32) error
	// associates val with key, replacing any other values
	Set(key string, val []byte, ttl uint32) error
	// gets all keys starting with prefix
	List(prefix string) []string
	// gets the first key starting with prefix found associated with val
	Find(val []byte, prefix string) string
	// gets all keys starting with prefix found associated with val
	FindAll(val []byte, prefix string) []string
	// gets all non-expired values associated with key
	Values(key string) [][]byte
	// gets the first non-expired value associated with key
	Get(key string) []byte
	// unassociates val with key, leaving any other values
	Remove(key string, val []byte)
	// deletes all values associated with key
	Delete(key string)
}

type AdminHandler struct {
	Store     TtlStore
	KeyPrefix string
}

func (h *AdminHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		var data interface{}
		key := req.PathValue("key")
		if len(key) == 0 {
			var keys []string
			q := req.URL.Query()
			find := q.Get("find")
			prefix := h.KeyPrefix + q.Get("prefix")
			switch {
			case len(find) == 0:
				keys = h.Store.List(prefix)
			case strings.HasPrefix(find, "0x"):
				b, err := hex.DecodeString(find[2:])
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				keys = h.Store.FindAll(b, prefix)
			case strings.HasPrefix(find, "base64:"):
				b, err := base64.StdEncoding.DecodeString(find[7:])
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				keys = h.Store.FindAll(b, prefix)
			default:
				keys = h.Store.FindAll([]byte(find), prefix)
			}
			if keys == nil {
				keys = []string{}
			}
			if len(h.KeyPrefix) > 0 {
				for i, v := range keys {
					keys[i] = v[len(h.KeyPrefix):]
				}
			}
			slices.Sort(keys)
			data = keys
		} else {
			values := h.Store.Values(h.KeyPrefix + key)
			if values == nil {
				values = [][]byte{}
			}
			data = values
		}
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.Encode(data)
	case http.MethodDelete:
		key := req.PathValue("key")
		if len(key) == 0 {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		h.Store.Delete(h.KeyPrefix + key)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET, DELETE")
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
	}
}
