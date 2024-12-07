package ttlstore

import (
	"encoding/json"
	"net/http"
	"slices"
)

type TtlStore interface {
	// appends val to any other values associated with key
	Add(key string, val []byte, ttl uint32) error
	// associates val with key, replacing any other values
	Set(key string, val []byte, ttl uint32) error
	// gets all keys starting with prefix
	List(prefix string) []string
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
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		key := req.PathValue("key")
		if len(key) == 0 {
			keys := h.Store.List(h.KeyPrefix + req.URL.Query().Get("prefix"))
			if keys == nil {
				keys = []string{}
			}
			if len(h.KeyPrefix) > 0 {
				for i, v := range keys {
					keys[i] = v[len(h.KeyPrefix):]
				}
			}
			slices.Sort(keys)
			enc.Encode(keys)
		} else {
			values := h.Store.Values(h.KeyPrefix + key)
			if values == nil {
				values = [][]byte{}
			}
			enc.Encode(values)
		}
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
