package dyn

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/brianshea2/addr.tools/internal/httputil"
	"github.com/brianshea2/addr.tools/internal/ttlstore"
)

const AddressTtl = 90 * 86400

type AddressRecord struct {
	Updated uint32
	IP      net.IP
}

func (r *AddressRecord) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 4+len(r.IP))
	binary.BigEndian.PutUint32(data, r.Updated)
	copy(data[4:], r.IP)
	return
}

func (r *AddressRecord) UnmarshalBinary(data []byte) error {
	if !(len(data) == 8 || len(data) == 20) {
		return fmt.Errorf("invalid AddressRecord length (%d)", len(data))
	}
	r.Updated = binary.BigEndian.Uint32(data)
	r.IP = make(net.IP, len(data)-4)
	copy(r.IP, data[4:])
	return nil
}

func LoadIPv4(name string, store ttlstore.TtlStore) (ip *AddressRecord, err error) {
	var data []byte
	data, err = store.Get(name + ":ip4")
	if err == nil && data != nil {
		ip = new(AddressRecord)
		err = ip.UnmarshalBinary(data)
	}
	return
}

func LoadIPv6(name string, store ttlstore.TtlStore) (ip *AddressRecord, err error) {
	var data []byte
	data, err = store.Get(name + ":ip6")
	if err == nil && data != nil {
		ip = new(AddressRecord)
		err = ip.UnmarshalBinary(data)
	}
	return
}

func UpdateIP(name string, ip net.IP, store ttlstore.TtlStore) error {
	var suffix string
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
		suffix = ":ip4"
	} else {
		suffix = ":ip6"
	}
	data, err := (&AddressRecord{
		Updated: uint32(time.Now().Unix()),
		IP:      ip,
	}).MarshalBinary()
	if err != nil {
		return err
	}
	return store.Set(name+suffix, data, AddressTtl)
}

type HTTPHandler struct {
	DataStore ttlstore.TtlStore
	Zone      string
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
			log.Printf("[error] dyn.HTTPHandler.ServeHTTP: get secret: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
		}
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
			log.Printf("[error] dyn.HTTPHandler.ServeHTTP: get ip: %v", err)
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
	// try to use the entire body as the "ip" value if not found
	// warning: could contain form values (i.e., "secret=...")
	if ip == nil && req.Method != http.MethodGet {
		bodyText, _ := values.BodyText()
		if bodyText == "self" {
			bodyText = req.Header.Get("X-Real-IP")
		}
		ip = net.ParseIP(bodyText)
	}
	// calculate domain
	domain := fmt.Sprintf("%x.%s", sha256.Sum224([]byte(secret)), h.Zone)
	switch req.Method {
	case http.MethodDelete:
		// prohibit "ip"
		if ip != nil {
			http.Error(w, "delete removes all addresses, do not specify \"ip\"", http.StatusBadRequest)
			return
		}
		// delete
		err = h.DataStore.Delete(domain + ":ip4")
		if err == nil {
			err = h.DataStore.Delete(domain + ":ip6")
		}
		if err != nil {
			log.Printf("[error] dyn.HTTPHandler.ServeHTTP: Delete: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		// write domain if "ip" not specified
		if ip == nil {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintln(w, domain)
			return
		}
		// update ip
		err = UpdateIP(domain, ip, h.DataStore)
		if err != nil {
			log.Printf("[error] dyn.HTTPHandler.ServeHTTP: UpdateIP: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "OK")
	}
}
