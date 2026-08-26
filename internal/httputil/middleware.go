package httputil

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
)

// RequestID adds a short request identifier for diagnostics. The identifier is
// safe to return to clients and does not contain request data.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" || len(id) > 128 || strings.ContainsAny(id, "\r\n") {
			var raw [12]byte
			if _, err := rand.Read(raw[:]); err == nil {
				id = hex.EncodeToString(raw[:])
			} else {
				id = "generated"
			}
		}
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r)
	})
}

// MaxBody limits request bodies before they reach a handler. It is intended
// for endpoints that accept bodies; GET-only handlers do not need it.
func MaxBody(next http.Handler, limit int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if limit > 0 && r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, limit)
		}
		next.ServeHTTP(w, r)
	})
}

// Methods restricts a handler to the supplied HTTP methods and advertises the
// allowed methods without changing the response body of valid requests.
func Methods(next http.Handler, allowed ...string) http.Handler {
	set := make(map[string]struct{}, len(allowed))
	for _, method := range allowed { set[strings.ToUpper(method)] = struct{}{} }
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := set[r.Method]; !ok {
			if len(allowed) > 0 { w.Header().Set("Allow", strings.Join(allowed, ", ")) }
			JSONError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// HealthHandler provides a dependency-free liveness response.
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}` + "\n"))
}

// ReadyHandler provides a simple readiness response. Dependency checks can be
// layered around it by deployments that require them.
func ReadyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ready"}` + "\n"))
}
