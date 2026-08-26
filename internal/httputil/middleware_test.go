package httputil

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequestID(t *testing.T) {
	h := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Header().Get("X-Request-ID") == "" { t.Fatal("request ID was not added") }
}

func TestMethods(t *testing.T) {
	h := Methods(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }), http.MethodGet)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/", nil))
	if w.Code != http.StatusMethodNotAllowed { t.Fatalf("status = %d", w.Code) }
	if w.Header().Get("Allow") != http.MethodGet { t.Fatalf("allow = %q", w.Header().Get("Allow")) }
}

func TestMaxBody(t *testing.T) {
	h := MaxBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}), 4)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/", strings.NewReader("12345")))
	if w.Code != http.StatusNoContent { t.Fatalf("status = %d", w.Code) }
}

func TestHealthAndReady(t *testing.T) {
	for _, handler := range []http.HandlerFunc{HealthHandler, ReadyHandler} {
		w := httptest.NewRecorder()
		handler(w, httptest.NewRequest(http.MethodGet, "/", nil))
		if w.Code != http.StatusOK { t.Fatalf("status = %d", w.Code) }
		if !strings.Contains(w.Body.String(), "status") { t.Fatalf("body = %q", w.Body.String()) }
	}
}
