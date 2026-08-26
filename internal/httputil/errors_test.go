package httputil

import (
	"net/http/httptest"
	"testing"
)

func TestJSONError(t *testing.T) {
	w := httptest.NewRecorder()
	JSONError(w, 400, "invalid request")
	if w.Code != 400 { t.Fatalf("status = %d, want 400", w.Code) }
	if got := w.Header().Get("Content-Type"); got != "application/json; charset=utf-8" { t.Fatalf("content type = %q", got) }
}
