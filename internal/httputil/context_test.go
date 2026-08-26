package httputil

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestRequestContext(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	ctx, cancel := RequestContext(r)
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok { t.Fatal("request context has no deadline") }
	if remaining := time.Until(deadline); remaining <= 0 || remaining > DefaultRequestTimeout { t.Fatalf("unexpected deadline window: %s", remaining) }
}
