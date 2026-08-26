package httputil

import (
	"context"
	"net/http"
	"time"
)

const DefaultRequestTimeout = 15 * time.Second

// RequestContext returns a bounded context for downstream network work.
func RequestContext(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), DefaultRequestTimeout)
}
