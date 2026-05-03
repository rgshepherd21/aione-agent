package capture

import "context"

// capturesPath is the backend endpoint that ingests Capture values.
// Mirrors aione-backend/app/api/v1/agents.py::receive_state_capture.
const capturesPath = "/api/v1/agents/state-captures"

// HTTPPoster is the transport surface the Poster needs. Implemented by
// transport.Client.PostJSON; kept as an interface so tests can inject a
// recording fake without a real HTTPS client.
type HTTPPoster interface {
	PostJSON(ctx context.Context, path string, body, dst interface{}) error
}

// Sink is the narrow interface action executors use to ship a built
// Capture to the backend. ``*Poster`` satisfies it; tests inject
// recording fakes. Defined in this package so both
// ``internal/actions/executor`` (the flush_dns_cache bracket path)
// and ``internal/actions/dsl`` (the SSH-transport state-capture path)
// can refer to the same type without duplicating the interface.
type Sink interface {
	Post(ctx context.Context, c Capture) error
}

// Poster ships Capture values to the backend's state_captures endpoint.
// Thin shim so callers don't hard-code the path and future header or
// auth tweaks land in exactly one spot.
type Poster struct {
	client HTTPPoster
}

// NewPoster wraps an HTTP client as a Poster.
func NewPoster(client HTTPPoster) *Poster {
	return &Poster{client: client}
}

// Post sends one Capture. Errors from the HTTP client propagate unchanged
// so the caller can decide whether to log, retry, or drop. A 4xx from
// the backend (e.g. 409 on duplicate) bubbles up as an HTTP %d error
// string from transport.Client.PostJSON.
func (p *Poster) Post(ctx context.Context, c Capture) error {
	return p.client.PostJSON(ctx, capturesPath, c, nil)
}
