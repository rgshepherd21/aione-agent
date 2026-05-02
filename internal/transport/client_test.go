// Tests for the transport retry policy, with focus on the terminal-error
// allowlist that prevents the 30s "ghost timeout" we saw on 2026-05-01 when
// the credential issuer returned 503 device_credentials_unconfigured for
// the DevNet device. See client.go:peekErrorCode + terminalErrorResponseCodes.
package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// newTestClient builds a Client pointed at the given test server URL with
// retries enabled but a tight delay so the test stays fast. RetryMax=3
// matches the production default observed in agent journal logs.
func newTestClient(baseURL string) *Client {
	return &Client{
		cfg: ClientConfig{
			BaseURL:    baseURL,
			Timeout:    2 * time.Second,
			RetryMax:   3,
			RetryDelay: 1 * time.Millisecond, // fast enough for tests
		},
		http: &http.Client{Timeout: 2 * time.Second},
	}
}

// TestDo_TerminalErrorCodeShortCircuitsRetry verifies that when the server
// returns 503 with a terminal error code in the JSON body, the client
// returns immediately on the first response instead of burning all retries.
//
// This is the exact failure mode from the 2026-05-01 logs: the API
// returned 503 device_credentials_unconfigured in ~250ms, but the agent
// retried three times across a 30s window before giving up.
func TestDo_TerminalErrorCodeShortCircuitsRetry(t *testing.T) {
	var calls int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"detail": map[string]string{
				"code":    "device_credentials_unconfigured",
				"message": "Device has no credential_ref configured",
			},
			"correlation_id": "test-corr-id",
		})
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	resp, err := c.Do(context.Background(), http.MethodPost, "/api/v1/credentials/issue", map[string]string{"x": "y"})
	if err != nil {
		t.Fatalf("Do returned error: %v", err)
	}
	defer resp.Body.Close()

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected 1 server call (no retries), got %d", got)
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 surfaced to caller, got %d", resp.StatusCode)
	}

	// Body must be re-readable — peekErrorCode rewinds the body, and
	// PostJSON / the test reads it for the error message.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body after Do: %v", err)
	}
	if !strings.Contains(string(body), "device_credentials_unconfigured") {
		t.Fatalf("body should still contain the terminal code; got %q", body)
	}
}

// TestDo_NonTerminal5xxStillRetries verifies that 5xx responses without a
// terminal code (or with no JSON body at all) still go through the full
// retry policy. This is the historical behavior — we don't want to mask
// real backend flaps just because we're parsing the body now.
func TestDo_NonTerminal5xxStillRetries(t *testing.T) {
	var calls int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		// vault_fetch_error is intentionally NOT in terminalErrorResponseCodes
		// (could be a transient vault flap), so retries should continue.
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"detail": map[string]string{
				"code":    "vault_fetch_error",
				"message": "Vault fetch failed",
			},
		})
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	resp, err := c.Do(context.Background(), http.MethodPost, "/anywhere", nil)
	if err != nil {
		t.Fatalf("Do returned error: %v", err)
	}
	defer resp.Body.Close()

	if got := atomic.LoadInt32(&calls); got != int32(c.cfg.RetryMax+1) {
		t.Fatalf("expected %d server calls (full retry budget), got %d", c.cfg.RetryMax+1, got)
	}
}

// TestDo_PlainText5xxStillRetries verifies that a 5xx response with a
// non-JSON body (e.g. an upstream proxy 502 page) doesn't accidentally
// match the terminal-error allowlist via parser misbehavior.
func TestDo_PlainText5xxStillRetries(t *testing.T) {
	var calls int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprintln(w, "<html><body>502 Bad Gateway</body></html>")
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	resp, err := c.Do(context.Background(), http.MethodPost, "/anywhere", nil)
	if err != nil {
		t.Fatalf("Do returned error: %v", err)
	}
	defer resp.Body.Close()

	if got := atomic.LoadInt32(&calls); got != int32(c.cfg.RetryMax+1) {
		t.Fatalf("non-JSON 5xx should retry %d times, got %d calls", c.cfg.RetryMax+1, got)
	}
}

// TestDo_4xxStillReturnsImmediately is a regression guard for the
// existing pre-Phase-1 behavior — 4xx responses must still bypass retry
// (they were never affected by terminal-code parsing, but it's worth
// pinning this so a future refactor doesn't accidentally break it).
func TestDo_4xxStillReturnsImmediately(t *testing.T) {
	var calls int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"detail": "nope"})
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	resp, err := c.Do(context.Background(), http.MethodGet, "/missing", nil)
	if err != nil {
		t.Fatalf("Do returned error: %v", err)
	}
	defer resp.Body.Close()

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected 1 call (4xx is terminal), got %d", got)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

// TestPostJSON_TerminalErrorMessageSurfaces verifies that the body we
// rewound in peekErrorCode is fully readable downstream. PostJSON's
// >=400 branch reads up to 4KB of body for the error text, so the
// terminal-error message should appear in the returned error string.
func TestPostJSON_TerminalErrorMessageSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"detail": map[string]string{
				"code":    "device_credentials_unconfigured",
				"message": "Device has no credential_ref configured",
			},
		})
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	var dst map[string]interface{}
	err := c.PostJSON(context.Background(), "/api/v1/credentials/issue", map[string]string{}, &dst)
	if err == nil {
		t.Fatalf("expected an error from PostJSON for 503 response")
	}
	if !strings.Contains(err.Error(), "device_credentials_unconfigured") {
		t.Fatalf("error should include the terminal code; got %v", err)
	}
}
