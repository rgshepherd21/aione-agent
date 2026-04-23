package executor

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/shepherdtech/aione-agent/internal/actions/validation"
	"github.com/shepherdtech/aione-agent/internal/capture"
	"github.com/shepherdtech/aione-agent/internal/config"
)

// recordingPoster is a CapturePoster that remembers every Post call.
// Concurrent-safe so the execute goroutine can post without racing
// test assertions.
type recordingPoster struct {
	mu       sync.Mutex
	captures []capture.Capture
}

func (r *recordingPoster) Post(_ context.Context, c capture.Capture) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.captures = append(r.captures, c)
	return nil
}

func (r *recordingPoster) snapshot() []capture.Capture {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]capture.Capture, len(r.captures))
	copy(out, r.captures)
	return out
}

// TestSetCaptureContextStoresFields pins that SetCaptureContext round-
// trips the identity triple. Without this a typo in the setter would go
// undetected until captureDNSState silently no-op'd in production.
func TestSetCaptureContextStoresFields(t *testing.T) {
	t.Parallel()
	e := New(config.ActionsConfig{
		MaxConcurrent: 1,
		Timeout:       time.Second,
	}, nil)

	poster := &recordingPoster{}
	e.SetCaptureContext("agent-1", "tenant-1", poster)

	gotAgent, gotTenant, gotPoster := e.captureContextSnapshot()
	if gotAgent != "agent-1" {
		t.Fatalf("agentID: want %q, got %q", "agent-1", gotAgent)
	}
	if gotTenant != "tenant-1" {
		t.Fatalf("tenantID: want %q, got %q", "tenant-1", gotTenant)
	}
	if gotPoster == nil {
		t.Fatal("capturePoster was not stored")
	}
}

// TestCaptureDNSStateNoOpWhenPosterNil pins that the bracket helper
// silently does nothing when capture wiring hasn't been installed.
// Action-execution must not depend on capture being enabled.
func TestCaptureDNSStateNoOpWhenPosterNil(t *testing.T) {
	t.Parallel()
	e := New(config.ActionsConfig{
		MaxConcurrent: 1,
		Timeout:       time.Second,
	}, nil)
	// Should not panic and should return cleanly.
	e.captureDNSState(context.Background(), "exec-id", capture.CaptureTypePre)
}

// TestCaptureDNSStatePostsWithIdentity pins that one call to
// captureDNSState posts exactly one Capture and the identity fields
// are threaded correctly onto the wire value.
func TestCaptureDNSStatePostsWithIdentity(t *testing.T) {
	t.Parallel()
	e := New(config.ActionsConfig{
		MaxConcurrent: 1,
		Timeout:       2 * time.Second,
	}, nil)

	poster := &recordingPoster{}
	e.SetCaptureContext("agent-xyz", "tenant-xyz", poster)

	e.captureDNSState(context.Background(), "exec-99", capture.CaptureTypePre)

	got := poster.snapshot()
	if len(got) != 1 {
		t.Fatalf("want 1 capture, got %d", len(got))
	}
	if got[0].CaptureType != "pre" {
		t.Errorf("CaptureType: want pre, got %s", got[0].CaptureType)
	}
	if got[0].ActionExecutionID != "exec-99" {
		t.Errorf("ActionExecutionID: want exec-99, got %s", got[0].ActionExecutionID)
	}
	if got[0].AgentID != "agent-xyz" || got[0].TenantID != "tenant-xyz" {
		t.Errorf("identity not threaded: agent=%s tenant=%s",
			got[0].AgentID, got[0].TenantID)
	}
	if got[0].CaptureMethod != capture.CaptureMethodShell {
		t.Errorf("CaptureMethod: want %s, got %s",
			capture.CaptureMethodShell, got[0].CaptureMethod)
	}
}

// TestDispatchFlushDNSCacheWrapsWithBrackets is the integration-ish
// test: it calls the private dispatch(...) method with a flush_dns_cache
// Action and asserts that exactly one pre and one post Capture landed
// at the poster, in that order. Exercises the whole E3 wiring -- any
// regression in the dispatch switch's ordering or capture-call count
// fails loud here.
//
// goos is forced to "nosuchos" so flushDNSCache hits ErrUnsupportedOS
// and returns instantly without shelling out -- we only care that the
// bracket still fires pre + post regardless of the action outcome.
func TestDispatchFlushDNSCacheWrapsWithBrackets(t *testing.T) {
	// Not t.Parallel() -- mutates the package-level goos var.
	origGOOS := goos
	defer func() { goos = origGOOS }()
	goos = "nosuchos"

	e := New(config.ActionsConfig{
		MaxConcurrent: 1,
		Timeout:       time.Second,
	}, nil)

	poster := &recordingPoster{}
	e.SetCaptureContext("agent-1", "tenant-1", poster)

	// dispatch now threads action.CommandID (the per-dispatch correlation
	// id) -- not action.ID (the KAL action slug) -- into captureDNSState,
	// because the backend's state-captures endpoint validates
	// action_execution_id as a UUID and rejects slugs. So the test sets
	// CommandID to the value we expect to land on the wire, and ID to the
	// action slug the dispatch switch actually keys off.
	_, _ = e.dispatch(context.Background(), validation.Action{
		ID:        "flush_dns_cache",
		CommandID: "exec-42",
		Type:      "flush_dns_cache",
	})

	got := poster.snapshot()
	if len(got) != 2 {
		t.Fatalf("want 2 captures (pre + post), got %d", len(got))
	}
	if got[0].CaptureType != "pre" {
		t.Errorf("first capture: want pre, got %s", got[0].CaptureType)
	}
	if got[1].CaptureType != "post" {
		t.Errorf("second capture: want post, got %s", got[1].CaptureType)
	}
	if got[0].ActionExecutionID != "exec-42" || got[1].ActionExecutionID != "exec-42" {
		t.Errorf("ActionExecutionID not threaded: pre=%s post=%s",
			got[0].ActionExecutionID, got[1].ActionExecutionID)
	}
}
