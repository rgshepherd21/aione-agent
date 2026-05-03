// Tests for the rollback dispatch path (Sprint follow-up S2.b.2).
//
// SubmitRollback runs in a goroutine and ships the result through the
// Executor's ResultSink. These tests install a synchronizing sink so
// the goroutine's completion can be observed deterministically.

package executor

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shepherdtech/aione-agent/internal/config"
)

// fanOutSink lets the test wait until the executor goroutine has
// shipped its Result. The sink stashes the Result and signals via a
// channel so the test doesn't have to time.Sleep.
type fanOutSink struct {
	mu      sync.Mutex
	results []Result
	done    chan struct{}
}

func newFanOutSink() *fanOutSink {
	return &fanOutSink{done: make(chan struct{}, 16)}
}

func (s *fanOutSink) Sink(r Result) {
	s.mu.Lock()
	s.results = append(s.results, r)
	s.mu.Unlock()
	s.done <- struct{}{}
}

func (s *fanOutSink) waitFor(t *testing.T, n int, within time.Duration) []Result {
	t.Helper()
	deadline := time.After(within)
	for i := 0; i < n; i++ {
		select {
		case <-s.done:
		case <-deadline:
			t.Fatalf("waited %s for sink result %d/%d", within, i+1, n)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Result(nil), s.results...)
}

func TestSubmitRollback_StubProducesFailedResult(t *testing.T) {
	t.Parallel()

	e := New(
		config.ActionsConfig{
			MaxConcurrent: 1,
			Timeout:       time.Second,
		},
		nil,
	)

	sink := newFanOutSink()
	e.SetResultSink(sink.Sink)

	cmd := RollbackCommand{
		CommandID:    "rb-cmd-1",
		ExecutionID:  "exec-uuid-1",
		ActionIDSlug: "interface_shutdown_no_shutdown",
		TenantID:     "tenant-uuid",
		DeviceID:     "device-uuid",
		PreState:     map[string]interface{}{"line_protocol": "up"},
		PayloadHash:  strings.Repeat("a", 64),
		CapturedAt:   time.Date(2026, 5, 3, 1, 0, 0, 0, time.UTC),
	}

	if err := e.SubmitRollback(context.Background(), cmd); err != nil {
		t.Fatalf("SubmitRollback: %v", err)
	}

	results := sink.waitFor(t, 1, 2*time.Second)
	got := results[0]

	if got.CommandID != "rb-cmd-1" {
		t.Errorf("CommandID: got %q want %q", got.CommandID, "rb-cmd-1")
	}
	if got.ActionID != "interface_shutdown_no_shutdown" {
		t.Errorf("ActionID: got %q want %q", got.ActionID,
			"interface_shutdown_no_shutdown")
	}
	if got.Success {
		t.Errorf("expected Success=false (stub) — got true")
	}
	if got.TimedOut {
		t.Errorf("stub should not flag timed_out")
	}
	if got.Err == "" || !strings.Contains(got.Err, "not yet implemented") {
		t.Errorf("expected stub error message, got %q", got.Err)
	}
	if got.Err == "" || !strings.Contains(got.Err, "exec-uuid-1") {
		t.Errorf("error should reference parent execution_id, got %q", got.Err)
	}
}

func TestSubmitRollback_AtCapacityReturnsError(t *testing.T) {
	t.Parallel()

	e := New(
		config.ActionsConfig{
			MaxConcurrent: 1,
			Timeout:       time.Second,
		},
		nil,
	)

	// Block the only slot with a slow execute_kal so SubmitRollback
	// can't claim it. We don't have a clean way to block from inside
	// the executor without writing a fake action; instead, drain the
	// semaphore directly to mimic "all slots in use."
	<-e.sem

	defer func() { e.sem <- struct{}{} }()

	cmd := RollbackCommand{
		CommandID:    "rb-cmd-2",
		ExecutionID:  "exec-uuid-2",
		ActionIDSlug: "noop",
		TenantID:     "tenant-uuid",
		PreState:     map[string]interface{}{},
		PayloadHash:  strings.Repeat("b", 64),
		CapturedAt:   time.Now(),
	}

	if err := e.SubmitRollback(context.Background(), cmd); err == nil {
		t.Fatal("expected at-capacity error, got nil")
	}
}
