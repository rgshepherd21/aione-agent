// Unit tests for the dispatcher. Uses fake Submitter + Poster to
// avoid spinning up a real executor / HTTPS client.

package dispatcher

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shepherdtech/aione-agent/internal/actions/executor"
	"github.com/shepherdtech/aione-agent/internal/actions/validation"
)

// --- fakes ---------------------------------------------------------

type fakeSubmitter struct {
	mu               sync.Mutex
	submits          []validation.Action
	submitFn         func(validation.Action) error // optional override
	rollbackSubmits  []executor.RollbackCommand
	rollbackSubmitFn func(executor.RollbackCommand) error // optional override
}

func (f *fakeSubmitter) Submit(_ context.Context, a validation.Action) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.submits = append(f.submits, a)
	if f.submitFn != nil {
		return f.submitFn(a)
	}
	return nil
}

func (f *fakeSubmitter) SubmitRollback(_ context.Context, c executor.RollbackCommand) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rollbackSubmits = append(f.rollbackSubmits, c)
	if f.rollbackSubmitFn != nil {
		return f.rollbackSubmitFn(c)
	}
	return nil
}

func (f *fakeSubmitter) lastSubmitted() (validation.Action, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.submits) == 0 {
		return validation.Action{}, false
	}
	return f.submits[len(f.submits)-1], true
}

func (f *fakeSubmitter) lastRollbackSubmitted() (executor.RollbackCommand, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.rollbackSubmits) == 0 {
		return executor.RollbackCommand{}, false
	}
	return f.rollbackSubmits[len(f.rollbackSubmits)-1], true
}

type fakePoster struct {
	mu    sync.Mutex
	posts []postedCall
	err   error
}

type postedCall struct {
	path string
	body CommandResult
}

func (f *fakePoster) PostJSON(_ context.Context, path string, body, _ interface{}) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	res, ok := body.(CommandResult)
	if !ok {
		return fmt.Errorf("fakePoster: expected CommandResult, got %T", body)
	}
	f.posts = append(f.posts, postedCall{path: path, body: res})
	return f.err
}

func (f *fakePoster) snapshot() []postedCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]postedCall, len(f.posts))
	copy(out, f.posts)
	return out
}

// --- helpers -------------------------------------------------------

const testAgentID = "11111111-2222-3333-4444-555555555555"

func newTestDispatcher(t *testing.T, sub Submitter, post Poster) *Dispatcher {
	t.Helper()
	d := New(context.Background(), sub, post, testAgentID)
	d.now = func() time.Time { return time.Date(2026, 4, 21, 12, 0, 0, 0, time.UTC) }
	return d
}

func executeKAL(commandID, actionID string, params map[string]interface{}) PendingCommand {
	return PendingCommand{
		CommandID:   commandID,
		CommandType: CommandTypeExecuteKAL,
		Payload: map[string]interface{}{
			"id":              actionID,
			"type":            actionID,
			"timeout_seconds": float64(60),
			"params":          params,
			"sig":             "deadbeef",
		},
		Priority: 5,
	}
}

// --- tests ---------------------------------------------------------

func TestDeliver_HappyPath(t *testing.T) {
	sub := &fakeSubmitter{}
	post := &fakePoster{}
	d := newTestDispatcher(t, sub, post)

	cmd := executeKAL("cmd-1", "restart_service", map[string]interface{}{
		"service": "aione-agent",
	})

	acks := d.Deliver([]PendingCommand{cmd})

	if len(acks) != 1 || acks[0] != "cmd-1" {
		t.Fatalf("expected acks=[cmd-1], got %v", acks)
	}

	got, ok := sub.lastSubmitted()
	if !ok {
		t.Fatalf("executor Submit was never called")
	}
	if got.ID != "restart_service" || got.Type != "restart_service" {
		t.Errorf("translated action id/type wrong: %+v", got)
	}
	if got.Timeout != 60 {
		t.Errorf("translated timeout = %d, want 60", got.Timeout)
	}
	if got.Params["service"] != "aione-agent" {
		t.Errorf("params not translated: %+v", got.Params)
	}
	if got.Sig != "deadbeef" {
		t.Errorf("sig not carried through: %q", got.Sig)
	}
}

// rollbackCommand builds a CommandTypeRollback PendingCommand
// with the wire shape rollback_service.build_rollback_command emits.
// Sprint follow-up S2.b.2.
func rollbackCommand(commandID, executionID, actionSlug string) PendingCommand {
	return PendingCommand{
		CommandID:   commandID,
		CommandType: CommandTypeRollback,
		Payload: map[string]interface{}{
			"execution_id":   executionID,
			"action_id_slug": actionSlug,
			"tenant_id":      "00000000-0000-0000-0000-cccccccccccc",
			"device_id":      "00000000-0000-0000-0000-dddddddddddd",
			"pre_state":      map[string]interface{}{"line_protocol": "up"},
			"payload_hash":   "0000000000000000000000000000000000000000000000000000000000000000",
			"captured_at":    "2026-05-03T01:00:00Z",
		},
		Priority: 10,
	}
}

func TestDeliver_RollbackRoutesToSubmitRollback(t *testing.T) {
	sub := &fakeSubmitter{}
	post := &fakePoster{}
	d := newTestDispatcher(t, sub, post)

	cmd := rollbackCommand("rb-cmd-1", "exec-uuid-1", "interface_shutdown_no_shutdown")

	acks := d.Deliver([]PendingCommand{cmd})

	if len(acks) != 1 || acks[0] != "rb-cmd-1" {
		t.Fatalf("expected acks=[rb-cmd-1], got %v", acks)
	}
	if len(sub.submits) != 0 {
		t.Errorf("rollback should NOT have hit Submit, got %d execute_kal submits", len(sub.submits))
	}
	got, ok := sub.lastRollbackSubmitted()
	if !ok {
		t.Fatalf("SubmitRollback was never called")
	}
	if got.CommandID != "rb-cmd-1" {
		t.Errorf("CommandID: got %q want rb-cmd-1", got.CommandID)
	}
	if got.ExecutionID != "exec-uuid-1" {
		t.Errorf("ExecutionID: got %q want exec-uuid-1", got.ExecutionID)
	}
	if got.ActionIDSlug != "interface_shutdown_no_shutdown" {
		t.Errorf("ActionIDSlug: got %q", got.ActionIDSlug)
	}
	if got.PreState["line_protocol"] != "up" {
		t.Errorf("PreState not carried through: %+v", got.PreState)
	}
}

func TestDeliver_RollbackMissingFieldFailsCleanly(t *testing.T) {
	sub := &fakeSubmitter{}
	post := &fakePoster{}
	d := newTestDispatcher(t, sub, post)

	// Malformed payload — execution_id missing.
	cmd := PendingCommand{
		CommandID:   "rb-bad-1",
		CommandType: CommandTypeRollback,
		Payload: map[string]interface{}{
			"action_id_slug": "x",
			"tenant_id":      "y",
			"pre_state":      map[string]interface{}{},
			"payload_hash":   strings.Repeat("0", 64),
			"captured_at":    "2026-05-03T01:00:00Z",
		},
		Priority: 10,
	}

	acks := d.Deliver([]PendingCommand{cmd})

	if len(acks) != 1 || acks[0] != "rb-bad-1" {
		t.Fatalf("expected acks=[rb-bad-1], got %v", acks)
	}
	if len(sub.rollbackSubmits) != 0 {
		t.Errorf("malformed rollback should not have hit SubmitRollback")
	}
	posts := post.snapshot()
	if len(posts) != 1 {
		t.Fatalf("expected 1 failure result POST, got %d", len(posts))
	}
	if posts[0].body.Status != StatusFailed {
		t.Errorf("expected failed status, got %q", posts[0].body.Status)
	}
}

func TestDeliver_UnsupportedCommandType_AcksAndReportsFailed(t *testing.T) {
	sub := &fakeSubmitter{}
	post := &fakePoster{}
	d := newTestDispatcher(t, sub, post)

	cmd := PendingCommand{
		CommandID:   "cmd-refresh",
		CommandType: "refresh_config",
		Payload:     map[string]interface{}{},
	}

	acks := d.Deliver([]PendingCommand{cmd})

	if len(acks) != 1 || acks[0] != "cmd-refresh" {
		t.Fatalf("expected acks=[cmd-refresh], got %v", acks)
	}
	if len(sub.submits) != 0 {
		t.Errorf("executor should NOT have been called for unsupported type, got %d submits", len(sub.submits))
	}

	posts := post.snapshot()
	if len(posts) != 1 {
		t.Fatalf("expected 1 result POST, got %d", len(posts))
	}
	if posts[0].path != commandResultsPath {
		t.Errorf("wrong result path %q", posts[0].path)
	}
	if posts[0].body.Status != StatusFailed {
		t.Errorf("expected failed status, got %q", posts[0].body.Status)
	}
	if posts[0].body.Error == nil || !strings.Contains(*posts[0].body.Error, "unsupported command_type") {
		t.Errorf("expected error mentioning unsupported command_type, got %+v", posts[0].body.Error)
	}
	if posts[0].body.AgentID != testAgentID {
		t.Errorf("agent_id not carried: %q", posts[0].body.AgentID)
	}
}

func TestDeliver_Dedup_SecondSubmissionNotForwarded(t *testing.T) {
	sub := &fakeSubmitter{}
	post := &fakePoster{}
	d := newTestDispatcher(t, sub, post)

	cmd := executeKAL("cmd-dup", "run_command", map[string]interface{}{
		"command": "echo hi",
	})

	_ = d.Deliver([]PendingCommand{cmd})
	if len(sub.submits) != 1 {
		t.Fatalf("first Deliver should have submitted once, got %d", len(sub.submits))
	}

	acks := d.Deliver([]PendingCommand{cmd})
	if len(acks) != 1 || acks[0] != "cmd-dup" {
		t.Errorf("dedup path should still ack: got %v", acks)
	}
	if len(sub.submits) != 1 {
		t.Errorf("second Deliver should NOT resubmit; got %d total submits", len(sub.submits))
	}
}

func TestDeliver_CapacityError_NotAcked(t *testing.T) {
	sub := &fakeSubmitter{
		submitFn: func(validation.Action) error {
			return errors.New("executor at capacity (4 concurrent actions)")
		},
	}
	post := &fakePoster{}
	d := newTestDispatcher(t, sub, post)

	cmd := executeKAL("cmd-cap", "run_command", map[string]interface{}{
		"command": "echo hi",
	})

	acks := d.Deliver([]PendingCommand{cmd})
	if len(acks) != 0 {
		t.Errorf("capacity failures should NOT be acked; got %v", acks)
	}
	if len(post.snapshot()) != 0 {
		t.Errorf("capacity failure should not POST a result; got %d posts", len(post.snapshot()))
	}
}

func TestDeliver_ValidatorRejection_AckedAndReportedFailed(t *testing.T) {
	sub := &fakeSubmitter{
		submitFn: func(validation.Action) error {
			return errors.New("action validation: action signature verification failed")
		},
	}
	post := &fakePoster{}
	d := newTestDispatcher(t, sub, post)

	cmd := executeKAL("cmd-badsig", "run_command", map[string]interface{}{
		"command": "echo hi",
	})

	acks := d.Deliver([]PendingCommand{cmd})
	if len(acks) != 1 || acks[0] != "cmd-badsig" {
		t.Fatalf("validator rejection should still be acked so BE dequeues: %v", acks)
	}
	posts := post.snapshot()
	if len(posts) != 1 {
		t.Fatalf("expected 1 failure report, got %d", len(posts))
	}
	if posts[0].body.Status != StatusFailed {
		t.Errorf("expected failed status, got %q", posts[0].body.Status)
	}
}

func TestDeliver_Expired_AckedAndReportedFailed(t *testing.T) {
	sub := &fakeSubmitter{}
	post := &fakePoster{}
	d := newTestDispatcher(t, sub, post)
	// dispatcher clock is fixed at 2026-04-21 12:00:00 UTC (see
	// newTestDispatcher). Set expiry 5 minutes before that.
	expired := time.Date(2026, 4, 21, 11, 55, 0, 0, time.UTC)

	cmd := executeKAL("cmd-stale", "run_command", map[string]interface{}{
		"command": "echo hi",
	})
	cmd.ExpiresAt = &expired

	acks := d.Deliver([]PendingCommand{cmd})
	if len(acks) != 1 {
		t.Fatalf("expired commands should be acked, got %v", acks)
	}
	if len(sub.submits) != 0 {
		t.Errorf("expired commands must NOT be submitted to executor")
	}
	posts := post.snapshot()
	if len(posts) != 1 || posts[0].body.Status != StatusFailed {
		t.Errorf("expected 1 failed result post, got %+v", posts)
	}
	if posts[0].body.Error == nil || !strings.Contains(*posts[0].body.Error, "expired") {
		t.Errorf("expected error mentioning expired, got %+v", posts[0].body.Error)
	}
}

func TestDeliver_NonStringParam_Rejected(t *testing.T) {
	sub := &fakeSubmitter{}
	post := &fakePoster{}
	d := newTestDispatcher(t, sub, post)

	cmd := PendingCommand{
		CommandID:   "cmd-badparam",
		CommandType: CommandTypeExecuteKAL,
		Payload: map[string]interface{}{
			"id":              "run_command",
			"type":            "run_command",
			"timeout_seconds": float64(60),
			"params": map[string]interface{}{
				"retries": 3, // not a string — backend should have stringified
			},
			"sig": "deadbeef",
		},
	}

	acks := d.Deliver([]PendingCommand{cmd})
	if len(acks) != 1 {
		t.Errorf("bad params should still be acked: %v", acks)
	}
	if len(sub.submits) != 0 {
		t.Errorf("bad params should short-circuit before executor Submit")
	}
	posts := post.snapshot()
	if len(posts) != 1 || posts[0].body.Status != StatusFailed {
		t.Errorf("expected 1 failed result post, got %+v", posts)
	}
}

func TestPostResult_SuccessfulExecution(t *testing.T) {
	sub := &fakeSubmitter{}
	post := &fakePoster{}
	d := newTestDispatcher(t, sub, post)

	// Simulate having previously dispatched cmd-1 (so dedup seen-set
	// is populated and we can verify forget() clears it).
	d.markSeen("cmd-1")

	start := time.Date(2026, 4, 21, 12, 0, 0, 0, time.UTC)
	end := start.Add(250 * time.Millisecond)
	r := executor.Result{
		ActionID:  "cmd-1",
		Success:   true,
		Output:    "hi",
		StartedAt: start,
		EndedAt:   end,
	}

	d.PostResult(r)

	posts := post.snapshot()
	if len(posts) != 1 {
		t.Fatalf("expected 1 post, got %d", len(posts))
	}
	got := posts[0].body
	if got.CommandID != "cmd-1" {
		t.Errorf("command_id not carried: %q", got.CommandID)
	}
	if got.AgentID != testAgentID {
		t.Errorf("agent_id wrong: %q", got.AgentID)
	}
	if got.Status != StatusSucceeded {
		t.Errorf("expected succeeded, got %q", got.Status)
	}
	if got.Output == nil || *got.Output != "hi" {
		t.Errorf("output not carried: %+v", got.Output)
	}
	if got.DurationMs == nil || *got.DurationMs != 250 {
		t.Errorf("duration_ms = %+v, want 250", got.DurationMs)
	}
	if !got.CompletedAt.Equal(end) {
		t.Errorf("completed_at wrong: %v vs %v", got.CompletedAt, end)
	}
	if d.alreadySeen("cmd-1") {
		t.Errorf("dedup entry should be cleared after PostResult")
	}
}

func TestPostResult_TimedOut(t *testing.T) {
	sub := &fakeSubmitter{}
	post := &fakePoster{}
	d := newTestDispatcher(t, sub, post)

	r := executor.Result{
		ActionID:  "cmd-slow",
		Success:   false,
		TimedOut:  true,
		Err:       "command exited: signal: killed",
		StartedAt: time.Now(),
		EndedAt:   time.Now().Add(10 * time.Second),
	}
	d.PostResult(r)

	posts := post.snapshot()
	if len(posts) != 1 {
		t.Fatalf("expected 1 post, got %d", len(posts))
	}
	if posts[0].body.Status != StatusTimedOut {
		t.Errorf("expected timed_out, got %q", posts[0].body.Status)
	}
}

func TestPostResult_GenericFailure(t *testing.T) {
	sub := &fakeSubmitter{}
	post := &fakePoster{}
	d := newTestDispatcher(t, sub, post)

	r := executor.Result{
		ActionID:  "cmd-failed",
		Success:   false,
		Err:       "exit status 1",
		StartedAt: time.Now(),
		EndedAt:   time.Now().Add(200 * time.Millisecond),
	}
	d.PostResult(r)

	posts := post.snapshot()
	if len(posts) != 1 {
		t.Fatalf("expected 1 post, got %d", len(posts))
	}
	if posts[0].body.Status != StatusFailed {
		t.Errorf("expected failed, got %q", posts[0].body.Status)
	}
	if posts[0].body.Error == nil || *posts[0].body.Error != "exit status 1" {
		t.Errorf("error not carried: %+v", posts[0].body.Error)
	}
}
