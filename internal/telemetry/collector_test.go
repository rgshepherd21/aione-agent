// Tests for telemetry.Send and the Manager orchestration (Sprint D / D5.2).
//
// Send is small but the wire contract is critical — the backend's
// /v1/agents/telemetry endpoint expects a JSON array of Event records
// at a specific path. These tests stand up a real httptest server,
// point a transport.Client at it, and verify the request shape.

package telemetry

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shepherdtech/aione-agent/internal/transport"
)

// ─── Send wire-format tests ────────────────────────────────────────────────

func TestSend_PostsToCorrectPath(t *testing.T) {
	var seenPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := newTestClient(t, srv.URL)
	events := []Event{newTestEvent("agent-1", "syslog", "192.168.1.10")}
	if err := Send(context.Background(), client, events); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if seenPath != "/v1/agents/telemetry" {
		t.Errorf("path: got %q, want /v1/agents/telemetry", seenPath)
	}
}

func TestSend_SerializesEventArray(t *testing.T) {
	var seenBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := newTestClient(t, srv.URL)
	events := []Event{
		newTestEvent("agent-x", "syslog", "10.0.0.1"),
		newTestEvent("agent-x", "snmp", "10.0.0.2"),
	}
	if err := Send(context.Background(), client, events); err != nil {
		t.Fatalf("Send: %v", err)
	}

	var decoded []Event
	if err := json.Unmarshal(seenBody, &decoded); err != nil {
		t.Fatalf("body not a JSON array: %v\nbody=%s", err, seenBody)
	}
	if len(decoded) != 2 {
		t.Fatalf("expected 2 events, got %d", len(decoded))
	}
	if decoded[0].Type != "syslog" || decoded[1].Type != "snmp" {
		t.Errorf("event types: got %q,%q want syslog,snmp", decoded[0].Type, decoded[1].Type)
	}
}

func TestSend_EmptyBatchStillPostsArray(t *testing.T) {
	// An empty batch should be a no-op or an empty array — either is
	// acceptable as long as it doesn't panic. The backend treats empty
	// as a no-op (returns 200 / 0 / 0).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	client := newTestClient(t, srv.URL)
	if err := Send(context.Background(), client, nil); err != nil {
		t.Fatalf("Send empty: %v", err)
	}
	if err := Send(context.Background(), client, []Event{}); err != nil {
		t.Fatalf("Send []: %v", err)
	}
}

func TestSend_SurfaceServerError(t *testing.T) {
	// 4xx is non-retried per transport.Client.Do — should surface as
	// an error for the caller (which buffers events into the ring on
	// failure).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	client := newTestClient(t, srv.URL)
	err := Send(context.Background(), client, []Event{newTestEvent("a", "syslog", "1.1.1.1")})
	if err == nil {
		t.Fatal("expected error from 401 response")
	}
}

func TestSend_RespectsContextCancel(t *testing.T) {
	// Server hangs forever; cancelled context should abort the call.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	client := newTestClient(t, srv.URL)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before issuing the call
	err := Send(ctx, client, []Event{newTestEvent("a", "syslog", "x")})
	if err == nil {
		t.Fatal("expected cancellation error")
	}
}

// ─── Manager wiring tests ──────────────────────────────────────────────────

// fakeCollector emits a deterministic stream of events on Run, then exits
// when the context is cancelled. Used to verify Manager fan-in semantics.
type fakeCollector struct {
	name   string
	events []Event
}

func (f *fakeCollector) Name() string { return f.name }

func (f *fakeCollector) Run(ctx context.Context, out chan<- Event) error {
	for _, ev := range f.events {
		select {
		case out <- ev:
		case <-ctx.Done():
			return nil
		}
	}
	<-ctx.Done()
	return nil
}

func TestManager_FansInEventsFromAllCollectors(t *testing.T) {
	mgr := NewManager(nil, "agent-multi")
	mgr.Register(&fakeCollector{name: "a", events: []Event{
		{ID: "a-1", Type: "syslog", Source: "src-a"},
		{ID: "a-2", Type: "syslog", Source: "src-a"},
	}})
	mgr.Register(&fakeCollector{name: "b", events: []Event{
		{ID: "b-1", Type: "snmp", Source: "src-b"},
	}})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		mgr.Run(ctx)
	}()

	// Drain Out() until we see all 3 events or hit a timeout.
	seen := map[string]bool{}
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()

drainLoop:
	for {
		select {
		case ev := <-mgr.Out():
			seen[ev.ID] = true
			if len(seen) == 3 {
				break drainLoop
			}
		case <-deadline.C:
			t.Fatalf("timeout: only saw %d events: %v", len(seen), seen)
		}
	}
	cancel()
	wg.Wait()

	for _, want := range []string{"a-1", "a-2", "b-1"} {
		if !seen[want] {
			t.Errorf("expected event %q, missed", want)
		}
	}
}

// ─── Helpers ───────────────────────────────────────────────────────────────

func newTestClient(t *testing.T, baseURL string) *transport.Client {
	t.Helper()
	c := transport.NewClient(transport.ClientConfig{
		BaseURL:            baseURL,
		InsecureSkipVerify: true,
		Timeout:            2 * time.Second,
		RetryMax:           0, // tests don't want to wait through retries
		RetryDelay:         10 * time.Millisecond,
	})
	c.SetIdentity("agent-test", "test")
	return c
}

func newTestEvent(agentID, eventType, source string) Event {
	return Event{
		ID:        strings.Join([]string{eventType, source, "1"}, "-"),
		AgentID:   agentID,
		Timestamp: time.Now().UTC(),
		Type:      eventType,
		Source:    source,
		Data:      map[string]interface{}{"message": "test"},
	}
}
