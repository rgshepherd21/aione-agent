// Tests for Agent.drainTelemetry (Sprint D / D5.2).
//
// drainTelemetry is the heart of the agent's telemetry push pipeline:
// reads from the manager's Out() channel, batches at 64 events,
// flushes every 15s (or when the batch fills), ships via telemetry.Send
// to the backend, and on failure stores events in the offline ring
// buffer to retry on the next flush tick.
//
// These tests stand up an httptest server, point a real transport.Client
// at it, and exercise the full path. The flush ticker is the only
// non-injectable bit — tests rely on filling batches to 64 to force
// a ship rather than waiting 15 seconds.

package service

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shepherdtech/aione-agent/internal/buffer"
	"github.com/shepherdtech/aione-agent/internal/telemetry"
	"github.com/shepherdtech/aione-agent/internal/transport"
)

// recordingServer captures every POST body it receives. Use to verify
// that drainTelemetry shipped the events we expected.
type recordingServer struct {
	mu        sync.Mutex
	calls     [][]telemetry.Event
	respCode  int32 // atomic; lets a test flip the response mid-flight
	respDelay time.Duration
}

func (r *recordingServer) handler(w http.ResponseWriter, req *http.Request) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var events []telemetry.Event
	if len(body) > 0 {
		if err := json.Unmarshal(body, &events); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	r.mu.Lock()
	r.calls = append(r.calls, events)
	r.mu.Unlock()

	if r.respDelay > 0 {
		time.Sleep(r.respDelay)
	}
	code := int(atomic.LoadInt32(&r.respCode))
	if code == 0 {
		code = http.StatusOK
	}
	w.WriteHeader(code)
}

func (r *recordingServer) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

func (r *recordingServer) lastBatch() []telemetry.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.calls) == 0 {
		return nil
	}
	return r.calls[len(r.calls)-1]
}

func (r *recordingServer) totalEvents() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, c := range r.calls {
		n += len(c)
	}
	return n
}

func newRecordingHarness(t *testing.T) (*recordingServer, *transport.Client, *buffer.RingBuffer, func()) {
	t.Helper()
	rec := &recordingServer{}
	srv := httptest.NewServer(http.HandlerFunc(rec.handler))

	client := transport.NewClient(transport.ClientConfig{
		BaseURL:            srv.URL,
		InsecureSkipVerify: true,
		Timeout:            2 * time.Second,
		RetryMax:           0,
		RetryDelay:         10 * time.Millisecond,
	})
	client.SetIdentity("agent-test", "test")

	buf, err := buffer.New(1000, "")
	if err != nil {
		t.Fatalf("buffer.New: %v", err)
	}
	return rec, client, buf, srv.Close
}

func makeEvent(id string) telemetry.Event {
	return telemetry.Event{
		ID:        id,
		AgentID:   "agent-test",
		Timestamp: time.Now().UTC(),
		Type:      "syslog",
		Source:    "test-source",
		Data:      map[string]interface{}{"message": id},
	}
}

// ─── Happy path: batch of 64 forces an immediate ship ─────────────────────

func TestDrainTelemetry_BatchOf64ShipsImmediately(t *testing.T) {
	rec, client, buf, closeSrv := newRecordingHarness(t)
	defer closeSrv()

	in := make(chan telemetry.Event, 100)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		(&Agent{}).drainTelemetry(ctx, in, buf, client)
	}()

	// Push exactly 64 events — drainTelemetry's batch threshold.
	for i := 0; i < 64; i++ {
		in <- makeEvent(string(rune('a' + i%26)))
	}

	// Wait for the ship to land.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && rec.callCount() == 0 {
		time.Sleep(20 * time.Millisecond)
	}
	if rec.callCount() != 1 {
		t.Fatalf("expected 1 POST after 64 events, got %d", rec.callCount())
	}
	if got := len(rec.lastBatch()); got != 64 {
		t.Errorf("batch size: got %d, want 64", got)
	}

	cancel()
	wg.Wait()
}

// ─── Failure path: 401 lands events in the ring buffer ────────────────────

func TestDrainTelemetry_ShipFailureBuffersEvents(t *testing.T) {
	rec, client, buf, closeSrv := newRecordingHarness(t)
	defer closeSrv()
	atomic.StoreInt32(&rec.respCode, http.StatusUnauthorized)

	in := make(chan telemetry.Event, 100)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		(&Agent{}).drainTelemetry(ctx, in, buf, client)
	}()

	for i := 0; i < 64; i++ {
		in <- makeEvent("x")
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && buf.Len() < 64 {
		time.Sleep(20 * time.Millisecond)
	}
	if buf.Len() != 64 {
		t.Errorf("offline buffer: got %d events, want 64", buf.Len())
	}

	cancel()
	wg.Wait()
}

// ─── Recovery path: server flips back to 200, buffered events drain ───────

func TestDrainTelemetry_OfflineBufferDrainsOnNextFlush(t *testing.T) {
	rec, client, buf, closeSrv := newRecordingHarness(t)
	defer closeSrv()

	// Pre-populate the offline buffer with events that arrived while
	// "offline" — simulating a previous failed batch.
	for i := 0; i < 10; i++ {
		buf.Push(makeEvent("offline"))
	}
	atomic.StoreInt32(&rec.respCode, http.StatusOK)

	in := make(chan telemetry.Event, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		(&Agent{}).drainTelemetry(ctx, in, buf, client)
	}()

	// Push enough events to cross the 64-batch threshold so a ship
	// fires. The post-success branch then drains the offline buffer.
	for i := 0; i < 64; i++ {
		in <- makeEvent("fresh")
	}

	deadline := time.Now().Add(20 * time.Second) // > flushInterval (15s)
	for time.Now().Before(deadline) && rec.totalEvents() < 74 {
		time.Sleep(100 * time.Millisecond)
	}
	if rec.totalEvents() < 74 {
		t.Errorf("expected >= 74 events shipped (64 fresh + 10 offline), got %d", rec.totalEvents())
	}
	if buf.Len() != 0 {
		t.Errorf("offline buffer should be empty post-drain, has %d", buf.Len())
	}

	cancel()
	wg.Wait()
}

// ─── Shutdown path: ctx cancellation buffers in-flight batch ─────────────

func TestDrainTelemetry_ShutdownPreservesPartialBatch(t *testing.T) {
	rec, client, buf, closeSrv := newRecordingHarness(t)
	defer closeSrv()

	in := make(chan telemetry.Event, 100)
	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		(&Agent{}).drainTelemetry(ctx, in, buf, client)
	}()

	// Push only 5 events — under the batch threshold. They sit in the
	// in-memory batch waiting for either 64 or a flush tick.
	for i := 0; i < 5; i++ {
		in <- makeEvent("partial")
	}
	// Give the goroutine a moment to absorb them into the batch.
	time.Sleep(100 * time.Millisecond)

	cancel()
	wg.Wait()

	// The in-flight batch should land in the offline buffer for the
	// next process to retry.
	if buf.Len() != 5 {
		t.Errorf("offline buffer post-shutdown: got %d, want 5", buf.Len())
	}
	if rec.callCount() != 0 {
		t.Errorf("no ships should have fired for a sub-batch on shutdown, got %d", rec.callCount())
	}
}

// ─── Closed-channel path: drainTelemetry exits cleanly on chan close ─────

func TestDrainTelemetry_ExitsOnInputChannelClose(t *testing.T) {
	_, client, buf, closeSrv := newRecordingHarness(t)
	defer closeSrv()

	in := make(chan telemetry.Event)
	close(in) // closed before any reader starts

	done := make(chan struct{})
	go func() {
		(&Agent{}).drainTelemetry(context.Background(), in, buf, client)
		close(done)
	}()

	select {
	case <-done:
		// expected — drainTelemetry should exit promptly on closed in-channel
	case <-time.After(2 * time.Second):
		t.Fatal("drainTelemetry didn't exit when input channel was closed")
	}
}
