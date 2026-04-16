// Package buffer provides a thread-safe, fixed-capacity ring buffer for
// offline telemetry storage.  When the agent loses connectivity, events are
// pushed here; once connectivity is restored the service drains and ships them.
// The buffer can optionally persist to disk so events survive process restarts.
package buffer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/rs/zerolog/log"
	"github.com/shepherdtech/aione-agent/internal/telemetry"
)

// RingBuffer is a bounded FIFO backed by a slice.  When the buffer is full
// the oldest entry is silently overwritten (drop-oldest semantics), matching
// the behaviour expected for a telemetry agent under sustained disconnection.
type RingBuffer struct {
	mu       sync.Mutex
	items    []telemetry.Event
	head     int // index of next slot to write
	count    int // number of valid entries
	capacity int

	filePath string // empty = no disk persistence
}

// New creates a RingBuffer with the given capacity.
// If filePath is non-empty the buffer is loaded from disk on creation and
// flushed to disk whenever items are added.
func New(capacity int, filePath string) (*RingBuffer, error) {
	if capacity <= 0 {
		return nil, fmt.Errorf("buffer capacity must be > 0")
	}

	rb := &RingBuffer{
		items:    make([]telemetry.Event, capacity),
		capacity: capacity,
		filePath: filePath,
	}

	if filePath != "" {
		if err := rb.loadFromDisk(); err != nil {
			// A missing or corrupt file is not fatal; start empty.
			log.Warn().Err(err).Str("path", filePath).Msg("could not load buffer from disk, starting empty")
		}
	}

	return rb, nil
}

// Push adds an event to the buffer.  If the buffer is full the oldest entry
// is overwritten and a warning is logged.
func (rb *RingBuffer) Push(ev telemetry.Event) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if rb.count == rb.capacity {
		log.Warn().Int("capacity", rb.capacity).Msg("buffer full, dropping oldest event")
	} else {
		rb.count++
	}

	rb.items[rb.head] = ev
	rb.head = (rb.head + 1) % rb.capacity

	if rb.filePath != "" {
		if err := rb.saveToDisk(); err != nil {
			log.Warn().Err(err).Msg("buffer: failed to persist to disk")
		}
	}
}

// Drain returns all buffered events and resets the buffer.
func (rb *RingBuffer) Drain() []telemetry.Event {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if rb.count == 0 {
		return nil
	}

	out := make([]telemetry.Event, rb.count)
	tail := (rb.head - rb.count + rb.capacity) % rb.capacity
	for i := range out {
		out[i] = rb.items[(tail+i)%rb.capacity]
	}

	// Reset.
	rb.head = 0
	rb.count = 0

	if rb.filePath != "" {
		if err := rb.saveToDisk(); err != nil {
			log.Warn().Err(err).Msg("buffer: failed to persist drain to disk")
		}
	}

	return out
}

// Len returns the number of buffered events.
func (rb *RingBuffer) Len() int {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.count
}

// persistenceFormat is the on-disk JSON structure.
type persistenceFormat struct {
	Events []telemetry.Event `json:"events"`
}

func (rb *RingBuffer) saveToDisk() error {
	if err := os.MkdirAll(filepath.Dir(rb.filePath), 0o700); err != nil {
		return fmt.Errorf("creating buffer directory: %w", err)
	}

	// Collect events in order without holding lock (already held by caller).
	events := make([]telemetry.Event, rb.count)
	tail := (rb.head - rb.count + rb.capacity) % rb.capacity
	for i := range events {
		events[i] = rb.items[(tail+i)%rb.capacity]
	}

	data, err := json.Marshal(persistenceFormat{Events: events})
	if err != nil {
		return fmt.Errorf("marshalling buffer: %w", err)
	}

	// Write via temp file for atomicity.
	tmp, err := os.CreateTemp(filepath.Dir(rb.filePath), ".buf-tmp-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	tmp.Close()
	return os.Rename(tmpName, rb.filePath)
}

func (rb *RingBuffer) loadFromDisk() error {
	data, err := os.ReadFile(rb.filePath)
	if err != nil {
		return err
	}

	var pf persistenceFormat
	if err := json.Unmarshal(data, &pf); err != nil {
		return fmt.Errorf("parsing buffer file: %w", err)
	}

	for _, ev := range pf.Events {
		if rb.count == rb.capacity {
			break // more events on disk than current capacity; discard oldest
		}
		rb.items[rb.head] = ev
		rb.head = (rb.head + 1) % rb.capacity
		rb.count++
	}

	log.Info().Int("recovered", rb.count).Str("path", rb.filePath).Msg("buffer loaded from disk")
	return nil
}
