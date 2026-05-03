// Package parsers — registry of named parsers used by the state-capture
// pipeline. Each KAL action's ``state_capture.pre.parser`` and
// ``state_capture.post.parser`` field names a parser registered here;
// the persistent-shell ``shellCollector`` looks up the parser, runs the
// declared commands on the device, and feeds the joined output to the
// parser. Whatever map the parser returns becomes the
// ``state_payload`` JSONB column on the ``state_captures`` row.
//
// Why a registry, not first-class functions in the YAML
// -----------------------------------------------------
// Parser code is non-trivial: it understands the vendor's output
// format, extracts the fields the validator cares about, and
// normalizes them so an invariant like ``post.line_protocol == 'up'``
// works the same on cisco_iosxe and arista_eos. Putting that in the
// YAML would either embed Go in the registry (no signed YAML) or
// embed a DSL the validator has to learn. Naming a parser by a slug
// keeps the YAML simple — the implementation is auditable Go that
// ships with the agent build.
//
// Adding a parser is a one-file change in this package plus a
// ``Register(...)`` call from its ``init()``. ``Get`` returns an
// error listing all known parsers when a YAML names something that
// isn't registered, so onboarding a new action with an unknown
// parser fails loud at action-load time, not silently at runtime.
package parsers

import (
	"fmt"
	"sort"
	"sync"
)

// Parser is the function signature every state-capture parser must
// implement. ``rawOutput`` is the joined stdout of the ``commands``
// list (commands separated by newlines, no per-command markers — the
// shell collector strips those before calling the parser). The
// returned map is the row's ``state_payload`` and must be canonical-
// JSON-serializable: only string-keyed maps, slices of supported
// types, and JSON-native scalars (string/bool/numbers).
type Parser func(rawOutput string) (map[string]any, error)

var (
	mu       sync.RWMutex
	registry = make(map[string]Parser)
)

// Register adds a parser to the registry under ``name``. Intended to
// be called from package-level ``init()`` functions in this package
// — registration order doesn't matter since lookups happen at
// action-execution time, well after init.
//
// Re-registering an existing name panics on purpose. Two parsers
// claiming the same name in production would mean one silently wins
// based on package import order, which is a hard-to-trace footgun.
func Register(name string, p Parser) {
	mu.Lock()
	defer mu.Unlock()
	if _, exists := registry[name]; exists {
		panic(fmt.Sprintf("capture/parsers: %q already registered", name))
	}
	if p == nil {
		panic(fmt.Sprintf("capture/parsers: %q registered with nil parser", name))
	}
	registry[name] = p
}

// Get returns the parser registered under ``name`` or an error
// listing the known parsers. Callers should surface the error
// up to the executor so a bad ``state_capture.pre.parser`` value
// in a YAML produces a clear "unknown parser X (registered: …)"
// message rather than an empty state_payload that confuses the
// validator.
func Get(name string) (Parser, error) {
	mu.RLock()
	defer mu.RUnlock()
	p, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf(
			"capture/parsers: unknown parser %q (registered: %v)",
			name, knownLocked(),
		)
	}
	return p, nil
}

// Names returns the registered parser slugs, sorted. Useful for
// logging at agent startup ("parsers loaded: ...") and for tests
// that assert the registry shape.
func Names() []string {
	mu.RLock()
	defer mu.RUnlock()
	return knownLocked()
}

// knownLocked returns sorted parser names. Caller must already hold
// at least mu.RLock.
func knownLocked() []string {
	out := make([]string, 0, len(registry))
	for name := range registry {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
