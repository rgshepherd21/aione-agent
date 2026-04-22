package capture

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// canonicalMarshal produces the byte sequence used as input to
// payload_hash. Contract (see package doc for full spec):
//
//   - UTF-8
//   - keys sorted lexicographically at every nesting level
//   - compact ","/":" separators, no whitespace
//   - HTML escaping DISABLED
//   - non-ASCII kept as raw UTF-8
//
// Implementation notes:
//
//   - encoding/json sorts map[string]* keys alphabetically at marshal time;
//     nested maps inherit that sort, so we get deterministic output at
//     every level for free provided the caller uses maps (not structs).
//
//   - json.Encoder with SetEscapeHTML(false) suppresses Go's default
//     HTML-safe escapes (<, >, &) that Python does not emit.
//
//   - Encoder appends a trailing newline; we strip it so the output is
//     byte-identical to Python's json.dumps(..., separators=(",", ":"),
//     sort_keys=True, ensure_ascii=False).encode("utf-8").
//
//   - nil payload is normalized to {} so the hash is stable regardless of
//     whether the caller passed nil or an empty map. This matches the
//     backend column default of '{}'::jsonb.
func canonicalMarshal(payload map[string]any) ([]byte, error) {
	if payload == nil {
		payload = map[string]any{}
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)

	if err := enc.Encode(payload); err != nil {
		return nil, fmt.Errorf("canonical marshal: %w", err)
	}

	out := buf.Bytes()
	// Strip the trailing newline that json.Encoder unconditionally appends.
	if n := len(out); n > 0 && out[n-1] == '\n' {
		out = out[:n-1]
	}
	return out, nil
}

// sha256Hex returns the lowercase hex encoding of SHA-256(data), which is
// always 64 characters. Matches the backend payload_hash CHAR(64) column.
func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
