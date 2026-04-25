// Package dsl provides the agent-side KAL DSL action-definition canonical
// body generator. It MUST stay byte-identical to the Python implementation
// in aione-backend/app/services/kal_canonical.py — a cross-repo golden
// fixture test (canonical_test.go::TestCanonicalActionBody_FlushDNSGolden)
// pins the expected SHA-256 to the same hex value as the Python-side
// pinned digest in tests/test_kal_canonical.py.
//
// Drift on either side fails both tests at once. Any time you change one,
// update the other in the same PR.
//
// Canonical form rules (mirror of the Python module):
//
//  1. Strip metadata fields that describe lifecycle/documentation rather
//     than action behavior (patent_claim_refs, deprecated, replaced_by).
//     These can evolve freely without invalidating the signature.
//  2. Recursively normalize: nil values in maps are dropped (absence ==
//     null), lists preserve declared order (executor fallback precedence,
//     arg order, supported_platforms ordering all matter semantically).
//  3. Serialize with sorted keys at every depth, no whitespace, UTF-8
//     literal for non-ASCII, no HTML escaping (<, >, & pass through).
//  4. SHA-256 of the canonical bytes is the stable content fingerprint
//     used as the agent's local identifier for action definition versions.
//
// Why we don't just call Python's json.dumps via cgo or a sidecar: the
// agent runs on customer hardware with no Python runtime; canonical form
// has to be a pure-Go function on the hot path of action execution.
package dsl

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// metadataFieldsExcluded mirrors _METADATA_FIELDS_EXCLUDED in
// aione-backend/app/services/kal_canonical.py. Fields that document
// state/lifecycle (patent claim refs for legal tracking; deprecated +
// replaced_by for migration tracking) don't affect runtime behavior, so
// they're stripped before signing. This lets ops add a patent claim
// reference or mark an action deprecated without re-signing every
// agent's embedded copy of the action definition.
var metadataFieldsExcluded = map[string]struct{}{
	"patent_claim_refs": {},
	"deprecated":        {},
	"replaced_by":       {},
}

// CanonicalActionBody returns the exact bytes to sign for a single action
// definition. Input is typically the result of yaml.Unmarshal into a
// map[string]interface{}. The implementation MUST stay byte-identical to
// canonical_action_body() in aione-backend/app/services/kal_canonical.py.
func CanonicalActionBody(action map[string]interface{}) ([]byte, error) {
	normalized, err := normalize(action)
	if err != nil {
		return nil, fmt.Errorf("dsl: normalize: %w", err)
	}

	// Go's json.Marshal sorts map[string]interface{} keys lexicographically
	// by default (matches Python sort_keys=True). What it does NOT match
	// out-of-the-box: the default encoder escapes <, >, & to < etc.
	// for HTML safety. Python's ensure_ascii=False does NOT do that, so we
	// have to use json.Encoder.SetEscapeHTML(false) to disable it.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(normalized); err != nil {
		return nil, fmt.Errorf("dsl: encode canonical body: %w", err)
	}
	// Encode appends a trailing newline; Python's json.dumps does not.
	out := buf.Bytes()
	if len(out) > 0 && out[len(out)-1] == '\n' {
		out = out[:len(out)-1]
	}
	return out, nil
}

// CanonicalActionSHA256 returns the hex-encoded SHA-256 digest of the
// canonical action body. This is the stable content fingerprint pinned
// in the registry and verified at agent registry-load time.
func CanonicalActionSHA256(action map[string]interface{}) (string, error) {
	body, err := CanonicalActionBody(action)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]), nil
}

// normalize recursively walks a YAML-decoded value applying the canonical
// rules: drop metadata-excluded keys + nil values from maps, preserve list
// order, pass scalars through.
//
// Defensive on map types: yaml.v3 normally returns map[string]interface{}
// for objects with string keys, but we accept map[interface{}]interface{}
// too (older yaml.v2 shape, sometimes appears in nested decodings) and
// reject any non-string key — JSON canonical form requires string keys
// and the KAL schema only permits them.
func normalize(value interface{}) (interface{}, error) {
	switch v := value.(type) {

	case map[string]interface{}:
		result := make(map[string]interface{}, len(v))
		for k, item := range v {
			if _, drop := metadataFieldsExcluded[k]; drop {
				continue
			}
			if item == nil {
				continue
			}
			n, err := normalize(item)
			if err != nil {
				return nil, fmt.Errorf("at key %q: %w", k, err)
			}
			result[k] = n
		}
		return result, nil

	case map[interface{}]interface{}:
		// yaml.v2-style nested map. Convert if all keys are strings;
		// reject otherwise — KAL schema disallows non-string keys.
		result := make(map[string]interface{}, len(v))
		for k, item := range v {
			ks, ok := k.(string)
			if !ok {
				return nil, fmt.Errorf("non-string map key %v (type %T)", k, k)
			}
			if _, drop := metadataFieldsExcluded[ks]; drop {
				continue
			}
			if item == nil {
				continue
			}
			n, err := normalize(item)
			if err != nil {
				return nil, fmt.Errorf("at key %q: %w", ks, err)
			}
			result[ks] = n
		}
		return result, nil

	case []interface{}:
		// Lists preserve declared order — never sort.
		result := make([]interface{}, len(v))
		for i, item := range v {
			n, err := normalize(item)
			if err != nil {
				return nil, fmt.Errorf("at index %d: %w", i, err)
			}
			result[i] = n
		}
		return result, nil

	case nil:
		return nil, nil

	default:
		// Scalars: string, int, int64, float64, bool, etc. Pass through.
		// json.Marshal handles each per its standard rules, and Python's
		// json.dumps produces the same output for the scalar types KAL
		// action YAMLs use (strings, ints, bools — no floats in the
		// schema, no special objects).
		return v, nil
	}
}
