package dsl

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

const testSecret = "test-secret-do-not-use-in-prod"

// makeBundle builds a freshly-signed SignedBundle for tests. Mirrors the
// shape produced by aione-backend/app/services/kal_registry_signer.py
// so failure modes here translate to the wire contract the BE serves.
func makeBundle(t *testing.T, actions map[string]map[string]interface{}, signedAt time.Time) *SignedBundle {
	t.Helper()
	body, err := CanonicalRegistryBytes(actions)
	if err != nil {
		t.Fatalf("CanonicalRegistryBytes: %v", err)
	}
	mac := hmac.New(sha256.New, []byte(testSecret))
	mac.Write(body)
	sig := hex.EncodeToString(mac.Sum(nil))
	return &SignedBundle{
		Actions:   actions,
		Signature: sig,
		SignedAt:  signedAt.UTC().Format(time.RFC3339Nano),
		Version:   1,
	}
}

func basicAction(id string) map[string]interface{} {
	return map[string]interface{}{
		"id":             id,
		"version":        1,
		"tier":           1,
		"category":       "test",
		"description":    "Test action.",
		"implementation": "dsl",
		"idempotent":     true,
	}
}

// ─── CanonicalRegistryBytes ────────────────────────────────────────────────

func TestCanonicalRegistryBytes_EmptyMap(t *testing.T) {
	out, err := CanonicalRegistryBytes(map[string]map[string]interface{}{})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected empty bytes, got %d bytes", len(out))
	}
}

func TestCanonicalRegistryBytes_OrderIndependent(t *testing.T) {
	a := map[string]map[string]interface{}{
		"a": basicAction("a"),
		"b": basicAction("b"),
		"c": basicAction("c"),
	}
	// Build a second map with explicit reverse-insertion order. Map
	// iteration in Go is randomized, but CanonicalRegistryBytes sorts
	// before concatenating — output must match.
	b := make(map[string]map[string]interface{}, 3)
	b["c"] = basicAction("c")
	b["b"] = basicAction("b")
	b["a"] = basicAction("a")

	bytesA, _ := CanonicalRegistryBytes(a)
	bytesB, _ := CanonicalRegistryBytes(b)
	if string(bytesA) != string(bytesB) {
		t.Errorf("insertion-order changed canonical bytes:\n  a: %q\n  b: %q", bytesA, bytesB)
	}
}

// ─── VerifyBundle happy path + tampering ───────────────────────────────────

func TestVerifyBundle_AcceptsValidSignature(t *testing.T) {
	bundle := makeBundle(t, map[string]map[string]interface{}{"a": basicAction("a")}, time.Now())
	if err := VerifyBundle(bundle, testSecret); err != nil {
		t.Errorf("expected verify to pass, got: %v", err)
	}
}

func TestVerifyBundle_RejectsTamperedSignature(t *testing.T) {
	bundle := makeBundle(t, map[string]map[string]interface{}{"a": basicAction("a")}, time.Now())
	bundle.Signature = hex.EncodeToString(make([]byte, 32)) // all zeros
	err := VerifyBundle(bundle, testSecret)
	if !errors.Is(err, ErrSignatureMismatch) {
		t.Errorf("expected ErrSignatureMismatch, got: %v", err)
	}
}

func TestVerifyBundle_RejectsTamperedActions(t *testing.T) {
	bundle := makeBundle(t, map[string]map[string]interface{}{"a": basicAction("a")}, time.Now())
	// Mutate after signing — the recomputed canonical bytes won't match.
	bundle.Actions["a"]["tier"] = 5
	err := VerifyBundle(bundle, testSecret)
	if !errors.Is(err, ErrSignatureMismatch) {
		t.Errorf("expected ErrSignatureMismatch on tampered actions, got: %v", err)
	}
}

func TestVerifyBundle_RejectsWrongSecret(t *testing.T) {
	bundle := makeBundle(t, map[string]map[string]interface{}{"a": basicAction("a")}, time.Now())
	err := VerifyBundle(bundle, "different-secret")
	if !errors.Is(err, ErrSignatureMismatch) {
		t.Errorf("expected ErrSignatureMismatch with wrong secret, got: %v", err)
	}
}

func TestVerifyBundle_RejectsEmptySecret(t *testing.T) {
	bundle := makeBundle(t, map[string]map[string]interface{}{"a": basicAction("a")}, time.Now())
	err := VerifyBundle(bundle, "")
	if err == nil || !contains(err.Error(), "must not be empty") {
		t.Errorf("expected empty-secret error, got: %v", err)
	}
}

func TestVerifyBundle_RejectsMissingFields(t *testing.T) {
	err := VerifyBundle(&SignedBundle{}, testSecret)
	if !errors.Is(err, ErrBundleMissingFields) {
		t.Errorf("expected ErrBundleMissingFields, got: %v", err)
	}
	err = VerifyBundle(nil, testSecret)
	if !errors.Is(err, ErrBundleMissingFields) {
		t.Errorf("expected ErrBundleMissingFields on nil, got: %v", err)
	}
}

// ─── Staleness window ──────────────────────────────────────────────────────

func TestVerifyBundle_RejectsStaleBundle(t *testing.T) {
	stale := time.Now().Add(-25 * time.Hour) // > MaxBundleAge (24h)
	bundle := makeBundle(t, map[string]map[string]interface{}{"a": basicAction("a")}, stale)
	err := VerifyBundle(bundle, testSecret)
	if !errors.Is(err, ErrBundleStale) {
		t.Errorf("expected ErrBundleStale, got: %v", err)
	}
}

func TestVerifyBundle_AcceptsBundleAtAgeBoundary(t *testing.T) {
	// 23h59m — comfortably under MaxBundleAge.
	bundle := makeBundle(t,
		map[string]map[string]interface{}{"a": basicAction("a")},
		time.Now().Add(-23*time.Hour-59*time.Minute),
	)
	if err := VerifyBundle(bundle, testSecret); err != nil {
		t.Errorf("expected verify to pass at age boundary, got: %v", err)
	}
}

func TestVerifyBundle_RejectsUnparseableTimestamp(t *testing.T) {
	bundle := makeBundle(t, map[string]map[string]interface{}{"a": basicAction("a")}, time.Now())
	bundle.SignedAt = "not-a-timestamp"
	err := VerifyBundle(bundle, testSecret)
	if err == nil || !contains(err.Error(), "parse signed_at") {
		t.Errorf("expected parse error, got: %v", err)
	}
}

// helpers

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
