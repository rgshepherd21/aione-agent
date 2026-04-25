package dsl

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// ─── Golden parity: this is THE test that closes task #23 ─────────────────
//
// Pinned SHA-256 must equal the value pinned in the BE-side test
// (aione-backend/tests/test_kal_canonical.py::test_flush_dns_cache_sha256_golden).
// Drift on either side fails both tests at once.
const flushDNSCacheGoldenSHA256 = "950194372938eeaec4372654ae669041182c2c4dfa5e66f383a045bfcb2111e0"

// flushDNSCacheGoldenBody is the expected exact bytes. Pinned here as a
// raw string so a mismatch produces a readable diff instead of just a
// hash comparison.
const flushDNSCacheGoldenBody = `{"category":"network/dns","description":"Flush the local DNS resolver cache. Idempotent; safe to run on demand.","executors":{"darwin":{"args":["-flushcache"],"binary":"/usr/sbin/dscacheutil"},"linux":{"args":["flush-caches"],"binary":"/usr/bin/resolvectl","fallbacks":[{"args":["--flush-caches"],"binary":"/usr/bin/systemd-resolve"}]},"windows":{"args":["/flushdns"],"binary":"C:\\Windows\\System32\\ipconfig.exe"}},"id":"flush_dns_cache","idempotent":true,"implementation":"dsl","parameters":{"schema":{"additionalProperties":false,"properties":{},"type":"object"}},"rollback":{"possible":false,"rationale":"DNS cache re-populates on next query. No explicit rollback needed."},"state_capture":{"post":"stateless","pre":"none"},"supported_platforms":[{"archs":["amd64","arm64"],"os":"linux"},{"archs":["amd64","arm64"],"os":"darwin"},{"archs":["amd64","arm64"],"os":"windows"}],"tier":1,"validators":{"post_execution":{"exit_code":0,"timeout_seconds":10}},"version":1}`

func TestCanonicalActionBody_FlushDNSGolden(t *testing.T) {
	raw := loadFixture(t, "flush_dns_cache.yaml")

	body, err := CanonicalActionBody(raw)
	if err != nil {
		t.Fatalf("CanonicalActionBody returned error: %v", err)
	}

	gotBody := string(body)
	if gotBody != flushDNSCacheGoldenBody {
		// Compute the position of first divergence so the failure
		// surfaces the actual issue, not the whole 800-byte diff.
		divergeAt := -1
		minLen := len(gotBody)
		if len(flushDNSCacheGoldenBody) < minLen {
			minLen = len(flushDNSCacheGoldenBody)
		}
		for i := 0; i < minLen; i++ {
			if gotBody[i] != flushDNSCacheGoldenBody[i] {
				divergeAt = i
				break
			}
		}
		t.Errorf(
			"canonical body mismatch (diverges at byte %d, lengths got=%d want=%d):\n  want: %q\n  got:  %q",
			divergeAt, len(gotBody), len(flushDNSCacheGoldenBody),
			flushDNSCacheGoldenBody, gotBody,
		)
	}

	sha, err := CanonicalActionSHA256(raw)
	if err != nil {
		t.Fatalf("CanonicalActionSHA256 returned error: %v", err)
	}
	if sha != flushDNSCacheGoldenSHA256 {
		t.Errorf("SHA-256 mismatch:\n  want: %s\n  got:  %s", flushDNSCacheGoldenSHA256, sha)
	}

	// Belt-and-suspenders: independently re-hash the byte form to catch
	// any drift between the two helper functions.
	independent := sha256.Sum256(body)
	if hex.EncodeToString(independent[:]) != sha {
		t.Errorf("CanonicalActionSHA256 != sha256(CanonicalActionBody): %s vs %s",
			sha, hex.EncodeToString(independent[:]))
	}
}

// ─── Determinism + isolation tests (mirror the Python suite) ──────────────

func TestCanonicalActionBody_Deterministic(t *testing.T) {
	action := baseAction()
	a, err := CanonicalActionBody(action)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	b, err := CanonicalActionBody(action)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if string(a) != string(b) {
		t.Errorf("non-deterministic output:\n  a: %s\n  b: %s", a, b)
	}
}

func TestCanonicalActionBody_KeyOrderInsensitive(t *testing.T) {
	a := baseAction()
	// Build a second map with keys inserted in a different order; Go map
	// iteration is randomized but json.Marshal sorts on serialize, so the
	// canonical bytes must be identical. (This is more of a sanity check
	// for the implementation's reliance on json.Marshal's sort behavior.)
	b := make(map[string]interface{}, len(a))
	keys := []string{}
	for k := range a {
		keys = append(keys, k)
	}
	// reverse insertion order
	for i := len(keys) - 1; i >= 0; i-- {
		b[keys[i]] = a[keys[i]]
	}
	aBytes, _ := CanonicalActionBody(a)
	bBytes, _ := CanonicalActionBody(b)
	if string(aBytes) != string(bBytes) {
		t.Errorf("key order changed canonical body:\n  a: %s\n  b: %s", aBytes, bBytes)
	}
}

func TestCanonicalActionBody_MetadataExcluded(t *testing.T) {
	a := baseAction()
	b := baseAction()
	b["patent_claim_refs"] = []interface{}{"4e", "1-vii"}
	b["deprecated"] = true
	b["replaced_by"] = "ping_host_v2"

	aBytes, _ := CanonicalActionBody(a)
	bBytes, _ := CanonicalActionBody(b)
	if string(aBytes) != string(bBytes) {
		t.Errorf("metadata changed canonical body (should be excluded):\n  a: %s\n  b: %s", aBytes, bBytes)
	}
}

func TestCanonicalActionBody_NilValuesDropped(t *testing.T) {
	a := baseAction()
	b := baseAction()
	b["parameter_transforms"] = nil

	aBytes, _ := CanonicalActionBody(a)
	bBytes, _ := CanonicalActionBody(b)
	if string(aBytes) != string(bBytes) {
		t.Errorf("nil value not dropped:\n  a: %s\n  b: %s", aBytes, bBytes)
	}
}

func TestCanonicalActionBody_ListOrderPreserved(t *testing.T) {
	a := baseAction()
	a["executors"].(map[string]interface{})["linux"].(map[string]interface{})["args"] = []interface{}{"first", "second", "third"}
	b := baseAction()
	b["executors"].(map[string]interface{})["linux"].(map[string]interface{})["args"] = []interface{}{"third", "second", "first"}

	aBytes, _ := CanonicalActionBody(a)
	bBytes, _ := CanonicalActionBody(b)
	if string(aBytes) == string(bBytes) {
		t.Errorf("list order ignored — should produce different canonical bodies:\n  bytes: %s", aBytes)
	}
}

func TestCanonicalActionBody_NonASCIIPreservedAsUTF8(t *testing.T) {
	a := baseAction()
	a["description"] = "Flush DNS — résumé café 日本語"
	body, err := CanonicalActionBody(a)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	// UTF-8 literal bytes for "日本語" (E6 97 A5 E6 9C AC E8 AA 9E) must
	// appear; no \uXXXX escape form.
	if !strings.Contains(string(body), "日本語") {
		t.Errorf("non-ASCII not preserved as UTF-8 literal: %s", body)
	}
	if strings.Contains(string(body), `\u`) {
		t.Errorf("found JSON unicode escape (should be UTF-8 literal): %s", body)
	}
}

func TestCanonicalActionBody_NoHTMLEscaping(t *testing.T) {
	// Python's json.dumps(ensure_ascii=False) does NOT escape <, >, &.
	// Go's default json.Encoder DOES (HTML-safe). Our generator disables
	// SetEscapeHTML; this test pins the behavior. We assert the canonical
	// body contains the literal characters (what we want) and does NOT
	// contain their JSON unicode-escape forms (what default Go would emit).
	a := baseAction()
	a["description"] = "uses < and > and & literally"
	body, err := CanonicalActionBody(a)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	bodyStr := string(body)
	for _, lit := range []string{`<`, `>`, `&`} {
		if !strings.Contains(bodyStr, lit) {
			t.Errorf("expected literal %q in canonical body, got: %s", lit, bodyStr)
		}
	}
	for _, esc := range []string{`<`, `>`, `&`} {
		if strings.Contains(bodyStr, esc) {
			t.Errorf("found HTML escape sequence %q (Go default) — SetEscapeHTML(false) failed: %s", esc, bodyStr)
		}
	}
}

// ─── helpers ──────────────────────────────────────────────────────────────

// loadFixture reads a YAML file from testdata/ and decodes it the same way
// the future loader (task #24) will: gopkg.in/yaml.v3 into
// map[string]interface{}. Returns the decoded map for canonical-body
// processing.
func loadFixture(t *testing.T, name string) map[string]interface{} {
	t.Helper()
	path := filepath.Join("testdata", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %q: %v", path, err)
	}
	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal fixture %q: %v", path, err)
	}
	return raw
}

// baseAction returns a minimal valid action used as the starting point
// for the per-rule tests above. Mirrors the _base_action() helper in
// aione-backend/tests/test_kal_canonical.py so the two suites stay
// recognizably parallel.
func baseAction() map[string]interface{} {
	return map[string]interface{}{
		"id":          "test_action",
		"version":     1,
		"tier":        1,
		"category":    "network/dns",
		"description": "Test action.",
		"implementation": "dsl",
		"parameters": map[string]interface{}{
			"schema": map[string]interface{}{
				"type":                 "object",
				"properties":           map[string]interface{}{},
				"additionalProperties": false,
			},
		},
		"idempotent": true,
		"supported_platforms": []interface{}{
			map[string]interface{}{
				"os":    "linux",
				"archs": []interface{}{"amd64"},
			},
		},
		"executors": map[string]interface{}{
			"linux": map[string]interface{}{
				"binary": "/usr/bin/echo",
				"args":   []interface{}{"hello"},
			},
		},
		"validators": map[string]interface{}{
			"post_execution": map[string]interface{}{
				"exit_code":       0,
				"timeout_seconds": 5,
			},
		},
		"state_capture": map[string]interface{}{
			"pre":  "none",
			"post": "stateless",
		},
		"rollback": map[string]interface{}{
			"possible":  false,
			"rationale": "No state.",
		},
	}
}
