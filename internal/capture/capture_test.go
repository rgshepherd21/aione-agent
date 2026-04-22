package capture

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// fixedTime is the captured_at value used by every test in this file so
// Capture values are trivially comparable across runs.
var fixedTime = time.Date(2026, 4, 22, 14, 30, 0, 0, time.UTC)

// okCollector returns the given payload without error.
func okCollector(payload map[string]any) Collector {
	return CollectorFunc(func(ctx context.Context) (map[string]any, error) {
		return payload, nil
	})
}

// errCollector returns the given error and a nil payload.
func errCollector(err error) Collector {
	return CollectorFunc(func(ctx context.Context) (map[string]any, error) {
		return nil, err
	})
}

func validRequest() Request {
	return Request{
		ActionExecutionID: "00000000-0000-0000-0000-000000000001",
		AgentID:           "00000000-0000-0000-0000-000000000002",
		TenantID:          "00000000-0000-0000-0000-000000000003",
		CaptureType:       CaptureTypePre,
		CaptureMethod:     CaptureMethodShell,
	}
}

func TestCaptureTypeConstants(t *testing.T) {
	// Must match the backend CHECK constraint in migration 019:
	// capture_type IN ('pre', 'post'). Any rename here without a
	// matching backend migration would fail as a 422 on first POST.
	if CaptureTypePre != "pre" {
		t.Errorf("CaptureTypePre = %q, want %q", CaptureTypePre, "pre")
	}
	if CaptureTypePost != "post" {
		t.Errorf("CaptureTypePost = %q, want %q", CaptureTypePost, "post")
	}
}

func TestCaptureMethodConstantsFitColumn(t *testing.T) {
	// capture_method column is VARCHAR(32); values longer than that
	// would error at the DB layer. Keep the constants short so
	// misuse by callers is unlikely.
	methods := []string{
		CaptureMethodShell,
		CaptureMethodWMI,
		CaptureMethodSNMP,
		CaptureMethodFile,
		CaptureMethodSyscall,
	}
	for _, m := range methods {
		if len(m) > 32 {
			t.Errorf("capture method %q exceeds VARCHAR(32)", m)
		}
		if m == "" {
			t.Error("capture method constant is empty")
		}
	}
}

func TestRunRejectsInvalidRequest(t *testing.T) {
	type tc struct {
		name   string
		mutate func(r *Request)
	}
	cases := []tc{
		{"missing ActionExecutionID", func(r *Request) { r.ActionExecutionID = "" }},
		{"missing AgentID", func(r *Request) { r.AgentID = "" }},
		{"missing TenantID", func(r *Request) { r.TenantID = "" }},
		{"missing CaptureMethod", func(r *Request) { r.CaptureMethod = "" }},
		{"empty CaptureType", func(r *Request) { r.CaptureType = "" }},
		{"unknown CaptureType", func(r *Request) { r.CaptureType = "during" }},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := validRequest()
			c.mutate(&req)
			_, err := Run(context.Background(), req, okCollector(nil))
			if err == nil {
				t.Fatal("expected Run to reject invalid request, got nil error")
			}
		})
	}
}

func TestRunSucceeds(t *testing.T) {
	req := validRequest()
	req.DeviceID = "00000000-0000-0000-0000-000000000009"
	req.CaptureSource = "ipconfig /displaydns"

	payload := map[string]any{
		"hostname":     "sheptech-win-01",
		"entry_count":  3,
		"tcp_enabled":  true,
		"resolver":     "1.1.1.1",
	}

	got, err := RunAt(context.Background(), req, okCollector(payload), fixedTime)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if !got.CaptureSucceeded {
		t.Error("CaptureSucceeded = false, want true")
	}
	if got.ErrorMessage != nil {
		t.Errorf("ErrorMessage = %q, want nil", *got.ErrorMessage)
	}
	if got.CaptureType != CaptureTypePre {
		t.Errorf("CaptureType = %q, want %q", got.CaptureType, CaptureTypePre)
	}
	if got.CapturedAt != fixedTime {
		t.Errorf("CapturedAt = %v, want %v", got.CapturedAt, fixedTime)
	}
	if got.DeviceID == nil || *got.DeviceID != req.DeviceID {
		t.Errorf("DeviceID = %v, want %q", got.DeviceID, req.DeviceID)
	}
	if got.CaptureSource == nil || *got.CaptureSource != req.CaptureSource {
		t.Errorf("CaptureSource = %v, want %q", got.CaptureSource, req.CaptureSource)
	}
	if len(got.PayloadHash) != 64 {
		t.Errorf("PayloadHash length = %d, want 64", len(got.PayloadHash))
	}
	if got.StatePayload["hostname"] != "sheptech-win-01" {
		t.Errorf("StatePayload did not round-trip: got %v", got.StatePayload)
	}
}

func TestRunCollectorError(t *testing.T) {
	req := validRequest()
	boom := errors.New("ipconfig: exit 1")

	got, err := RunAt(context.Background(), req, errCollector(boom), fixedTime)
	if err == nil {
		t.Fatal("Run returned nil error on collector failure")
	}
	if err.Error() != boom.Error() {
		t.Errorf("Run err = %q, want %q", err, boom)
	}
	if got.CaptureSucceeded {
		t.Error("CaptureSucceeded = true, want false on collector error")
	}
	if got.ErrorMessage == nil || *got.ErrorMessage != boom.Error() {
		t.Errorf("ErrorMessage = %v, want %q", got.ErrorMessage, boom.Error())
	}
	if len(got.StatePayload) != 0 {
		t.Errorf("StatePayload = %v, want empty map", got.StatePayload)
	}
	// Hash of canonical({}) is deterministic and always 64 hex chars.
	expectedEmpty, _ := canonicalMarshal(map[string]any{})
	if got, want := got.PayloadHash, sha256Hex(expectedEmpty); got != want {
		t.Errorf("PayloadHash on failure = %q, want hash of {} = %q", got, want)
	}
}

func TestRunNilPayloadIsEmptyObject(t *testing.T) {
	// Collector returns nil, nil — treat as empty {} and succeed.
	req := validRequest()
	got, err := RunAt(context.Background(), req, okCollector(nil), fixedTime)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !got.CaptureSucceeded {
		t.Error("CaptureSucceeded = false, want true")
	}
	if got.StatePayload == nil {
		t.Error("StatePayload is nil, want empty map")
	}
	if len(got.StatePayload) != 0 {
		t.Errorf("StatePayload = %v, want empty map", got.StatePayload)
	}
}

func TestCanonicalKeyOrderStable(t *testing.T) {
	// Build the same logical payload two different ways; canonical
	// bytes must match because encoding/json sorts map keys at every
	// level regardless of insertion order.
	a := map[string]any{"b": 2, "a": 1, "c": map[string]any{"z": 9, "y": 8}}
	b := map[string]any{"c": map[string]any{"y": 8, "z": 9}, "a": 1, "b": 2}

	ba, err := canonicalMarshal(a)
	if err != nil {
		t.Fatalf("marshal a: %v", err)
	}
	bb, err := canonicalMarshal(b)
	if err != nil {
		t.Fatalf("marshal b: %v", err)
	}
	if string(ba) != string(bb) {
		t.Errorf("canonical bytes differ:\n  a = %s\n  b = %s", ba, bb)
	}
}

func TestCanonicalNoHTMLEscape(t *testing.T) {
	// Go json default escapes <, >, & to \u003c/\u003e/\u0026;
	// Python json.dumps does not. Our canonical form matches Python,
	// so these chars must appear literally in the output.
	payload := map[string]any{"policy": "a&b<c>d"}
	got, err := canonicalMarshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	gotStr := string(got)
	if !strings.Contains(gotStr, "a&b<c>d") {
		t.Errorf("canonical bytes should contain literal 'a&b<c>d', got: %s", gotStr)
	}
	if strings.Contains(gotStr, `\u003c`) || strings.Contains(gotStr, `\u003e`) || strings.Contains(gotStr, `\u0026`) {
		t.Errorf("canonical bytes contain HTML-escape sequences: %s", gotStr)
	}
}

func TestCanonicalUTF8NotEscaped(t *testing.T) {
	// Python ensure_ascii=False keeps non-ASCII as raw UTF-8 bytes
	// rather than \u escapes. Our canonical form must match.
	payload := map[string]any{"site_note": "café日本"}
	got, err := canonicalMarshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(got), "café日本") {
		t.Errorf("canonical bytes should contain raw UTF-8 'café日本', got: %s", got)
	}
	if strings.Contains(string(got), `\u00e9`) {
		t.Error("canonical bytes contain \\u escape for 'é'; ensure_ascii drift")
	}
}

// goldenPayload is the reference input for the canonical-form snapshot
// test. Covers: nested object inside an array, multiple top-level keys
// requiring sort, non-ASCII, HTML-unsafe chars, null, bool, int.
func goldenPayload() map[string]any {
	return map[string]any{
		"dns_cache_entries": []any{
			map[string]any{"name": "example.com", "type": "A", "ttl": 300},
			map[string]any{"name": "api.github.com", "type": "A", "ttl": 60},
		},
		"failover_resolver": nil,
		"hostname":          "sheptech-win-01",
		"policy":            "a&b",
		"resolver":          "1.1.1.1",
		"site_note":         "café",
		"tcp_enabled":       true,
	}
}

// canonicalGolden is the expected canonical-form output for goldenPayload.
// Array element order is preserved (JSON arrays are ordered); object keys
// are sorted at every nesting level; compact separators; no HTML escape;
// non-ASCII as raw UTF-8. If this ever drifts, the rollback validator
// (task #14) on the backend will compute different hashes for the same
// logical payload — break this test LOUD, do not paper over.
const canonicalGolden = `{"dns_cache_entries":[{"name":"example.com","ttl":300,"type":"A"},{"name":"api.github.com","ttl":60,"type":"A"}],"failover_resolver":null,"hostname":"sheptech-win-01","policy":"a&b","resolver":"1.1.1.1","site_note":"café","tcp_enabled":true}`

func TestCanonicalGoldenFixture(t *testing.T) {
	got, err := canonicalMarshal(goldenPayload())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(got) != canonicalGolden {
		t.Errorf("canonical bytes drift:\n  got  = %s\n  want = %s", got, canonicalGolden)
	}

	// Sanity-check the hash is 64 hex chars of the golden bytes.
	sum := sha256.Sum256([]byte(canonicalGolden))
	wantHash := hex.EncodeToString(sum[:])
	if len(wantHash) != 64 {
		t.Fatalf("wantHash length = %d, want 64", len(wantHash))
	}
	if got := sha256Hex([]byte(canonicalGolden)); got != wantHash {
		t.Errorf("sha256Hex drift: got %s, want %s", got, wantHash)
	}
}

func TestCaptureWireShapeOmitsEmptyOptionals(t *testing.T) {
	// DeviceID and CaptureSource are nullable on the backend. When
	// unset on the agent, they must serialize as missing (omitempty)
	// rather than "" so Pydantic treats them as None.
	req := validRequest()
	got, err := RunAt(context.Background(), req, okCollector(map[string]any{"ok": true}), fixedTime)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	s := string(b)
	if strings.Contains(s, `"device_id"`) {
		t.Errorf("device_id should be omitted when empty: %s", s)
	}
	if strings.Contains(s, `"capture_source"`) {
		t.Errorf("capture_source should be omitted when empty: %s", s)
	}
	if strings.Contains(s, `"error_message"`) {
		t.Errorf("error_message should be omitted on success: %s", s)
	}
	// Required fields must always be present.
	for _, field := range []string{
		`"action_execution_id"`, `"agent_id"`, `"tenant_id"`,
		`"capture_type"`, `"captured_at"`, `"state_payload"`,
		`"payload_hash"`, `"capture_method"`, `"capture_succeeded"`,
	} {
		if !strings.Contains(s, field) {
			t.Errorf("required field %s missing: %s", field, s)
		}
	}
}
