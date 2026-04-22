package capture

import (
	"context"
	"fmt"
	"time"
)

// Collector gathers a single state snapshot. Implementations are
// action-specific (e.g. a flush_dns_cache pre-collector runs
// "ipconfig /displaydns" on Windows and "resolvectl statistics" on
// Linux, shaping the output into a map).
//
// A Collector returning a non-nil error is treated as a capture failure,
// NOT as a terminal error of the outer action. Run(...) wraps the
// failure into a Capture with CaptureSucceeded=false, an empty payload
// ({}), and the error surfaced in ErrorMessage. That matches the
// backend's intent: a "pre failed" row is disambiguated from "pre never
// ran" exactly by the existence of a row with capture_succeeded=false.
type Collector interface {
	Collect(ctx context.Context) (map[string]any, error)
}

// CollectorFunc is a function adapter so callers can pass a closure
// without defining a named type. Same pattern as http.HandlerFunc.
type CollectorFunc func(ctx context.Context) (map[string]any, error)

// Collect implements Collector.
func (f CollectorFunc) Collect(ctx context.Context) (map[string]any, error) {
	return f(ctx)
}

// Request is the caller-supplied context for a single Run call. The
// identifiers travel with the capture on the wire so the backend can
// stitch it to the right execution / tenant / device. Required fields
// are validated at the top of Run and returned as an error before the
// collector is invoked — a bad Request is a caller bug, not a capture
// failure.
type Request struct {
	// ActionExecutionID is the backend action_executions.id this capture
	// belongs to. REQUIRED — the unique (action_execution_id, capture_type)
	// constraint on the backend fails loud if this is empty.
	ActionExecutionID string

	// AgentID is the agent_registrations.id of the agent producing the
	// capture. REQUIRED.
	AgentID string

	// TenantID is the tenants.id this capture is scoped to. REQUIRED —
	// the backend column is NOT NULL and the RLS policy filters on it.
	TenantID string

	// DeviceID is the devices.id if the capture pertains to a specific
	// managed device (as opposed to the agent host itself). Optional;
	// empty string is interpreted as "no device" and serialized as a
	// JSON null.
	DeviceID string

	// CaptureType MUST be one of CaptureTypePre / CaptureTypePost.
	// REQUIRED.
	CaptureType string

	// CaptureMethod labels how the payload was collected (shell/wmi/
	// snmp/file/syscall/...). REQUIRED; max 32 chars on the backend.
	CaptureMethod string

	// CaptureSource is a free-form label identifying the specific source
	// within the method (e.g. the shell command that produced the
	// output, the OID that was walked, the file path that was read).
	// Optional; max 256 chars on the backend.
	CaptureSource string
}

// Capture is the wire-shape value POSTed to the backend's state_captures
// endpoint. Field tags match the column names in migration 019. Nullable
// columns use pointer + omitempty so empty values round-trip as JSON
// null rather than "" / 0.
type Capture struct {
	ActionExecutionID string         `json:"action_execution_id"`
	AgentID           string         `json:"agent_id"`
	TenantID          string         `json:"tenant_id"`
	DeviceID          *string        `json:"device_id,omitempty"`
	CaptureType       string         `json:"capture_type"`
	CapturedAt        time.Time      `json:"captured_at"`
	StatePayload      map[string]any `json:"state_payload"`
	PayloadHash       string         `json:"payload_hash"`
	CaptureMethod     string         `json:"capture_method"`
	CaptureSource     *string        `json:"capture_source,omitempty"`
	CaptureSucceeded  bool           `json:"capture_succeeded"`
	ErrorMessage      *string        `json:"error_message,omitempty"`
}

// validate checks required fields up front so a caller bug is surfaced
// before we spend cycles running a collector. CaptureType is checked
// against the backend CHECK constraint so a typo fails at the agent
// rather than as a 422 from the backend.
func (r Request) validate() error {
	if r.ActionExecutionID == "" {
		return fmt.Errorf("ActionExecutionID is required")
	}
	if r.AgentID == "" {
		return fmt.Errorf("AgentID is required")
	}
	if r.TenantID == "" {
		return fmt.Errorf("TenantID is required")
	}
	if r.CaptureMethod == "" {
		return fmt.Errorf("CaptureMethod is required")
	}
	if r.CaptureType != CaptureTypePre && r.CaptureType != CaptureTypePost {
		return fmt.Errorf(
			"CaptureType must be %q or %q, got %q",
			CaptureTypePre, CaptureTypePost, r.CaptureType,
		)
	}
	return nil
}

// now is indirected so tests can inject a fixed clock without a global
// monkey-patch. Production callers use Run (which uses time.Now via this
// var); tests use RunAt for an explicit timestamp.
var now = time.Now

// Run executes the collector and returns a wire-ready Capture. It never
// panics: any collector error is captured into the returned Capture with
// CaptureSucceeded=false. An error return from Run itself means the
// Request was invalid — no Capture value should be posted.
//
// The returned error (when non-nil on a successful call) is the
// collector's error, returned alongside a well-formed failure Capture
// so the caller can log it in addition to posting the capture row.
func Run(ctx context.Context, req Request, collector Collector) (Capture, error) {
	if err := req.validate(); err != nil {
		return Capture{}, err
	}
	return runAt(ctx, req, collector, now())
}

// RunAt is Run with an explicit captured_at timestamp. Exposed for
// tests; production code should use Run.
func RunAt(ctx context.Context, req Request, collector Collector, at time.Time) (Capture, error) {
	if err := req.validate(); err != nil {
		return Capture{}, err
	}
	return runAt(ctx, req, collector, at)
}

func runAt(ctx context.Context, req Request, collector Collector, at time.Time) (Capture, error) {
	out := Capture{
		ActionExecutionID: req.ActionExecutionID,
		AgentID:           req.AgentID,
		TenantID:          req.TenantID,
		CaptureType:       req.CaptureType,
		CapturedAt:        at.UTC(),
		CaptureMethod:     req.CaptureMethod,
	}
	if req.DeviceID != "" {
		d := req.DeviceID
		out.DeviceID = &d
	}
	if req.CaptureSource != "" {
		s := req.CaptureSource
		out.CaptureSource = &s
	}

	payload, err := collector.Collect(ctx)
	if err != nil {
		// Failure capture: empty payload ({}, still a stable hash) +
		// the error surfaced in ErrorMessage. Row is still posted so
		// the backend can disambiguate "pre failed" from "pre never
		// fired". Canonicalizing {} cannot fail in practice; the
		// error return is discarded for that reason.
		out.StatePayload = map[string]any{}
		out.CaptureSucceeded = false
		msg := err.Error()
		out.ErrorMessage = &msg
		hashBytes, _ := canonicalMarshal(out.StatePayload)
		out.PayloadHash = sha256Hex(hashBytes)
		return out, err
	}

	if payload == nil {
		payload = map[string]any{}
	}

	hashBytes, hashErr := canonicalMarshal(payload)
	if hashErr != nil {
		// Payload doesn't canonicalize (unsupported type in the map,
		// e.g. a channel). Collector contract is violated — treat as a
		// failure capture so the rollback pipeline sees it rather than
		// silently dropping the row.
		out.StatePayload = map[string]any{}
		out.CaptureSucceeded = false
		msg := fmt.Sprintf("canonical marshal: %s", hashErr.Error())
		out.ErrorMessage = &msg
		empty, _ := canonicalMarshal(nil)
		out.PayloadHash = sha256Hex(empty)
		return out, hashErr
	}
	out.StatePayload = payload
	out.CaptureSucceeded = true
	out.PayloadHash = sha256Hex(hashBytes)
	return out, nil
}
