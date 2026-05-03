// Rollback synthesis runner (Sprint follow-up S2.b.2 phase 2b).
//
// Sits next to ``device_executor.go``. The two share most of their
// shape — open a persistent shell, run a YAML-declared command list
// — but they differ in three meaningful ways:
//
//  1. Source of commands. ``RunDeviceAction`` reads
//     ``device_executors.<vendor>`` (the action body); ``RunRollback``
//     reads ``rollback.spec.device_executors.<vendor>`` (the
//     synthesis body, declared by the same YAML next to the rollback
//     possibility flag).
//
//  2. Credential identity. ``RunDeviceAction`` resolves credentials
//     using ``DeviceTarget.ActionExecutionID`` (== command_id ==
//     ``action_executions.id`` on the backend). Rollback commands
//     have ``CommandID = RollbackAttempt.id`` which the platform's
//     credential issuer doesn't recognize, so the rollback runner
//     uses ``cmd.ExecutionID`` (the parent execution's id) instead.
//
//  3. Templating surface. Rollback synthesis commands need to
//     reference pre-capture state — e.g. ``description
//     {{pre_state.description}}`` to restore a description to its
//     captured value. The runner flattens ``cmd.PreState`` into
//     the params map under ``pre_state.<key>`` so the existing
//     ``expandOneArg`` works without specialization.
//
// State capture for rollbacks
// ---------------------------
// A successful rollback's outcome is the *device state*, not a
// stdout. After the synthesis runs, the runner emits a
// ``capture_type='rollback_post'`` capture if the action's YAML
// has a structured ``state_capture.post`` block — this is what the
// backend's stage-5 rollback validator (``rollback_validator.py``)
// reads to confirm the device landed back at the pre-state hash.
// When the YAML's state_capture is sentinel (``stateless``), no
// rollback_post capture is shipped — we have nothing to read.

package dsl

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/shepherdtech/aione-agent/internal/capture"
	"github.com/shepherdtech/aione-agent/internal/transport/sshclient"
)

// RollbackTarget carries the inputs RunRollback needs that aren't
// in the action's KAL YAML. Same shape as DeviceTarget except for
// the rollback-specific identity bookkeeping.
//
// ExecutionID is what the runner passes to CredentialFetcher.Fetch
// (the platform's credential issuer indexes on action_executions).
// CommandID is the RollbackAttempt.id and is propagated onto the
// rollback_post capture so the backend can stitch it back to the
// attempt row.
type RollbackTarget struct {
	CommandID    string // RollbackAttempt.id (only used for logging)
	ExecutionID  string // ActionExecution.id (used as cred fetch id)
	TenantID     string
	AgentID      string
	DeviceID     string
	Vendor       string
	Host         string
	Port         int
	PreState     map[string]interface{}
	OriginalParams map[string]interface{} // params from the original action

	// CredentialRef + LocalVault mirror the same-named fields on
	// DeviceTarget (Sprint follow-up Bucket A.2 / HIGH#2 from the
	// post-S4 code review). When CredentialRef begins with
	// ``local://`` the runner resolves it through LocalVault rather
	// than calling the platform fetcher — same V1.local invariant the
	// action body honors. Without this branch, rollbacks of a
	// local-vault-backed device would 404 at the platform issuer.
	CredentialRef string
	LocalVault    VaultBackend
}

// RollbackOutcome is the runner's return shape — narrower than
// device-action Outcome since rollback success is binary on the
// agent side. The caller maps this to its Result envelope.
type RollbackOutcome struct {
	Success     bool
	Stdout      string
	Err         string
	StartedAt   time.Time
	EndedAt     time.Time
	TimedOut    bool
	PostCapture *capture.Capture // nil when no rollback_post was emitted
}

// RunRollback opens a persistent shell, runs the action's
// rollback.spec.device_executors.<vendor> commands templated against
// the original params + cmd.PreState, and emits a rollback_post
// capture when the action's YAML state_capture.post block is
// structured.
//
// Errors at the validation layer (action not found, vendor not
// supported, no rollback declared) come back through the outcome's
// Err field, not the function's error return. The runner only
// returns a non-nil error for caller bugs — nil action, missing
// fetcher, missing required identity.
func RunRollback(
	ctx context.Context,
	action *KALAction,
	target RollbackTarget,
	fetcher CredentialFetcher,
	sink CaptureSink,
) (RollbackOutcome, error) {
	startedAt := time.Now().UTC()
	if action == nil {
		return RollbackOutcome{}, errors.New("dsl: RunRollback nil action")
	}
	if fetcher == nil {
		return RollbackOutcome{}, errors.New("dsl: RunRollback requires CredentialFetcher")
	}
	if target.ExecutionID == "" {
		return RollbackOutcome{}, errors.New("dsl: RunRollback requires ExecutionID")
	}
	if target.Vendor == "" {
		return RollbackOutcome{}, errors.New("dsl: RunRollback requires Vendor")
	}
	if sink == nil {
		sink = noopSink{}
	}

	// 1. Pull rollback.spec.device_executors.<vendor> from action.Raw.
	rollback, ok := action.Raw["rollback"].(map[string]interface{})
	if !ok {
		return failOutcome(startedAt, "action declares no rollback block"), nil
	}
	if possible, _ := rollback["possible"].(bool); !possible {
		return failOutcome(startedAt, "action.rollback.possible=false; nothing to synthesize"), nil
	}
	spec, _ := rollback["spec"].(map[string]interface{})
	if spec == nil {
		return failOutcome(startedAt, "action.rollback.spec is empty"), nil
	}
	devExecs, _ := spec["device_executors"].(map[string]interface{})
	if devExecs == nil {
		return failOutcome(startedAt, "action.rollback.spec has no device_executors"), nil
	}
	vendorBlock, _ := devExecs[target.Vendor].(map[string]interface{})
	if vendorBlock == nil {
		return failOutcome(startedAt,
			fmt.Sprintf("action.rollback.spec has no device_executors.%s", target.Vendor),
		), nil
	}

	// 2. Build the templating params: original action params merged
	// with flattened pre_state under the ``pre_state.`` prefix. The
	// regex in loader.go was extended to allow dotted names so
	// ``{{pre_state.description}}`` lookups land on the right entry.
	//
	// We also expose each pre_state value under its bare key as a
	// fallback. This lets state_capture's existing commands (which
	// were authored against the action's params, like
	// ``{{interface_name}}``) resolve cleanly during rollback —
	// pre_state entries are the canonical fields the action's
	// parser produces, and most action params share names with those
	// fields. OriginalParams (when populated by a future wire-format
	// extension) wins over the pre_state fallback so a real param
	// value never gets silently shadowed.
	params := make(map[string]interface{}, len(target.OriginalParams)+2*len(target.PreState))
	for k, v := range target.PreState {
		params["pre_state."+k] = v
		params[k] = v // bare-key fallback
	}
	for k, v := range target.OriginalParams {
		params[k] = v // overwrites the pre_state fallback when present
	}

	preCommands, err := expandStringList(vendorBlock["pre_commands"], params)
	if err != nil {
		return failOutcome(startedAt,
			fmt.Sprintf("rollback pre_commands expansion: %s", err),
		), nil
	}
	commands, err := readCommands(vendorBlock, params)
	if err != nil {
		return failOutcome(startedAt,
			fmt.Sprintf("rollback commands expansion: %s", err),
		), nil
	}
	if len(commands) == 0 {
		return failOutcome(startedAt,
			"rollback synthesis has no command(s)",
		), nil
	}

	// 3. Fetch credentials. Use ExecutionID (parent action_execution)
	// — the credential issuer indexes on action_executions, not
	// rollback_attempts.
	//
	// Bucket A.2 / HIGH#2: route through resolveCredential so a
	// local://-backed device's rollback hits the agent's own vault
	// (the V1.local invariant). Pre-A.2 the rollback unconditionally
	// called the platform fetcher, which 404s for local:// refs.
	hintedCredType, _ := action.Raw["cred_type"].(string)
	cred, err := resolveCredential(ctx, credResolveInput{
		LogActionID:   target.CommandID,
		FetchID:       target.ExecutionID,
		CredentialRef: target.CredentialRef,
		HintedType:    hintedCredType,
		LocalVault:    target.LocalVault,
		Fetcher:       fetcher,
	})
	if err != nil {
		return failOutcome(startedAt,
			fmt.Sprintf("rollback credential fetch: %s", err),
		), nil
	}

	host := target.Host
	if host == "" {
		host = cred.Attrs["host"]
	}
	if host == "" {
		return failOutcome(startedAt,
			"rollback has no host on target or credential attrs",
		), nil
	}
	port := target.Port
	if port == 0 {
		if p, ok := atoiSafe(cred.Attrs["port"]); ok {
			port = p
		}
	}

	// 4. Bound the rollback by the action's post_execution timeout
	// — same envelope as the original action since the device is
	// the same and the synthesis is approximately the same scale.
	timeout := readPostExecTimeout(action.Raw)
	devCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	sshCfg := sshclient.Config{
		Host: host,
		Port: port,
		User: cred.Principal,
	}
	switch sshclient.AuthMethod(cred.Type) {
	case sshclient.AuthMethodPrivateKey:
		sshCfg.AuthMethod = sshclient.AuthMethodPrivateKey
		sshCfg.PrivateKeyPEM = []byte(cred.Secret)
	case sshclient.AuthMethodPassword, sshclient.AuthMethodSSHPassword:
		sshCfg.AuthMethod = sshclient.AuthMethod(cred.Type)
		sshCfg.Password = cred.Secret
	default:
		return failOutcome(startedAt,
			fmt.Sprintf("rollback unsupported credential type %q", cred.Type),
		), nil
	}

	shellCfg, err := sshclient.ShellConfigFor(target.Vendor)
	if err != nil {
		return failOutcome(startedAt,
			fmt.Sprintf("rollback shell config: %s", err),
		), nil
	}

	log.Info().
		Str("command_id", target.CommandID).
		Str("execution_id", target.ExecutionID).
		Str("action_id_slug", action.ID).
		Str("vendor", target.Vendor).
		Int("synthesis_pre_command_count", len(preCommands)).
		Int("synthesis_command_count", len(commands)).
		Msg("rollback: dialing device for synthesis")

	cli, err := sshclient.Connect(devCtx, sshCfg)
	if err != nil {
		out := failOutcome(startedAt, fmt.Sprintf("rollback ssh connect: %s", err))
		if errors.Is(devCtx.Err(), context.DeadlineExceeded) {
			out.TimedOut = true
		}
		return out, nil
	}
	defer cli.Close()

	shell, err := cli.NewShell(devCtx, shellCfg)
	if err != nil {
		out := failOutcome(startedAt, fmt.Sprintf("rollback open shell: %s", err))
		if errors.Is(devCtx.Err(), context.DeadlineExceeded) {
			out.TimedOut = true
		}
		return out, nil
	}
	defer shell.Close()

	// 5. Run pre_commands then synthesis commands in the persistent
	// shell. Same patterns as RunDeviceAction; same ``! ===== %s
	// =====`` markers around each user command for stdout legibility.
	for _, pre := range preCommands {
		if _, err := shell.Send(devCtx, pre); err != nil {
			out := failOutcome(startedAt,
				fmt.Sprintf("rollback pre-command %q: %s", pre, err),
			)
			if errors.Is(devCtx.Err(), context.DeadlineExceeded) {
				out.TimedOut = true
			}
			return out, nil
		}
	}

	var combined strings.Builder
	for i, cmd := range commands {
		if i > 0 {
			combined.WriteString("\n")
		}
		fmt.Fprintf(&combined, "! ===== %s =====\n", cmd)
		cmdOut, err := shell.Send(devCtx, cmd)
		if err != nil {
			out := RollbackOutcome{
				Success:   false,
				Stdout:    combined.String(),
				Err:       err.Error(),
				StartedAt: startedAt,
				EndedAt:   time.Now().UTC(),
			}
			if errors.Is(devCtx.Err(), context.DeadlineExceeded) {
				out.TimedOut = true
			}
			return out, nil
		}
		combined.WriteString(cmdOut)
	}

	endedAt := time.Now().UTC()
	out := RollbackOutcome{
		Success:   true,
		Stdout:    combined.String(),
		StartedAt: startedAt,
		EndedAt:   endedAt,
	}

	// 6. rollback_post capture — only when the action's YAML has a
	// structured state_capture.post block. The backend's stage-5
	// rollback validator reads this row to confirm the device
	// landed back at the pre-state hash.
	captureSpec, capErr := readStateCaptureSpec(action.Raw, params)
	if capErr == nil && captureSpec.Post.structured() {
		// Build a DeviceTarget-shaped identity for the capture
		// runShellCapture helper; reuse the same wiring the action
		// uses so the row's tenant/agent/device IDs match.
		captureTarget := DeviceTarget{
			ActionExecutionID: target.ExecutionID,
			AgentID:           target.AgentID,
			TenantID:          target.TenantID,
			DeviceID:          target.DeviceID,
			Vendor:            target.Vendor,
		}
		rbCap, capRunErr := runShellCapture(
			devCtx, shell, captureSpec.Post, capture.CaptureTypeRollbackPost, captureTarget,
		)
		if postErr := sink.Post(devCtx, rbCap); postErr != nil {
			log.Warn().Err(postErr).
				Str("execution_id", target.ExecutionID).
				Msg("rollback: posting rollback_post capture failed (continuing)")
		}
		if capRunErr != nil {
			log.Warn().Err(capRunErr).
				Str("execution_id", target.ExecutionID).
				Msg("rollback: rollback_post collector failed")
		}
		out.PostCapture = &rbCap
	}

	return out, nil
}

// failOutcome is a tiny constructor that pre-stamps the timestamps
// on a failure outcome so the call sites stay compact.
func failOutcome(startedAt time.Time, msg string) RollbackOutcome {
	return RollbackOutcome{
		Success:   false,
		Err:       msg,
		StartedAt: startedAt,
		EndedAt:   time.Now().UTC(),
	}
}
