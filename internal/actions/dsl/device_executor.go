// Package dsl — device executor (Sprint D / Task #2).
//
// This file lives alongside the existing shell executor (executor.go) and
// adds a parallel dispatch path for device-targeting KAL actions: actions
// whose ``transport: ssh`` field tells the executor to open an SSH
// connection to a network device rather than fork a local binary.
//
// Action shape recognized here (formalized in D3):
//
//   transport: ssh
//   executors:
//     cisco_iosxe:
//       pre_commands: ["terminal length 0"]
//       command: "show running-config"
//     arista_eos:
//       pre_commands: ["terminal length 0"]
//       command: "show running-config"
//     juniper_junos:
//       command: "show configuration"
//
// At runtime the executor:
//   1. Reads action.transport — must be "ssh".
//   2. Looks up executors[device.Vendor] — this is the vendor-specific
//      command set. Falls through if the action doesn't cover this vendor.
//   3. Calls the CredentialFetcher to issue an ssh_key bundle for the
//      ActionExecution (action_id parameter is the ActionExecution UUID,
//      same one credentials/manager.go consumes).
//   4. Dials the device over SSH, runs pre_commands then either
//      ``command`` (single) or ``commands`` (sequence), captures output.
//   5. Returns an Outcome with stdout = device output, exit_code = 0 on
//      success.
//
// The shell-mode executor is untouched. D3 will consolidate behind a
// transport-dispatch abstraction once we have a few more transports.
package dsl

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/shepherdtech/aione-agent/internal/transport/sshclient"
)

// CredentialFetcher is the contract the device executor uses to obtain
// short-lived per-action credentials. Implemented by
// ``internal/credentials/Manager`` in production; tests substitute a fake.
//
// The interface is intentionally narrow so the dsl package doesn't import
// the credentials package — keeps the dependency arrow pointing the right
// way.
type CredentialFetcher interface {
	Fetch(ctx context.Context, actionID, credType string) (DeviceCredential, error)
}

// DeviceCredential mirrors ``credentials.ActionCred`` but lives here so
// dsl doesn't import credentials. The shapes must stay compatible —
// adapter at the call site converts between them.
type DeviceCredential struct {
	Type      string
	Principal string
	Secret    string // PEM-encoded private key when Type is "ssh_key"
	Attrs     map[string]string
	ExpiresAt time.Time
}

// DeviceTarget carries the device identity + addressing that the action
// needs to reach the box. The caller (typically the dispatcher) builds
// this from the ActionExecution row's device_id lookup.
type DeviceTarget struct {
	// ActionExecutionID is the UUID the platform expects in
	// /v1/credentials/issue requests — passes straight through to
	// CredentialFetcher.Fetch as the action_id.
	ActionExecutionID string

	// Vendor is the normalized device-type slug used to pick the right
	// vendor-specific block from action.executors.
	// Examples: "cisco_iosxe", "cisco_nxos", "arista_eos", "juniper_junos".
	Vendor string

	// Host is the management IP or hostname to dial.
	Host string

	// Port is the SSH port. Zero defaults to 22.
	Port int
}

// RunDeviceAction is the SSH-transport sibling of Run. Caller provides the
// loaded action, parameter map, target device, and a credential fetcher.
//
// Returns the same Outcome shape as Run so dispatch layers above can
// treat shell and device actions uniformly. Non-recoverable validation
// errors (action doesn't declare SSH, vendor not supported, missing
// credentials) come back through the error return; per-command failures
// land in Outcome.Err with an Outcome record.
func RunDeviceAction(
	ctx context.Context,
	action *KALAction,
	params map[string]interface{},
	target DeviceTarget,
	fetcher CredentialFetcher,
) (Outcome, error) {
	startedAt := time.Now().UTC()

	// 1. Parameter schema validation (same as shell path).
	if err := validateParams(action, params); err != nil {
		return Outcome{
			StartedAt: startedAt,
			EndedAt:   time.Now().UTC(),
			Err:       fmt.Sprintf("parameter validation: %s", err),
		}, fmt.Errorf("dsl: parameter validation: %w", err)
	}

	// 2. Confirm this action is actually SSH-transport.
	transport, _ := action.Raw["transport"].(string)
	if transport != "ssh" {
		return Outcome{StartedAt: startedAt, EndedAt: time.Now().UTC()},
			fmt.Errorf("dsl: action %q has transport=%q, not 'ssh'", action.ID, transport)
	}

	// 3. Pick the vendor-specific executor block. Sprint D / Task #3
	//    formalized the schema split: shell actions use `executors:`
	//    keyed by OS, device actions use `device_executors:` keyed by
	//    vendor. Read the latter for SSH/NETCONF/SNMP/cloud_api transports.
	executors, ok := action.Raw["device_executors"].(map[string]interface{})
	if !ok {
		return Outcome{StartedAt: startedAt, EndedAt: time.Now().UTC()},
			fmt.Errorf("dsl: action %q has no device_executors block", action.ID)
	}
	if target.Vendor == "" {
		return Outcome{StartedAt: startedAt, EndedAt: time.Now().UTC()},
			errors.New("dsl: DeviceTarget.Vendor is required for SSH actions")
	}
	vendorBlock, ok := executors[target.Vendor].(map[string]interface{})
	if !ok {
		return Outcome{StartedAt: startedAt, EndedAt: time.Now().UTC()},
			fmt.Errorf("dsl: action %q has no device executor for vendor %q (have %v)",
				action.ID, target.Vendor, sortedKeys(executors))
	}

	// 4. Pull commands (single ``command`` or list ``commands``) and
	//    pre_commands. Expand parameter interpolation before running.
	preCommands, err := expandStringList(vendorBlock["pre_commands"], params)
	if err != nil {
		return Outcome{StartedAt: startedAt, EndedAt: time.Now().UTC()},
			fmt.Errorf("dsl: pre_commands expansion: %w", err)
	}
	commands, err := readCommands(vendorBlock, params)
	if err != nil {
		return Outcome{StartedAt: startedAt, EndedAt: time.Now().UTC()},
			fmt.Errorf("dsl: commands expansion: %w", err)
	}
	if len(commands) == 0 {
		return Outcome{StartedAt: startedAt, EndedAt: time.Now().UTC()},
			fmt.Errorf("dsl: action %q vendor %q has no command(s)", action.ID, target.Vendor)
	}

	// 5. Fetch credentials.
	if fetcher == nil {
		return Outcome{StartedAt: startedAt, EndedAt: time.Now().UTC()},
			errors.New("dsl: CredentialFetcher is required")
	}
	if target.ActionExecutionID == "" {
		return Outcome{StartedAt: startedAt, EndedAt: time.Now().UTC()},
			errors.New("dsl: DeviceTarget.ActionExecutionID is required")
	}
	cred, err := fetcher.Fetch(ctx, target.ActionExecutionID, "ssh_key")
	if err != nil {
		return Outcome{
			StartedAt: startedAt,
			EndedAt:   time.Now().UTC(),
			Err:       fmt.Sprintf("credential fetch: %s", err),
		}, fmt.Errorf("dsl: credential fetch: %w", err)
	}
	if cred.Type != "ssh_key" {
		return Outcome{StartedAt: startedAt, EndedAt: time.Now().UTC()},
			fmt.Errorf("dsl: expected ssh_key credential, got %q", cred.Type)
	}

	// Resolve host: caller-provided target.Host wins; fall back to
	// cred.Attrs["host"] which the vault may also carry. Same for port.
	host := target.Host
	if host == "" {
		host = cred.Attrs["host"]
	}
	if host == "" {
		return Outcome{StartedAt: startedAt, EndedAt: time.Now().UTC()},
			errors.New("dsl: no host on DeviceTarget or credential attrs")
	}
	port := target.Port
	if port == 0 {
		if p, ok := atoiSafe(cred.Attrs["port"]); ok {
			port = p
		}
	}

	// 6. Bound the whole device operation by validators.post_execution.timeout_seconds.
	timeout := readPostExecTimeout(action.Raw)
	devCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cli, err := sshclient.Connect(devCtx, sshclient.Config{
		Host:          host,
		Port:          port,
		User:          cred.Principal,
		PrivateKeyPEM: []byte(cred.Secret),
		PreCommands:   preCommands,
	})
	if err != nil {
		return Outcome{
			StartedAt: startedAt,
			EndedAt:   time.Now().UTC(),
			Err:       fmt.Sprintf("ssh connect: %s", err),
		}, nil
	}
	defer cli.Close()

	out := Outcome{StartedAt: startedAt, ExecutorUsed: "ssh:" + target.Vendor}

	// 7. Run the user's commands.
	stdout, runErr := cli.RunSequence(devCtx, commands)
	out.Stdout = stdout
	out.EndedAt = time.Now().UTC()

	if runErr != nil {
		out.ExitCode = -1
		out.Err = runErr.Error()
		out.AttemptErrs = append(out.AttemptErrs, runErr.Error())
		// Distinguish timeout vs. other errors for downstream classification.
		if errors.Is(devCtx.Err(), context.DeadlineExceeded) {
			out.TimedOut = true
		}
		return out, nil
	}

	// 8. Validator: shell-style exit_code check doesn't apply directly to
	// SSH multi-command runs (each command has its own exit). For now,
	// success = "all commands ran without error." Per-command exit-code
	// gating is a D3 enhancement.
	out.ExitCode = 0
	out.Success = true
	return out, nil
}

// readCommands extracts the runnable command(s) from a vendor-block.
// Supports either ``command: "show ..."`` (single) or ``commands: [...]``
// (sequence). At most one may be set; both empty is an error caught
// upstream by the empty-len(commands) check.
func readCommands(vendorBlock map[string]interface{}, params map[string]interface{}) ([]string, error) {
	if single, ok := vendorBlock["command"].(string); ok && single != "" {
		expanded, err := expandOneArg(single, params)
		if err != nil {
			return nil, err
		}
		return []string{expanded}, nil
	}
	if multi, ok := vendorBlock["commands"]; ok {
		return expandStringList(multi, params)
	}
	return nil, nil
}

// expandStringList turns a raw YAML []interface{} of strings into a
// concrete []string with parameter interpolation applied. nil input
// returns nil (caller's responsibility to decide whether that's OK).
func expandStringList(raw interface{}, params map[string]interface{}) ([]string, error) {
	if raw == nil {
		return nil, nil
	}
	list, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("expected list, got %T", raw)
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		s, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("expected string in list, got %T", item)
		}
		expanded, err := expandOneArg(s, params)
		if err != nil {
			return nil, err
		}
		out = append(out, expanded)
	}
	return out, nil
}

// atoiSafe parses an integer from a string without bringing in strconv
// just for one call site. Returns (0, false) on any parse failure.
func atoiSafe(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}
