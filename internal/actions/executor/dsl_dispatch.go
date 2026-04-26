package executor

import (
	"context"
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/shepherdtech/aione-agent/internal/actions/dsl"
)

// dslRegistry returns the active KAL action registry. Preference order:
//
//  1. Live BE-pull (e.dslClient.Current()) — set up in service.go and
//     refreshed every 5 min. Lets the agent pick up action-library updates
//     without a binary rebuild (task #28).
//  2. Embedded build-time snapshot — lazy-loaded once. Bootstrap fallback
//     for first-run agents and offline mode.
//
// The dsl package's own tests gate that the embedded registry is well-formed
// at build time, so a load failure here is a hard infrastructure bug — log
// loudly and let the dispatch fall back to the hand-coded implementations.
func (e *Executor) dslRegistry() (dsl.Registry, error) {
	// Preference 1: live BE-pull registry, if a client is wired and has
	// successfully fetched at least once.
	if e.dslClient != nil {
		if reg := e.dslClient.Current(); reg != nil {
			return reg, nil
		}
	}

	// Preference 2: embedded snapshot. Lazy-loaded on first request,
	// then cached for the process lifetime.
	e.dslOnce.Do(func() {
		e.dslReg, e.dslErr = dsl.LoadEmbeddedRegistry()
		if e.dslErr != nil {
			log.Error().Err(e.dslErr).Msg("dsl: embedded registry failed to load — falling back to hand-coded action implementations")
		} else {
			log.Info().Int("actions", len(e.dslReg)).Msg("dsl: embedded registry loaded")
		}
	})
	return e.dslReg, e.dslErr
}

// dslHasAction reports whether the action ID is present in the DSL
// registry. Used by the dispatch switch to route a request through
// the generic DSL executor instead of the hand-coded path.
func (e *Executor) dslHasAction(actionID string) bool {
	reg, err := e.dslRegistry()
	if err != nil || reg == nil {
		return false
	}
	_, ok := reg[actionID]
	return ok
}

// runDSLAction dispatches a KAL action through the generic DSL executor.
// Maps the DSL Outcome to the (output, error) shape the rest of the
// dispatch package uses.
//
// Sprint D / Task #2.5: transport-aware. For shell actions (transport
// absent or "shell"), routes through dsl.Run as before. For network-
// device actions (transport=ssh today; netconf/snmp/cloud_api are
// reserved), routes through dsl.RunDeviceAction with a DeviceTarget
// built from the action's off-wire fields (DeviceVendor / DeviceHost /
// DevicePort / CommandID, all populated by the dispatcher from the
// outer AgentCommand envelope) and the executor's CredentialFetcher.
//
// Param-type conversion: existing executor methods take params as
// map[string]string (the agent-side dispatch shape — see
// internal/dispatcher/dispatcher.go's translateAction). The DSL
// executor takes map[string]interface{} so it can validate against the
// per-action JSON Schema. We coerce strings → interface{} on the way in.
// Schema-declared types (number, boolean) are NOT supported through
// this path until the dispatcher itself starts preserving param types
// from the backend command frame.
func (e *Executor) runDSLAction(
	ctx context.Context,
	action *dsl.KALAction,
	params map[string]string,
	target dsl.DeviceTarget,
) (string, error) {
	// Coerce string-keyed params to the interface{} shape Run expects.
	// nil → empty map (Run's validator special-cases nil too, but being
	// explicit here makes the conversion intent obvious).
	p := make(map[string]interface{}, len(params))
	for k, v := range params {
		p[k] = v
	}

	// Branch on transport. The schema (Sprint D / Task #3) constrains
	// transport to {shell, ssh, netconf, snmp, cloud_api}; we accept
	// any of the non-shell values via the device-action path so that
	// new transports can author YAML before the agent driver lands —
	// the load-time error surfaces clearly.
	transport, _ := action.Raw["transport"].(string)
	var outcome dsl.Outcome
	var err error

	if transport == "" || transport == "shell" {
		outcome, err = dsl.Run(ctx, action, p)
	} else {
		if e.credFetcher == nil {
			return "", fmt.Errorf(
				"dsl[%s]: transport=%q requires a credential fetcher; "+
					"executor not wired with SetCredentialFetcher",
				action.ID, transport,
			)
		}
		// Stamp the ActionExecutionID from the dispatch envelope's
		// CommandID. The backend's /v1/credentials/issue handler
		// expects this to match an ActionExecution row in the running
		// state — which is exactly what command_id is.
		outcome, err = dsl.RunDeviceAction(ctx, action, p, target, e.credFetcher)
	}

	if err != nil {
		return "", err
	}

	if !outcome.Success {
		// Surface the executor that produced the failure plus its
		// captured stderr/stdout — matches the diagnostic shape the
		// hand-coded implementations produced (combined output in the
		// error chain so operator UI shows what went wrong).
		combined := strings.TrimSpace(outcome.Stdout + "\n" + outcome.Stderr)
		msg := outcome.Err
		if msg == "" {
			msg = strings.Join(outcome.AttemptErrs, "; ")
		}
		return combined, fmt.Errorf("dsl[%s]: %s", action.ID, msg)
	}

	out := strings.TrimSpace(outcome.Stdout)
	if out == "" {
		// Some actions (resolvectl, ipconfig /flushdns on success) emit
		// nothing on stdout. Synthesize a non-empty status so the
		// execution row isn't blank in the operator UI — matches the
		// existing flushDNSCache hand-coded behavior.
		out = fmt.Sprintf("%s succeeded", action.ID)
	}
	return out, nil
}
