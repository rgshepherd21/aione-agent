package executor

import (
	"context"
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/shepherdtech/aione-agent/internal/actions/dsl"
)

// dslRegistry returns the embedded KAL action registry, lazy-loading it
// on first call. The agent ships with a build-time-bundled snapshot of
// kal/actions/**.yaml; B2 (task #28) replaces this with a signed pull
// from the backend at startup. The dsl package's own tests gate that
// the embedded registry is well-formed at build time, so a load failure
// here is a hard infrastructure bug — log loudly and let the dispatch
// fall back to the hand-coded implementations.
func (e *Executor) dslRegistry() (dsl.Registry, error) {
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
	actionID string,
	params map[string]string,
) (string, error) {
	reg, err := e.dslRegistry()
	if err != nil {
		return "", fmt.Errorf("dsl: %w", err)
	}
	action, ok := reg[actionID]
	if !ok {
		return "", fmt.Errorf("dsl: action %q not found in registry", actionID)
	}

	// Coerce string-keyed params to the interface{} shape Run expects.
	// nil → empty map (Run's validator special-cases nil too, but being
	// explicit here makes the conversion intent obvious).
	p := make(map[string]interface{}, len(params))
	for k, v := range params {
		p[k] = v
	}

	outcome, err := dsl.Run(ctx, action, p)
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
		return combined, fmt.Errorf("dsl[%s]: %s", actionID, msg)
	}

	out := strings.TrimSpace(outcome.Stdout)
	if out == "" {
		// Some actions (resolvectl, ipconfig /flushdns on success) emit
		// nothing on stdout. Synthesize a non-empty status so the
		// execution row isn't blank in the operator UI — matches the
		// existing flushDNSCache hand-coded behavior.
		out = fmt.Sprintf("%s succeeded", actionID)
	}
	return out, nil
}
