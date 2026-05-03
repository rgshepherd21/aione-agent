// Shared credential-resolution helper used by RunDeviceAction and
// RunRollback (Sprint follow-up Bucket A.2 / MEDIUM#7 from the post-S4
// code review).
//
// Both paths need to turn a (CredentialRef, ExecutionID,
// hintedCredType) tuple into a populated DeviceCredential. Before this
// helper, the action body had a clean local:// branch in
// device_executor.go but the rollback path went straight to the
// platform fetcher — which 404s for any local:// device because the
// V1.local invariant says backend code MUST NOT resolve local:// refs.
// Extracting the branch into one place fixes the rollback gap (HIGH#2)
// and removes the future-drift footgun.
//
// The helper is intentionally small and side-effect-free except for
// debug logging. Callers handle host/port resolution and SSH dial
// downstream — the credential resolution is the only piece that
// genuinely needed to be shared.

package dsl

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
)

// credResolveInput is the narrow argument bundle resolveCredential
// accepts. Both DeviceTarget and RollbackTarget carry a superset of
// these fields; we copy only what the resolution decision needs to
// keep the helper testable.
type credResolveInput struct {
	// LogActionID is the value used in debug logs — the action's
	// ActionExecutionID for the action body, the rollback's
	// CommandID for the rollback path. Identifies the caller in
	// shared log records.
	LogActionID string

	// FetchID is the identifier passed to CredentialFetcher.Fetch
	// for the platform path. Both action body and rollback use the
	// parent ActionExecution.id (the platform's credential issuer
	// indexes on action_executions, NOT rollback_attempts).
	FetchID string

	CredentialRef string
	HintedType    string
	LocalVault    VaultBackend
	Fetcher       CredentialFetcher
}

// resolveCredential is the single chokepoint for turning a
// CredentialRef into a DeviceCredential. local:// refs go to
// LocalVault; everything else goes to Fetcher. Returns a wrapped
// error from each branch so the caller can log a precise message
// without re-implementing the dispatch.
func resolveCredential(ctx context.Context, in credResolveInput) (DeviceCredential, error) {
	if in.FetchID == "" {
		return DeviceCredential{}, errors.New("dsl: resolveCredential requires FetchID")
	}

	if strings.HasPrefix(in.CredentialRef, localSchemePrefix) {
		// V1.local — local:// refs MUST resolve through the local
		// vault, never through the platform fetcher. A nil vault is
		// a fail-fast configuration error rather than a silent leak.
		if in.LocalVault == nil {
			return DeviceCredential{}, fmt.Errorf(
				"dsl: action requires local vault for credential_ref=%q "+
					"but no vault is wired (set vault.backend in agent.yaml)",
				in.CredentialRef,
			)
		}
		id := strings.TrimPrefix(in.CredentialRef, localSchemePrefix)
		vc, err := in.LocalVault.Get(ctx, id)
		if err != nil {
			return DeviceCredential{}, fmt.Errorf("dsl: local vault lookup: %w", err)
		}
		cred := DeviceCredential{
			Type:      vc.Type,
			Principal: vc.Principal,
			Secret:    vc.Secret,
			Attrs:     vc.Attrs,
		}
		log.Debug().
			Str("action_id", in.LogActionID).
			Str("credential_ref", in.CredentialRef).
			Str("cred_type_received", cred.Type).
			Str("cred_principal", cred.Principal).
			Int("cred_secret_len", len(cred.Secret)).
			Msg("dsl: credential bundle resolved from local vault")
		return cred, nil
	}

	// Platform fetch path — the historical default.
	if in.Fetcher == nil {
		return DeviceCredential{}, errors.New("dsl: CredentialFetcher is required")
	}
	cred, err := in.Fetcher.Fetch(ctx, in.FetchID, in.HintedType)
	if err != nil {
		return DeviceCredential{}, fmt.Errorf("dsl: credential fetch: %w", err)
	}
	log.Debug().
		Str("action_id", in.LogActionID).
		Str("cred_type_received", cred.Type).
		Str("cred_principal", cred.Principal).
		Int("cred_secret_len", len(cred.Secret)).
		Msg("dsl: credential bundle received from platform")
	return cred, nil
}
