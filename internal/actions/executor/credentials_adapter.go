// Sprint D / Task #2.5 — adapter that lets the agent's
// internal/credentials.Manager satisfy the dsl.CredentialFetcher
// interface without forcing the dsl package to import credentials.
//
// The dsl package keeps a narrow CredentialFetcher contract so it can
// stay decoupled from the agent's credential storage strategy. This
// adapter is the one place that knows about both sides.

package executor

import (
	"context"

	"github.com/shepherdtech/aione-agent/internal/actions/dsl"
	"github.com/shepherdtech/aione-agent/internal/credentials"
)

// CredentialFetcherAdapter wraps a *credentials.Manager so it satisfies
// dsl.CredentialFetcher. Construct with NewCredentialFetcher; pass to
// Executor.SetCredentialFetcher.
type CredentialFetcherAdapter struct {
	mgr *credentials.Manager
}

// NewCredentialFetcher returns an adapter over the provided manager.
// Nil mgr produces a usable adapter that fails every Fetch call —
// surfaces misconfiguration rather than panicking on first SSH action.
func NewCredentialFetcher(mgr *credentials.Manager) *CredentialFetcherAdapter {
	return &CredentialFetcherAdapter{mgr: mgr}
}

// Fetch satisfies dsl.CredentialFetcher. Translates the credentials
// package's *ActionCred return shape into dsl.DeviceCredential.
func (a *CredentialFetcherAdapter) Fetch(ctx context.Context, actionID, credType string) (dsl.DeviceCredential, error) {
	if a == nil || a.mgr == nil {
		return dsl.DeviceCredential{}, errAdapterUnconfigured
	}
	cred, err := a.mgr.Fetch(ctx, actionID, credType)
	if err != nil {
		return dsl.DeviceCredential{}, err
	}
	return dsl.DeviceCredential{
		Type:      cred.Type,
		Principal: cred.Principal,
		Secret:    cred.Secret,
		Attrs:     cred.Attrs,
		ExpiresAt: cred.ExpiresAt,
	}, nil
}

// errAdapterUnconfigured is returned when Fetch is called with a nil
// manager. Sentinel as a package-level value so tests can errors.Is
// against it.
var errAdapterUnconfigured = errAdapter("credentials adapter has no Manager wired — pass executor.NewCredentialFetcher a non-nil *credentials.Manager")

type errAdapter string

func (e errAdapter) Error() string { return string(e) }
