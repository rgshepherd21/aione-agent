// AzureKVBackend — production credential vault backed by Azure Key
// Vault.
//
// Sprint S3.b. Uses ``azidentity.NewDefaultAzureCredential`` so the
// auth chain follows the standard Azure precedence: env vars → managed
// identity → Azure CLI → IDE-cached credentials. In production
// (customer-tenant cloud agent shape, eventual Sprint K), the agent
// runs as a Container App with an attached managed identity that the
// customer has granted ``Key Vault Secrets User`` on their vault. In
// dev / lab, az login provides credentials.
//
// One Azure KV secret holds one Credentials bundle, JSON-encoded as
// the secret's ``value``:
//
//	{"type": "ssh_password",
//	 "principal": "admin",
//	 "secret": "...",
//	 "attrs": {"host": "172.20.20.12", "port": "22"}}
//
// Same shape as DevBackend's seed JSON entries. The bundle counts as
// one secret operation (single GET / SET / DELETE per device id).
//
// ``Backend.Get`` returns ``ErrNotFound`` (wrapped) when the vault
// reports a 404 for the secret name. Other errors propagate; the
// caller decides whether to retry, escalate, or fall back. The
// dispatch path treats ``ErrNotFound`` as a permanent miss (action
// fails fast with a clear "no credential for device X" message),
// other errors as transient.

package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
)

// AzureKVBackend implements ``Backend`` against an Azure Key Vault.
// Construct with ``NewAzureKVBackend`` so the credential chain + client
// are wired correctly; the zero value is invalid.
type AzureKVBackend struct {
	client   *azsecrets.Client
	vaultURL string
}

// NewAzureKVBackend builds a backend for the vault at ``vaultURL``
// (e.g. ``https://my-vault.vault.azure.net/``). Auth uses the default
// Azure credential chain.
//
// Returns an error if either the credential chain or the client
// construction fails. The credential chain itself is lazy — the
// first request triggers token acquisition. So a constructor that
// returned without error doesn't guarantee a usable client; the
// first ``Get`` will surface auth failures explicitly.
func NewAzureKVBackend(vaultURL string) (*AzureKVBackend, error) {
	if strings.TrimSpace(vaultURL) == "" {
		return nil, errors.New("vault: AzureKVBackend requires non-empty vaultURL")
	}
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("vault: azure default credential: %w", err)
	}
	client, err := azsecrets.NewClient(vaultURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("vault: azsecrets new client: %w", err)
	}
	return &AzureKVBackend{client: client, vaultURL: vaultURL}, nil
}

// Get fetches a secret by id and parses its JSON value into a
// Credentials bundle. Returns ErrNotFound when the vault reports
// 404; other errors propagate verbatim with a vault: prefix so the
// log line says where the failure came from.
func (b *AzureKVBackend) Get(ctx context.Context, id string) (*Credentials, error) {
	resp, err := b.client.GetSecret(ctx, id, "", nil)
	if err != nil {
		if isAzureNotFound(err) {
			return nil, fmt.Errorf("azure-kv: %q: %w", id, ErrNotFound)
		}
		return nil, fmt.Errorf("azure-kv: get %q: %w", id, err)
	}
	if resp.Value == nil {
		return nil, fmt.Errorf("azure-kv: %q: empty secret value", id)
	}
	var entry rawCredEntry
	if err := json.Unmarshal([]byte(*resp.Value), &entry); err != nil {
		return nil, fmt.Errorf("azure-kv: %q: parse secret JSON: %w", id, err)
	}
	creds := entry.toCredentials()
	if err := creds.Validate(); err != nil {
		return nil, fmt.Errorf("azure-kv: %q: %w", id, err)
	}
	return creds, nil
}

// Put encodes a Credentials bundle as JSON and writes it under the
// given id. Validates the bundle before encoding so a malformed
// input never lands in the vault.
func (b *AzureKVBackend) Put(ctx context.Context, id string, c *Credentials) error {
	if id == "" {
		return errors.New("azure-kv: Put requires non-empty id")
	}
	if err := c.Validate(); err != nil {
		return fmt.Errorf("azure-kv: Put %q: %w", id, err)
	}
	payload, err := json.Marshal(rawCredEntry{
		Type:      c.Type,
		Principal: c.Principal,
		Secret:    c.Secret,
		Attrs:     c.Attrs,
	})
	if err != nil {
		return fmt.Errorf("azure-kv: Put %q encode: %w", id, err)
	}
	value := string(payload)
	_, err = b.client.SetSecret(ctx, id, azsecrets.SetSecretParameters{Value: &value}, nil)
	if err != nil {
		return fmt.Errorf("azure-kv: Put %q: %w", id, err)
	}
	return nil
}

// List enumerates secret names in the vault. Pages through the
// response until exhausted; sort order matches DevBackend (lex
// ascending) so callers can rely on deterministic output.
func (b *AzureKVBackend) List(ctx context.Context) ([]string, error) {
	pager := b.client.NewListSecretPropertiesPager(nil)
	out := make([]string, 0, 16)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("azure-kv: list page: %w", err)
		}
		for _, item := range page.Value {
			if item.ID == nil {
				continue
			}
			name := extractSecretName(string(*item.ID))
			if name != "" {
				out = append(out, name)
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

// Delete soft-deletes a secret. Azure KV's "soft delete" is the
// default; the secret moves to deleted-but-recoverable state for
// the vault's retention period. Operators recover via the Azure
// portal or `az keyvault secret recover`.
func (b *AzureKVBackend) Delete(ctx context.Context, id string) error {
	_, err := b.client.DeleteSecret(ctx, id, nil)
	if err != nil {
		if isAzureNotFound(err) {
			return fmt.Errorf("azure-kv: %q: %w", id, ErrNotFound)
		}
		return fmt.Errorf("azure-kv: delete %q: %w", id, err)
	}
	return nil
}

// Close is a no-op. The azsecrets client wraps an *http.Client whose
// transport is reused; no per-Backend resource needs explicit
// teardown today. The method is on the interface so backends with
// real teardown (file handles, SQLite connections) can implement it.
func (b *AzureKVBackend) Close() error { return nil }

// isAzureNotFound reports whether err is an Azure SDK response error
// with status 404. The SDK wraps HTTP errors in
// ``*azcore.ResponseError`` which carries StatusCode; we use
// ``errors.As`` so the test still works if the SDK adds extra
// wrapping in a future version.
func isAzureNotFound(err error) bool {
	var apiErr *azcore.ResponseError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == http.StatusNotFound
	}
	return false
}

// extractSecretName parses a secret resource URL like
// ``https://vault.example.vault.azure.net/secrets/my-secret/abcdef...``
// and returns ``my-secret`` (the segment between ``/secrets/`` and
// the next ``/``). Returns "" when the URL doesn't match the expected
// shape — caller filters those out of the listing.
func extractSecretName(rawURL string) string {
	const marker = "/secrets/"
	i := strings.Index(rawURL, marker)
	if i < 0 {
		return ""
	}
	tail := rawURL[i+len(marker):]
	if j := strings.Index(tail, "/"); j >= 0 {
		return tail[:j]
	}
	return tail
}
