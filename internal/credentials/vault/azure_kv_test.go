// Tests for the AzureKVBackend pieces we can exercise without a
// running Azure Key Vault. Get / Put / List / Delete go to the SDK
// which talks to a real vault; their integration is validated by
// the cEOS soak smoke (manual, lab-only) and by the SDK's own unit
// tests upstream.

package vault

import (
	"strings"
	"testing"
)

func TestExtractSecretName(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			"with version segment",
			"https://my-vault.vault.azure.net/secrets/lab-router-1/abc123",
			"lab-router-1",
		},
		{
			"no version segment",
			"https://my-vault.vault.azure.net/secrets/lab-router-1",
			"lab-router-1",
		},
		{
			"trailing slash",
			"https://my-vault.vault.azure.net/secrets/lab-router-1/",
			"lab-router-1",
		},
		{
			"no /secrets/ marker",
			"https://my-vault.vault.azure.net/keys/some-key/v1",
			"",
		},
		{
			"empty",
			"",
			"",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractSecretName(tc.in); got != tc.want {
				t.Errorf("extractSecretName(%q) = %q want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestNewAzureKVBackend_RequiresVaultURL(t *testing.T) {
	for _, in := range []string{"", "   ", "\n"} {
		_, err := NewAzureKVBackend(in)
		if err == nil {
			t.Errorf("blank vault URL %q should error", in)
		}
		if err != nil && !strings.Contains(err.Error(), "vaultURL") {
			t.Errorf("error %q should mention vaultURL", err)
		}
	}
}

// _ Backend = (*AzureKVBackend)(nil) at the bottom of azure_kv.go
// would be the conventional compile-time interface check; we put it
// here in the test file instead so a stale assertion in production
// code can't accidentally green a missing method.
var _ Backend = (*AzureKVBackend)(nil)
var _ Backend = (*DevBackend)(nil)
