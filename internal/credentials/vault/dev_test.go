// Tests for DevBackend + the Credentials struct's validation.
// AzureKVBackend has its own test file because its mocks are more
// involved (Azure SDK fakes).

package vault

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestCredentialsValidate(t *testing.T) {
	cases := []struct {
		name    string
		c       *Credentials
		wantErr bool
		errSub  string
	}{
		{"nil", nil, true, "nil"},
		{"missing type", &Credentials{Principal: "a", Secret: "b"}, true, "Type"},
		{"missing principal", &Credentials{Type: "ssh_key", Secret: "b"}, true, "Principal"},
		{"missing secret", &Credentials{Type: "ssh_key", Principal: "a"}, true, "Secret"},
		{"happy", &Credentials{Type: "ssh_key", Principal: "a", Secret: "b"}, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.c.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate err=%v wantErr=%v", err, tc.wantErr)
			}
			if tc.wantErr && !strings.Contains(err.Error(), tc.errSub) {
				t.Errorf("err message %q should mention %q", err, tc.errSub)
			}
		})
	}
}

// ─── DevBackend behavior ────────────────────────────────────────────────

func TestDevBackend_PutGet(t *testing.T) {
	b := NewDevBackend()
	ctx := context.Background()

	c := &Credentials{
		Type:      "ssh_key",
		Principal: "admin",
		Secret:    "-----BEGIN OPENSSH PRIVATE KEY-----...",
		Attrs:     map[string]string{"host": "10.0.0.1", "port": "22"},
	}
	if err := b.Put(ctx, "lab-router-1", c); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := b.Get(ctx, "lab-router-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Type != "ssh_key" || got.Principal != "admin" {
		t.Errorf("round-trip lost fields: %+v", got)
	}
	if got.Attrs["host"] != "10.0.0.1" {
		t.Errorf("attrs not preserved: %+v", got.Attrs)
	}
}

func TestDevBackend_GetReturnsErrNotFound(t *testing.T) {
	b := NewDevBackend()
	_, err := b.Get(context.Background(), "missing")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get on missing id should wrap ErrNotFound; got %v", err)
	}
}

func TestDevBackend_GetCopiesAttrs(t *testing.T) {
	// Mutating the returned bundle's Attrs must NOT leak into the
	// store. Caller-side mutation safety is part of the Backend
	// contract.
	b := NewDevBackend()
	ctx := context.Background()
	original := &Credentials{
		Type: "ssh_key", Principal: "a", Secret: "k",
		Attrs: map[string]string{"host": "10.0.0.1"},
	}
	_ = b.Put(ctx, "x", original)

	got, _ := b.Get(ctx, "x")
	got.Attrs["host"] = "MUTATED"

	got2, _ := b.Get(ctx, "x")
	if got2.Attrs["host"] != "10.0.0.1" {
		t.Errorf("Get caller mutated stored value: %q", got2.Attrs["host"])
	}
}

func TestDevBackend_PutCopiesAttrs(t *testing.T) {
	// Symmetric: mutating the source bundle's Attrs after Put must
	// NOT leak into the stored copy.
	b := NewDevBackend()
	ctx := context.Background()
	src := &Credentials{
		Type: "ssh_key", Principal: "a", Secret: "k",
		Attrs: map[string]string{"host": "10.0.0.1"},
	}
	_ = b.Put(ctx, "x", src)
	src.Attrs["host"] = "MUTATED"

	got, _ := b.Get(ctx, "x")
	if got.Attrs["host"] != "10.0.0.1" {
		t.Errorf("Put source mutation leaked to store: %q", got.Attrs["host"])
	}
}

func TestDevBackend_PutValidates(t *testing.T) {
	b := NewDevBackend()
	err := b.Put(context.Background(), "x", &Credentials{Type: "ssh_key"})
	if err == nil {
		t.Fatal("Put should reject a Credentials missing Principal/Secret")
	}
}

func TestDevBackend_PutEmptyIDRejected(t *testing.T) {
	b := NewDevBackend()
	c := &Credentials{Type: "ssh_key", Principal: "a", Secret: "k"}
	if err := b.Put(context.Background(), "", c); err == nil {
		t.Fatal("Put with empty id should error")
	}
}

func TestDevBackend_List(t *testing.T) {
	b := NewDevBackend()
	ctx := context.Background()
	for _, id := range []string{"zeta", "alpha", "mu"} {
		_ = b.Put(ctx, id, &Credentials{Type: "x", Principal: "y", Secret: "z"})
	}
	got, err := b.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	want := []string{"alpha", "mu", "zeta"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("List sorted: got %v want %v", got, want)
	}
}

func TestDevBackend_ListEmptyIsEmptySlice(t *testing.T) {
	b := NewDevBackend()
	got, err := b.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if got == nil {
		t.Fatal("List on empty backend must return [], not nil")
	}
	if len(got) != 0 {
		t.Errorf("List on empty backend: %v", got)
	}
}

func TestDevBackend_Delete(t *testing.T) {
	b := NewDevBackend()
	ctx := context.Background()
	_ = b.Put(ctx, "x", &Credentials{Type: "x", Principal: "y", Secret: "z"})

	if err := b.Delete(ctx, "x"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := b.Get(ctx, "x"); !errors.Is(err, ErrNotFound) {
		t.Errorf("post-Delete Get: %v", err)
	}
}

func TestDevBackend_DeleteMissingErrNotFound(t *testing.T) {
	b := NewDevBackend()
	err := b.Delete(context.Background(), "never-was")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Delete on missing should wrap ErrNotFound: %v", err)
	}
}

func TestDevBackend_CloseIdempotent(t *testing.T) {
	b := NewDevBackend()
	for i := 0; i < 3; i++ {
		if err := b.Close(); err != nil {
			t.Errorf("Close iter %d: %v", i, err)
		}
	}
}

// ─── Seed loading (JSON + file) ─────────────────────────────────────────

func TestNewDevBackendFromJSON_HappyPath(t *testing.T) {
	const seed = `{
      "lab-router-1": {
        "type":      "ssh_key",
        "principal": "admin",
        "secret":    "PEM-DATA",
        "attrs":     {"host": "10.0.0.1", "port": "22"}
      },
      "f7-ceos-1": {
        "type":      "ssh_password",
        "principal": "admin",
        "secret":    "passwd",
        "attrs":     {"host": "172.20.20.11", "port": "22"}
      }
    }`
	b, err := NewDevBackendFromJSON(seed)
	if err != nil {
		t.Fatalf("seed parse: %v", err)
	}
	ids, _ := b.List(context.Background())
	if len(ids) != 2 {
		t.Fatalf("seeded entries: got %d want 2", len(ids))
	}
	got, _ := b.Get(context.Background(), "f7-ceos-1")
	if got.Principal != "admin" || got.Type != "ssh_password" || got.Attrs["host"] != "172.20.20.11" {
		t.Errorf("seed entry round-trip wrong: %+v", got)
	}
}

func TestNewDevBackendFromJSON_BlankIsEmpty(t *testing.T) {
	for _, raw := range []string{"", "   ", "\n\t  \n"} {
		b, err := NewDevBackendFromJSON(raw)
		if err != nil {
			t.Errorf("blank seed %q should be ok, got %v", raw, err)
		}
		ids, _ := b.List(context.Background())
		if len(ids) != 0 {
			t.Errorf("blank seed should yield empty backend, got %v", ids)
		}
	}
}

func TestNewDevBackendFromJSON_BadJSONErrors(t *testing.T) {
	_, err := NewDevBackendFromJSON("not-json")
	if err == nil {
		t.Fatal("malformed JSON should error")
	}
}

func TestNewDevBackendFromJSON_MalformedEntryErrors(t *testing.T) {
	// Missing required fields on an entry — should fail at parse,
	// not silently become a corrupt store.
	const seed = `{"x": {"type": "ssh_key", "principal": "a"}}`
	_, err := NewDevBackendFromJSON(seed)
	if err == nil {
		t.Fatal("entry missing Secret should error")
	}
	if !strings.Contains(err.Error(), "Secret") {
		t.Errorf("error should name the missing field: %v", err)
	}
}

func TestNewDevBackendFromFile_MissingIsEmpty(t *testing.T) {
	b, err := NewDevBackendFromFile("/nonexistent/path/to/seed.json")
	if err != nil {
		t.Errorf("missing file should yield empty backend, got %v", err)
	}
	ids, _ := b.List(context.Background())
	if len(ids) != 0 {
		t.Errorf("missing file: %v", ids)
	}
}
