// Tests for the parsers package: the registry contract and the
// first registered parser (vendor_eos_interface_status).

package parsers

import (
	"strings"
	"testing"
)

func TestRegistry_GetReturnsErrorForUnknown(t *testing.T) {
	if _, err := Get("does_not_exist_xyz"); err == nil {
		t.Fatal("Get on unknown name should error")
	}
}

func TestRegistry_NamesIncludesRegisteredParsers(t *testing.T) {
	names := Names()
	want := "vendor_eos_interface_status"
	found := false
	for _, n := range names {
		if n == want {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Names()=%v should include %q", names, want)
	}
}

func TestRegistry_RegisterDuplicatePanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("re-registering an existing name should panic")
		}
	}()
	// vendor_eos_interface_status is registered by the package init —
	// a second Register with the same name must panic.
	Register("vendor_eos_interface_status", func(string) (map[string]any, error) {
		return nil, nil
	})
}

func TestRegistry_RegisterNilPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("registering a nil parser should panic")
		}
	}()
	Register("test_nil_parser", nil)
}

// ─── vendor_eos_interface_status ─────────────────────────────────────────

// Real cEOS output captured with `show interface Ethernet1 | json` —
// trimmed to the fields we care about plus a few we drop. Tests pin
// the parser's contract: input shape, output shape, and tolerance to
// surrounding noise the shell collector might leave.
const eosInterfaceStatusUp = `
{
  "interfaces": {
    "Ethernet1": {
      "name": "Ethernet1",
      "interfaceStatus": "connected",
      "lineProtocolStatus": "up",
      "mtu": 9214,
      "duplex": "duplexFull",
      "interfaceStatistics": {
        "inputRate": 0,
        "outputRate": 0
      },
      "physicalAddress": "00:1c:73:01:02:03"
    }
  }
}
`

const eosInterfaceStatusDown = `
{
  "interfaces": {
    "Ethernet1": {
      "name": "Ethernet1",
      "interfaceStatus": "notconnect",
      "lineProtocolStatus": "down",
      "mtu": 9214,
      "duplex": "duplexFull"
    }
  }
}
`

func TestVendorEOSInterfaceStatus_ParsesUp(t *testing.T) {
	p, err := Get("vendor_eos_interface_status")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	out, err := p(eosInterfaceStatusUp)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	wantStr := map[string]string{
		"interface_name":   "Ethernet1",
		"interface_status": "connected",
		"line_protocol":    "up",
		"duplex":           "duplexFull",
	}
	for k, want := range wantStr {
		got, _ := out[k].(string)
		if got != want {
			t.Errorf("%s: got %q want %q", k, got, want)
		}
	}
	if mtu, ok := out["mtu"].(int); !ok || mtu != 9214 {
		t.Errorf("mtu: got %v (%T) want int 9214", out["mtu"], out["mtu"])
	}
}

func TestVendorEOSInterfaceStatus_ParsesDown(t *testing.T) {
	p, _ := Get("vendor_eos_interface_status")
	out, err := p(eosInterfaceStatusDown)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got, _ := out["line_protocol"].(string); got != "down" {
		t.Errorf("line_protocol: got %q want %q", got, "down")
	}
	if got, _ := out["interface_status"].(string); got != "notconnect" {
		t.Errorf("interface_status: got %q want %q", got, "notconnect")
	}
}

func TestVendorEOSInterfaceStatus_TolerantOfPromptResidue(t *testing.T) {
	// Simulate output where the shell collector left a trailing
	// prompt fragment after the JSON. The parser must locate the
	// matching closing brace and not feed the prompt to json.Unmarshal.
	noisy := eosInterfaceStatusUp + "\nceos-1#"
	p, _ := Get("vendor_eos_interface_status")
	if _, err := p(noisy); err != nil {
		t.Errorf("expected tolerance to trailing prompt residue, got: %v", err)
	}
}

func TestVendorEOSInterfaceStatus_TolerantOfLeadingPrompt(t *testing.T) {
	// Some collectors leave the echoed command line before the JSON.
	noisy := "show interface Ethernet1 | json\r\n" + eosInterfaceStatusUp
	p, _ := Get("vendor_eos_interface_status")
	if _, err := p(noisy); err != nil {
		t.Errorf("expected tolerance to leading echo, got: %v", err)
	}
}

func TestVendorEOSInterfaceStatus_RejectsMissingJSON(t *testing.T) {
	p, _ := Get("vendor_eos_interface_status")
	_, err := p("% Invalid input detected at '^' marker.")
	if err == nil {
		t.Fatal("expected error for output with no JSON")
	}
	if !strings.Contains(err.Error(), "no JSON") {
		t.Errorf("error should mention missing JSON: %v", err)
	}
}

func TestVendorEOSInterfaceStatus_RejectsMultipleInterfaces(t *testing.T) {
	multi := `{
      "interfaces": {
        "Ethernet1": {"name":"Ethernet1","interfaceStatus":"connected","lineProtocolStatus":"up","mtu":9214,"duplex":"duplexFull"},
        "Ethernet2": {"name":"Ethernet2","interfaceStatus":"connected","lineProtocolStatus":"up","mtu":9214,"duplex":"duplexFull"}
      }
    }`
	p, _ := Get("vendor_eos_interface_status")
	_, err := p(multi)
	if err == nil {
		t.Fatal("expected error for multi-interface payload")
	}
	if !strings.Contains(err.Error(), "exactly one interface") {
		t.Errorf("error should explain the one-interface contract: %v", err)
	}
}

func TestVendorEOSInterfaceStatus_RejectsEmptyInterfaces(t *testing.T) {
	empty := `{"interfaces": {}}`
	p, _ := Get("vendor_eos_interface_status")
	_, err := p(empty)
	if err == nil {
		t.Fatal("expected error for empty interfaces map")
	}
}

func TestFindMatchingBrace(t *testing.T) {
	cases := []struct {
		name string
		in   string
		open int
		want int
	}{
		{"simple", `{}`, 0, 1},
		{"nested", `{"a":{"b":1}}`, 0, 12},
		{"with_string_brace", `{"a":"}"}`, 0, 8},
		{"escaped_quote_in_string", `{"a":"\""}`, 0, 9},
		{"unbalanced", `{"a":{`, 0, -1},
		{"not_at_open", `x{}`, 0, -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := findMatchingBrace(tc.in, tc.open)
			if got != tc.want {
				t.Errorf("findMatchingBrace(%q, %d) = %d, want %d",
					tc.in, tc.open, got, tc.want)
			}
		})
	}
}
