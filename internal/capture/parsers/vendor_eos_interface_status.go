// vendor_eos_interface_status: parses Arista EOS ``show interface
// <name> | json`` output into the canonical state_payload shape used
// by the state-capture validator service.
//
// Sample input (single interface, trimmed):
//
//   {
//     "interfaces": {
//       "Ethernet1": {
//         "name": "Ethernet1",
//         "interfaceStatus": "connected",
//         "lineProtocolStatus": "up",
//         "mtu": 9214,
//         "duplex": "duplexFull",
//         "interfaceStatistics": {
//           "inputRate": 0, "outputRate": 0,
//           "outBitsRate": 0, "inBitsRate": 0
//         },
//         ...
//       }
//     }
//   }
//
// Output (canonical state_payload):
//
//   {
//     "interface_name": "Ethernet1",
//     "interface_status": "connected",   // operational
//     "line_protocol": "up",             // L2
//     "mtu": 9214,
//     "duplex": "duplexFull"
//   }
//
// The output is intentionally narrow — the validator's invariants
// reference these fields by name (e.g. ``post.line_protocol == "up"``),
// so the parser's job is to normalize EOS's nested JSON into a flat
// shape that's stable across software versions. Fields the validator
// doesn't currently use (statistics, queue counters, etc.) are
// dropped here rather than stored in the row, because state_payload
// participates in the canonical hash and including volatile counters
// would make pre/post hashes always differ for nonsense reasons.

package parsers

import (
	"encoding/json"
	"fmt"
	"strings"
)

func init() {
	Register("vendor_eos_interface_status", parseVendorEOSInterfaceStatus)
}

// parseVendorEOSInterfaceStatus reads the joined output of
// ``show interface <name> | json`` and returns the canonical
// state_payload. EOS prefixes the JSON with a blank line and may
// also include a trailing prompt residue depending on how the shell
// collector strips its output; we tolerate both by hunting for the
// first '{' and parsing from there.
func parseVendorEOSInterfaceStatus(rawOutput string) (map[string]any, error) {
	jsonStart := strings.Index(rawOutput, "{")
	if jsonStart < 0 {
		return nil, fmt.Errorf(
			"vendor_eos_interface_status: no JSON object found in output (got %d bytes)",
			len(rawOutput),
		)
	}

	// EOS sometimes appends trailing text after the closing brace
	// (e.g. an unterminated prompt residue). Find the matching
	// closing brace by walking the string with a depth counter so
	// we feed json.Unmarshal a clean object even if there's noise.
	jsonEnd := findMatchingBrace(rawOutput, jsonStart)
	if jsonEnd < 0 {
		return nil, fmt.Errorf(
			"vendor_eos_interface_status: opening brace at %d has no matching close",
			jsonStart,
		)
	}

	var doc struct {
		Interfaces map[string]struct {
			Name               string `json:"name"`
			InterfaceStatus    string `json:"interfaceStatus"`
			LineProtocolStatus string `json:"lineProtocolStatus"`
			MTU                int    `json:"mtu"`
			Duplex             string `json:"duplex"`
		} `json:"interfaces"`
	}
	body := rawOutput[jsonStart : jsonEnd+1]
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		return nil, fmt.Errorf("vendor_eos_interface_status: unmarshal: %w", err)
	}
	if len(doc.Interfaces) == 0 {
		return nil, fmt.Errorf(
			"vendor_eos_interface_status: no interfaces in JSON output",
		)
	}
	if len(doc.Interfaces) > 1 {
		// The action's commands list is supposed to scope to one
		// interface (``show interface <name> | json``). Multiple
		// hits means the command was misformed — surface clearly
		// rather than silently picking the first.
		names := make([]string, 0, len(doc.Interfaces))
		for k := range doc.Interfaces {
			names = append(names, k)
		}
		return nil, fmt.Errorf(
			"vendor_eos_interface_status: expected exactly one interface, got %d (%v)",
			len(doc.Interfaces), names,
		)
	}

	// Exactly one entry — extract it.
	for _, iface := range doc.Interfaces {
		return map[string]any{
			"interface_name":   iface.Name,
			"interface_status": iface.InterfaceStatus,
			"line_protocol":    iface.LineProtocolStatus,
			"mtu":              iface.MTU,
			"duplex":           iface.Duplex,
		}, nil
	}
	// unreachable: len > 0 + len <= 1 + range covers the single key.
	return nil, fmt.Errorf("vendor_eos_interface_status: internal: empty range")
}

// findMatchingBrace walks the string from openIdx (which must point
// at '{') and returns the index of the matching '}'. Returns -1 if
// unbalanced. Skips brace characters inside JSON string literals.
func findMatchingBrace(s string, openIdx int) int {
	if openIdx >= len(s) || s[openIdx] != '{' {
		return -1
	}
	depth := 0
	inString := false
	escaped := false
	for i := openIdx; i < len(s); i++ {
		c := s[i]
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' && inString {
			escaped = true
			continue
		}
		if c == '"' {
			inString = !inString
			continue
		}
		if inString {
			continue
		}
		switch c {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}
