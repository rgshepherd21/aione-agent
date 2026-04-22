// Cross-repo schema parity regression test — partner of
// aione-backend/tests/test_contract_agent_schemas.py (drift-doc item #14,
// extended scope from aione-backend PR #32).
//
// The backend is the source of truth for the agent-commands wire
// schemas. It emits a canonical JSON description under
// aione-backend/schemas-exports/agent-commands.v1.json, and this
// test asserts that PendingCommand / CommandResult in types.go still
// line up with it.
//
// The check is deliberately lenient about optional wire fields: the
// agent is allowed to omit them. What the test *does* enforce:
//
//   - Every field marked required by the canonical schema MUST be
//     present on the Go struct, or a live POST will 422.
//   - Those required Go fields MUST NOT carry `,omitempty` — a zero
//     value would silently drop the field off the wire.
//   - No Go field may reference a wire name the canonical schema
//     doesn't declare. Either the BE forgot to add it or the Go tag
//     is a typo.
//
// Fixing a failure
// ----------------
//  1. Look at the diff in the test output to see which side drifted.
//  2. If the BE intentionally changed the schema, update the Go structs
//     in types.go and refresh this testdata file by copying
//     aione-backend/schemas-exports/agent-commands.v1.json into
//     internal/dispatcher/testdata/.
//  3. If the Go side drifted by accident, revert types.go.

package dispatcher

import (
	_ "embed"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

//go:embed testdata/agent-commands.v1.json
var agentCommandsExport []byte

// modelShape mirrors the describe_model output from
// aione-backend/app/schemas/exports.py.
type modelShape struct {
	Fields   []string `json:"fields"`
	Required []string `json:"required"`
}

type contractExport struct {
	Version int                   `json:"version"`
	Schema  string                `json:"schema"`
	Source  string                `json:"source"`
	Models  map[string]modelShape `json:"models"`
}

// wireNames returns the JSON wire names declared on a struct type in
// declaration order, alongside a set of names that carry the
// `,omitempty` tag option. Fields with no json tag (or json:"-") are
// skipped — those are internal and not on the wire.
func wireNames(t reflect.Type) (names []string, omitEmpty map[string]bool) {
	omitEmpty = make(map[string]bool)
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		tag := f.Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		parts := strings.Split(tag, ",")
		name := parts[0]
		if name == "" {
			continue
		}
		names = append(names, name)
		for _, opt := range parts[1:] {
			if opt == "omitempty" {
				omitEmpty[name] = true
			}
		}
	}
	return
}

func loadContract(t *testing.T) contractExport {
	t.Helper()
	var c contractExport
	if err := json.Unmarshal(agentCommandsExport, &c); err != nil {
		t.Fatalf("parse testdata/agent-commands.v1.json: %v", err)
	}
	if c.Schema != "agent-commands" {
		t.Fatalf("unexpected schema %q in testdata (want agent-commands)", c.Schema)
	}
	return c
}

func assertParity(t *testing.T, modelName string, goType reflect.Type, shape modelShape) {
	t.Helper()

	goNames, omitEmpty := wireNames(goType)
	goSet := make(map[string]bool, len(goNames))
	for _, n := range goNames {
		goSet[n] = true
	}
	jsonSet := make(map[string]bool, len(shape.Fields))
	for _, n := range shape.Fields {
		jsonSet[n] = true
	}

	// Agent must carry every required wire field.
	for _, req := range shape.Required {
		if !goSet[req] {
			t.Errorf(
				"%s: required wire field %q missing from Go struct.\n"+
					"  Go fields:   %v\n"+
					"  JSON fields: %v\n"+
					"Remedy: add the field to types.go and refresh\n"+
					"testdata/agent-commands.v1.json from aione-backend/schemas-exports/.",
				modelName, req, goNames, shape.Fields,
			)
		}
		if omitEmpty[req] {
			t.Errorf(
				"%s: required wire field %q carries `,omitempty` in the Go tag.\n"+
					"A zero value would silently drop the field off the wire. Remove omitempty.",
				modelName, req,
			)
		}
	}

	// No Go field may reference a wire name the schema doesn't declare.
	for _, name := range goNames {
		if !jsonSet[name] {
			t.Errorf(
				"%s: Go field %q has no counterpart in the canonical schema.\n"+
					"Either the BE forgot to declare it, or the Go tag is a typo.\n"+
					"Canonical schema fields: %v",
				modelName, name, shape.Fields,
			)
		}
	}
}

func TestAgentCommandsSchemaParity(t *testing.T) {
	c := loadContract(t)

	cases := []struct {
		name string
		typ  reflect.Type
	}{
		{"AgentCommand", reflect.TypeOf(PendingCommand{})},
		{"AgentCommandResult", reflect.TypeOf(CommandResult{})},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			shape, ok := c.Models[tc.name]
			if !ok {
				t.Fatalf("model %s missing from canonical schema export", tc.name)
			}
			assertParity(t, tc.name, tc.typ, shape)
		})
	}
}
