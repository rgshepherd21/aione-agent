package dsl

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v5"
	"gopkg.in/yaml.v3"
)

// embeddedKAL is the build-time-bundled snapshot of the KAL action library
// + schema. Used by LoadEmbeddedRegistry. Replaced at runtime by signed
// pulls from the backend once task #28 (B2) ships — the embed is the
// fallback for offline-bootstrap and the seed for first-run agents.
//
//go:embed all:kal
var embeddedKAL embed.FS

// shellBlocklist mirrors SHELL_BLOCKLIST in
// aione-backend/app/services/kal_registry.py. Action binaries that match
// any entry (case-insensitive basename) are rejected at load time —
// shells reintroduce the metachar / env-lookup / job-control attack
// surface that exec.CommandContext + arg-array dispatch defeats.
var shellBlocklist = map[string]struct{}{
	"sh": {}, "bash": {}, "dash": {}, "zsh": {}, "ksh": {}, "csh": {},
	"tcsh": {}, "ash": {}, "fish": {},
	"cmd.exe": {}, "cmd": {},
	"powershell.exe": {}, "powershell": {}, "pwsh.exe": {}, "pwsh": {},
	"wsl.exe": {}, "wsl": {},
}

// interpolationRE matches a `{{name}}` token in an executor arg.
// Greedy match — `{{a}}stuff{{b}}` is two tokens. Mirrors
// _INTERPOLATION_RE in the Python loader.
//
// Sprint follow-up S2.b.2 phase 2b extended ``name`` to allow
// dotted identifiers (``{{pre_state.description}}``) so rollback
// synthesis commands can reference pre-capture state. The lookup
// is still a flat ``params[name]`` — the rollback executor
// flattens ``pre_state["description"]`` into
// ``params["pre_state.description"]`` before expansion, so this
// regex change is the only signal-path edit. Existing single-
// word interpolations (``{{interface_name}}``) keep working
// unchanged.
var interpolationRE = regexp.MustCompile(`\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)\s*\}\}`)

// KALAction is the in-memory representation of a validated action. Mirrors
// the Python dataclass. The full YAML map is preserved in Raw so the
// canonical body generator + downstream consumers don't have to re-parse.
type KALAction struct {
	ID                 string
	Version            int
	Tier               int
	Category           string
	Description        string
	Implementation     string // "dsl" | "curated"
	Idempotent         bool
	SupportedPlatforms []map[string]interface{}
	Raw                map[string]interface{}
	SourcePath         string
}

// Registry is the loaded action library, keyed by action ID.
type Registry map[string]*KALAction

// LoadError is returned when the registry fails to validate. The error
// message names the failing file + rule so a human can fix the YAML
// without re-running with -v. Mirrors KALLoadError in the Python loader.
type LoadError struct {
	Path string // empty if not file-specific
	Msg  string
	Err  error // wrapped underlying error (yaml parse, schema, etc.)
}

func (e *LoadError) Error() string {
	prefix := ""
	if e.Path != "" {
		prefix = filepath.Base(e.Path) + ": "
	}
	if e.Err != nil {
		return prefix + e.Msg + ": " + e.Err.Error()
	}
	return prefix + e.Msg
}
func (e *LoadError) Unwrap() error { return e.Err }

// loadErrf builds a LoadError with file context.
func loadErrf(p string, format string, args ...interface{}) *LoadError {
	return &LoadError{Path: p, Msg: fmt.Sprintf(format, args...)}
}

// ─── Public API ──────────────────────────────────────────────────────────

// LoadEmbeddedRegistry loads the registry from the build-time-bundled
// kal/ tree. This is the agent's bootstrap path — runs at startup to seed
// the in-memory registry before any pull from the backend (task #28).
func LoadEmbeddedRegistry() (Registry, error) {
	return loadFromFS(embeddedKAL, "kal/actions", "kal/schema/action.schema.json")
}

// LoadRegistry loads the registry from a host filesystem. Test-only path
// for fixture-based rule verification (mirrors the actions_dir + schema_path
// override args in the Python loader's load_registry).
func LoadRegistry(actionsDir, schemaPath string) (Registry, error) {
	return loadFromFS(osFS{}, actionsDir, schemaPath)
}

// ─── Internals ───────────────────────────────────────────────────────────

// fsLike is the minimal subset of fs.FS used by loadFromFS. embed.FS
// satisfies it; osFS adapts the host filesystem.
type fsLike interface {
	ReadFile(name string) ([]byte, error)
	walk(root string, walkFn fs.WalkDirFunc) error
}

type osFS struct{}

func (osFS) ReadFile(name string) ([]byte, error) { return os.ReadFile(name) }
func (osFS) walk(root string, walkFn fs.WalkDirFunc) error {
	return filepath.WalkDir(root, walkFn)
}

// embedFSAdapter wraps embed.FS so it satisfies fsLike.
type embedFSAdapter struct{ embed.FS }

func (e embedFSAdapter) walk(root string, walkFn fs.WalkDirFunc) error {
	return fs.WalkDir(e.FS, root, walkFn)
}

func loadFromFS(rawFS interface{}, actionsDir, schemaPath string) (Registry, error) {
	var src fsLike
	switch v := rawFS.(type) {
	case embed.FS:
		src = embedFSAdapter{v}
	case fsLike:
		src = v
	default:
		return nil, &LoadError{Msg: fmt.Sprintf("unsupported FS type %T", rawFS)}
	}

	schemaBytes, err := src.ReadFile(schemaPath)
	if err != nil {
		return nil, &LoadError{Path: schemaPath, Msg: "schema file missing", Err: err}
	}
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	if err := compiler.AddResource(schemaPath, strings.NewReader(string(schemaBytes))); err != nil {
		return nil, &LoadError{Path: schemaPath, Msg: "schema is not valid JSON", Err: err}
	}
	schema, err := compiler.Compile(schemaPath)
	if err != nil {
		return nil, &LoadError{Path: schemaPath, Msg: "schema compile failed", Err: err}
	}

	var yamlPaths []string
	walkErr := src.walk(actionsDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(strings.ToLower(p), ".yaml") {
			yamlPaths = append(yamlPaths, p)
		}
		return nil
	})
	if walkErr != nil {
		// Empty actions dir (or fully missing) → empty registry, not an
		// error. Mirrors the Python loader's behavior: rglob("*.yaml")
		// on a nonexistent dir yields no files.
		if !errors.Is(walkErr, fs.ErrNotExist) {
			return nil, &LoadError{Path: actionsDir, Msg: "walk failed", Err: walkErr}
		}
	}
	sort.Strings(yamlPaths)

	registry := make(Registry, len(yamlPaths))

	for _, p := range yamlPaths {
		data, err := src.ReadFile(p)
		if err != nil {
			return nil, &LoadError{Path: p, Msg: "read failed", Err: err}
		}

		var raw map[string]interface{}
		if err := yaml.Unmarshal(data, &raw); err != nil {
			return nil, &LoadError{Path: p, Msg: "YAML parse error", Err: err}
		}
		if raw == nil {
			return nil, loadErrf(p, "YAML root must be a mapping, got nil")
		}

		// JSON Schema validation needs JSON-decoded input (uses any-typed
		// numbers etc.). Round-trip through json.Marshal/Unmarshal to
		// normalize before passing to jsonschema. This also catches any
		// non-JSON-encodable types in the YAML (cycles, weird custom
		// tags, etc.) before they hit downstream consumers.
		jsonBytes, err := json.Marshal(raw)
		if err != nil {
			return nil, &LoadError{Path: p, Msg: "YAML→JSON marshal failed", Err: err}
		}
		var jsonForSchema interface{}
		if err := json.Unmarshal(jsonBytes, &jsonForSchema); err != nil {
			return nil, &LoadError{Path: p, Msg: "JSON re-decode failed", Err: err}
		}
		if err := schema.Validate(jsonForSchema); err != nil {
			return nil, loadErrf(p, "schema violation: %s", schemaErrorPath(err))
		}

		// Cross-field rules — mirror the Python loader's call ordering.
		if err := checkIDUnique(raw, registry, p); err != nil {
			return nil, err
		}
		if err := checkBinariesAbsoluteAndSafe(raw, p); err != nil {
			return nil, err
		}
		if err := checkInterpolationCoverage(raw, p); err != nil {
			return nil, err
		}
		if err := checkPlatformMatrixConsistent(raw, p); err != nil {
			return nil, err
		}
		if err := checkRollbackCompleteness(raw, p); err != nil {
			return nil, err
		}

		action := &KALAction{
			ID:             asString(raw["id"]),
			Version:        asInt(raw["version"]),
			Tier:           asInt(raw["tier"]),
			Category:       asString(raw["category"]),
			Description:    asString(raw["description"]),
			Implementation: asString(raw["implementation"]),
			Idempotent:     asBool(raw["idempotent"]),
			Raw:            raw,
			SourcePath:     p,
		}
		if sp, ok := raw["supported_platforms"].([]interface{}); ok {
			for _, entry := range sp {
				if m, ok := entry.(map[string]interface{}); ok {
					action.SupportedPlatforms = append(action.SupportedPlatforms, m)
				}
			}
		}
		registry[action.ID] = action
	}

	return registry, nil
}

// schemaErrorPath extracts a compact "field — message" summary from a
// santhosh-tekuri/jsonschema validation error. The library's full Error()
// is verbose; we want one line that names the failing field.
func schemaErrorPath(err error) string {
	var verr *jsonschema.ValidationError
	if errors.As(err, &verr) {
		// Drill to the deepest leaf — that's the actual rule violation.
		leaf := verr
		for len(leaf.Causes) > 0 {
			leaf = leaf.Causes[0]
		}
		loc := leaf.InstanceLocation
		if loc == "" {
			loc = "<root>"
		}
		return fmt.Sprintf("at %s: %s", loc, leaf.Message)
	}
	return err.Error()
}

// ─── Cross-field rule checkers ───────────────────────────────────────────

func checkIDUnique(raw map[string]interface{}, registry Registry, p string) error {
	id, _ := raw["id"].(string)
	if id == "" {
		return loadErrf(p, "missing or non-string id")
	}
	if existing, ok := registry[id]; ok {
		return loadErrf(p, "duplicate action id '%s' (first seen in %s)",
			id, filepath.Base(existing.SourcePath))
	}
	return nil
}

func checkBinariesAbsoluteAndSafe(raw map[string]interface{}, p string) error {
	for _, executor := range iterAllExecutors(raw) {
		bin, _ := executor["binary"].(string)
		base := strings.ToLower(path.Base(filepath.ToSlash(bin)))
		if _, blocked := shellBlocklist[base]; blocked {
			return loadErrf(p,
				"binary '%s' is a shell; shells are forbidden (exec.CommandContext + arg array is the only allowed path)",
				bin)
		}
	}
	return nil
}

func checkInterpolationCoverage(raw map[string]interface{}, p string) error {
	declared := map[string]struct{}{}
	if params, ok := raw["parameters"].(map[string]interface{}); ok {
		if schema, ok := params["schema"].(map[string]interface{}); ok {
			if props, ok := schema["properties"].(map[string]interface{}); ok {
				for k := range props {
					declared[k] = struct{}{}
				}
			}
		}
	}
	if pt, ok := raw["parameter_transforms"].(map[string]interface{}); ok {
		for k := range pt {
			declared[k] = struct{}{}
		}
	}

	checkString := func(s, where string) error {
		for _, m := range interpolationRE.FindAllStringSubmatch(s, -1) {
			name := m[1]
			if _, ok := declared[name]; !ok {
				return loadErrf(p,
					"%s interpolation '{{%s}}' is not a declared parameter or parameter_transform",
					where, name)
			}
		}
		return nil
	}

	// Shell executors: scan args.
	for _, executor := range iterAllExecutors(raw) {
		args, _ := executor["args"].([]interface{})
		for _, a := range args {
			s, ok := a.(string)
			if !ok {
				continue
			}
			if err := checkString(s, "arg"); err != nil {
				return err
			}
		}
	}

	// Device executors (Sprint D / Task #3): scan pre_commands, command,
	// commands. SSH/NETCONF/SNMP/cloud_api transports use these instead
	// of the shell args array.
	for _, executor := range iterAllDeviceExecutors(raw) {
		if pre, ok := executor["pre_commands"].([]interface{}); ok {
			for _, item := range pre {
				if s, ok := item.(string); ok {
					if err := checkString(s, "pre_command"); err != nil {
						return err
					}
				}
			}
		}
		if cmd, ok := executor["command"].(string); ok {
			if err := checkString(cmd, "command"); err != nil {
				return err
			}
		}
		if cmds, ok := executor["commands"].([]interface{}); ok {
			for _, item := range cmds {
				if s, ok := item.(string); ok {
					if err := checkString(s, "command"); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func checkPlatformMatrixConsistent(raw map[string]interface{}, p string) error {
	impl, _ := raw["implementation"].(string)
	if impl != "dsl" {
		return nil
	}
	// Sprint D / Task #3: supported_platforms is OS-keyed (which agent
	// hosts can dispatch the action). For non-shell transports, every
	// agent OS can dispatch any device action — the OS↔executor coupling
	// only applies to shell. Vendor coverage is enforced by the schema's
	// device_executors property allowlist.
	transport, _ := raw["transport"].(string)
	if transport != "" && transport != "shell" {
		return nil
	}

	supported := map[string]struct{}{}
	if sp, ok := raw["supported_platforms"].([]interface{}); ok {
		for _, entry := range sp {
			if m, ok := entry.(map[string]interface{}); ok {
				if osName, ok := m["os"].(string); ok {
					supported[osName] = struct{}{}
				}
			}
		}
	}

	executorOS := map[string]struct{}{}
	if execs, ok := raw["executors"].(map[string]interface{}); ok {
		for k := range execs {
			executorOS[k] = struct{}{}
		}
	}

	var missing, orphan []string
	for k := range supported {
		if _, ok := executorOS[k]; !ok {
			missing = append(missing, k)
		}
	}
	for k := range executorOS {
		if _, ok := supported[k]; !ok {
			orphan = append(orphan, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(orphan)

	if len(missing) > 0 {
		return loadErrf(p,
			"supported_platforms declares OS %v but executors block has no entry for them",
			missing)
	}
	if len(orphan) > 0 {
		return loadErrf(p,
			"executors block declares OS %v not in supported_platforms (unreachable dispatch)",
			orphan)
	}
	return nil
}

func checkRollbackCompleteness(raw map[string]interface{}, p string) error {
	rb, ok := raw["rollback"].(map[string]interface{})
	if !ok {
		return loadErrf(p, "missing rollback block")
	}
	possible, _ := rb["possible"].(bool)
	if possible {
		if _, ok := rb["spec"]; !ok {
			return loadErrf(p, "rollback.possible=true requires rollback.spec")
		}
	} else {
		rationale, _ := rb["rationale"].(string)
		if rationale == "" {
			return loadErrf(p, "rollback.possible=false requires rollback.rationale")
		}
	}
	return nil
}

// iterAllExecutors yields every executor block in the action — primary
// executors, fallbacks, and rollback.spec.executors (if dsl-rollback).
// Mirrors _iter_all_executors in the Python loader. Used by binary-safety
// + interpolation-coverage checks to cover the full dispatch surface.
func iterAllExecutors(raw map[string]interface{}) []map[string]interface{} {
	var out []map[string]interface{}

	if execs, ok := raw["executors"].(map[string]interface{}); ok {
		for _, spec := range execs {
			if m, ok := spec.(map[string]interface{}); ok {
				out = append(out, m)
				if fbs, ok := m["fallbacks"].([]interface{}); ok {
					for _, fb := range fbs {
						if fm, ok := fb.(map[string]interface{}); ok {
							out = append(out, fm)
						}
					}
				}
			}
		}
	}

	if rb, ok := raw["rollback"].(map[string]interface{}); ok {
		if spec, ok := rb["spec"].(map[string]interface{}); ok {
			if execs, ok := spec["executors"].(map[string]interface{}); ok {
				for _, spec := range execs {
					if m, ok := spec.(map[string]interface{}); ok {
						out = append(out, m)
						if fbs, ok := m["fallbacks"].([]interface{}); ok {
							for _, fb := range fbs {
								if fm, ok := fb.(map[string]interface{}); ok {
									out = append(out, fm)
								}
							}
						}
					}
				}
			}
		}
	}
	return out
}

// iterAllDeviceExecutors yields every device-transport executor block
// (Sprint D / Task #3) — primary device_executors and any
// rollback.spec.device_executors. Device executors don't carry `binary`
// / `args`; instead they have `pre_commands` / `command` / `commands`
// strings that the interpolation-coverage check needs to scan. Mirrors
// _iter_all_device_executors in the Python loader.
func iterAllDeviceExecutors(raw map[string]interface{}) []map[string]interface{} {
	var out []map[string]interface{}

	if execs, ok := raw["device_executors"].(map[string]interface{}); ok {
		for _, spec := range execs {
			if m, ok := spec.(map[string]interface{}); ok {
				out = append(out, m)
			}
		}
	}

	if rb, ok := raw["rollback"].(map[string]interface{}); ok {
		if spec, ok := rb["spec"].(map[string]interface{}); ok {
			if execs, ok := spec["device_executors"].(map[string]interface{}); ok {
				for _, dspec := range execs {
					if m, ok := dspec.(map[string]interface{}); ok {
						out = append(out, m)
					}
				}
			}
		}
	}

	return out
}

// ─── Type coercion helpers ───────────────────────────────────────────────

func asString(v interface{}) string {
	s, _ := v.(string)
	return s
}
func asBool(v interface{}) bool {
	b, _ := v.(bool)
	return b
}
func asInt(v interface{}) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	}
	return 0
}
