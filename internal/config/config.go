package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level agent configuration.
type Config struct {
	Agent     AgentConfig     `yaml:"agent"`
	API       APIConfig       `yaml:"api"`
	Transport TransportConfig `yaml:"transport"`
	Telemetry TelemetryConfig `yaml:"telemetry"`
	Actions   ActionsConfig   `yaml:"actions"`
	Buffer    BufferConfig    `yaml:"buffer"`
	Updater   UpdaterConfig   `yaml:"updater"`
	Vault     VaultConfig     `yaml:"vault"`
	Log       LogConfig       `yaml:"log"`
}

// VaultConfig controls the agent-side credential vault that resolves
// ``local://`` credential references. Sprint S3.b.
//
// Fields default to the in-memory dev backend with no seed — safe
// for first-run agents that don't yet handle local:// refs. Production
// deployments override Backend to ``azure-kv`` and set AzureURL to
// the customer's Azure Key Vault.
type VaultConfig struct {
	// Backend selects the vault implementation:
	//   "dev"      — in-memory map seeded from DevSeedJSON or
	//                DevSeedPath. Default.
	//   "azure-kv" — Azure Key Vault via DefaultAzureCredential
	//                (managed identity, az login, env vars, …).
	Backend string `yaml:"backend"`

	// AzureURL is the Azure Key Vault URL when Backend="azure-kv",
	// e.g. "https://my-vault.vault.azure.net/".
	AzureURL string `yaml:"azure_url"`

	// DevSeedJSON is an inline JSON map of {id: {type, principal,
	// secret, attrs}} pairs. Highest priority for the dev backend.
	// Env-var friendly: set ``vault.dev_seed_json: "${AIONE_VAULT_SEED}"``
	// in the YAML and populate the env var at deploy time.
	DevSeedJSON string `yaml:"dev_seed_json"`

	// DevSeedPath is a JSON file path. Lower priority than
	// DevSeedJSON; ignored when the inline JSON is set. Useful for
	// dev workflows where a file lives next to the binary.
	DevSeedPath string `yaml:"dev_seed_path"`
}

// AgentConfig contains identity and runtime settings.
type AgentConfig struct {
	ID           string        `yaml:"id"`            // Populated after registration
	Name         string        `yaml:"name"`          // Human-readable hostname label
	InstallToken string        `yaml:"install_token"` // One-time registration token
	DataDir      string        `yaml:"data_dir"`      // Certs, state, buffer files
	Heartbeat    time.Duration `yaml:"heartbeat"`     // Interval between heartbeats
	Tags         []string      `yaml:"tags"`          // Arbitrary labels
}

// APIConfig controls outbound API connectivity.
type APIConfig struct {
	BaseURL    string        `yaml:"base_url"`
	Timeout    time.Duration `yaml:"timeout"`
	RetryMax   int           `yaml:"retry_max"`
	RetryDelay time.Duration `yaml:"retry_delay"`
}

// TransportConfig holds mTLS certificate paths.
type TransportConfig struct {
	CertFile           string `yaml:"cert_file"`
	KeyFile            string `yaml:"key_file"`
	CAFile             string `yaml:"ca_file"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"` // Dev/testing only
}

// TelemetryConfig groups all collector configs.
type TelemetryConfig struct {
	SNMP   SNMPConfig         `yaml:"snmp"`
	Syslog SyslogConfig       `yaml:"syslog"`
	WMI    WMIConfig          `yaml:"wmi"`
	API    APICollectorConfig `yaml:"api_collector"`
}

// SNMPConfig controls SNMP polling.
type SNMPConfig struct {
	Enabled  bool          `yaml:"enabled"`
	Interval time.Duration `yaml:"interval"`
	Targets  []SNMPTarget  `yaml:"targets"`
}

// SNMPTarget describes a single SNMP-polled device.
type SNMPTarget struct {
	Host      string   `yaml:"host"`
	Port      uint16   `yaml:"port"`
	Community string   `yaml:"community"`
	Version   string   `yaml:"version"` // "2c" or "3"
	OIDs      []string `yaml:"oids"`
}

// SyslogConfig controls the embedded syslog listener.
type SyslogConfig struct {
	Enabled bool   `yaml:"enabled"`
	UDPAddr string `yaml:"udp_addr"`
	TCPAddr string `yaml:"tcp_addr"`
}

// WMIConfig controls Windows WMI polling.
type WMIConfig struct {
	Enabled  bool          `yaml:"enabled"`
	Interval time.Duration `yaml:"interval"`
	Queries  []WMIQuery    `yaml:"queries"`
}

// WMIQuery is a named WMI/PowerShell query.
type WMIQuery struct {
	Name      string `yaml:"name"`
	Namespace string `yaml:"namespace"`
	Query     string `yaml:"query"`
}

// APICollectorConfig controls REST endpoint polling.
type APICollectorConfig struct {
	Enabled   bool                `yaml:"enabled"`
	Interval  time.Duration       `yaml:"interval"`
	Endpoints []CollectorEndpoint `yaml:"endpoints"`
}

// CollectorEndpoint describes one REST endpoint to poll.
type CollectorEndpoint struct {
	Name    string            `yaml:"name"`
	URL     string            `yaml:"url"`
	Method  string            `yaml:"method"`
	Headers map[string]string `yaml:"headers"`
}

// ActionsConfig controls the action executor.
type ActionsConfig struct {
	Enabled        bool          `yaml:"enabled"`
	MaxConcurrent  int           `yaml:"max_concurrent"`
	Timeout        time.Duration `yaml:"timeout"`
	AllowedActions []string      `yaml:"allowed_actions"`
	HMACSecret     string        `yaml:"hmac_secret"` // For action signature validation
}

// BufferConfig controls offline telemetry buffering.
type BufferConfig struct {
	Enabled  bool   `yaml:"enabled"`
	MaxSize  int    `yaml:"max_size"`  // Maximum number of buffered events
	DataFile string `yaml:"data_file"` // Optional disk persistence path
}

// UpdaterConfig controls auto-update behaviour.
type UpdaterConfig struct {
	Enabled  bool          `yaml:"enabled"`
	Channel  string        `yaml:"channel"` // "stable" or "beta"
	Interval time.Duration `yaml:"interval"`
}

// LogConfig controls structured logging.
type LogConfig struct {
	Level  string `yaml:"level"`  // trace, debug, info, warn, error
	Pretty bool   `yaml:"pretty"` // Human-readable console output
	File   string `yaml:"file"`   // Optional file path (empty = stderr)
}

// Load reads, env-expands, and validates the YAML config at path.
func Load(path string) (*Config, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolving config path: %w", err)
	}

	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", absPath, err)
	}

	cfg := defaults()
	if err := yaml.Unmarshal([]byte(os.ExpandEnv(string(data))), cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}

func defaults() *Config {
	return &Config{
		Agent: AgentConfig{
			DataDir:   dataDir(),
			Heartbeat: 30 * time.Second,
		},
		API: APIConfig{
			Timeout:    30 * time.Second,
			RetryMax:   5,
			RetryDelay: 5 * time.Second,
		},
		Telemetry: TelemetryConfig{
			SNMP: SNMPConfig{Interval: 60 * time.Second},
			WMI:  WMIConfig{Interval: 30 * time.Second},
			API:  APICollectorConfig{Interval: 60 * time.Second},
		},
		Actions: ActionsConfig{
			MaxConcurrent: 5,
			Timeout:       5 * time.Minute,
		},
		Buffer: BufferConfig{
			MaxSize: 10_000,
		},
		Updater: UpdaterConfig{
			Channel:  "stable",
			Interval: 6 * time.Hour,
		},
		Log: LogConfig{Level: "info"},
	}
}

func (c *Config) validate() error {
	if c.API.BaseURL == "" {
		return fmt.Errorf("api.base_url is required")
	}
	if c.Agent.DataDir == "" {
		return fmt.Errorf("agent.data_dir is required")
	}
	return nil
}

// ClearInstallToken rewrites the YAML config file at path so that
// agent.install_token holds an empty string. Called by the registrar
// after a successful registration so the one-time token doesn't sit
// in /etc/aione-agent/agent.yaml (Linux) or C:\ProgramData\AIOne\Agent\
// agent.yaml (Windows) for the lifetime of the agent install.
//
// Sprint H / Task #H3. The token is single-use — once the registration
// API has consumed it the value in the local YAML is meaningless to
// the server but still readable by anyone with file-system access to
// the host. Clearing it removes the lingering secret-shaped artifact
// and makes "agent.yaml leaked" a non-event on the credential side.
//
// Implementation note — line-level regex replacement, not a YAML
// round-trip. ``yaml.v3`` doesn't preserve comments or operator-
// authored formatting (key ordering, blank-line layout, inline #
// notes), so a Marshal()/WriteFile() cycle would silently rewrite
// the operator's customized agent.yaml every successful registration.
// Regex on the single line lets us touch ONLY the install_token
// value while leaving every other byte of the file untouched.
//
// The replacement is idempotent — calling it on a config whose
// install_token is already empty returns nil without writing.
//
// Returns nil on success or no-op. On any I/O / pattern failure
// returns an error; the caller (registration.EnsureRegistered)
// logs and continues — registration itself has already succeeded
// and the token is already consumed server-side.
func ClearInstallToken(path string) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolving config path: %w", err)
	}

	data, err := os.ReadFile(absPath)
	if err != nil {
		return fmt.Errorf("reading config %s: %w", absPath, err)
	}

	// Match the install_token: line in any of the three common shapes:
	//   install_token: abcXYZ123              # bare scalar
	//   install_token: "abcXYZ123"            # double-quoted
	//   install_token: 'abcXYZ123'            # single-quoted
	// Trailing inline comments (`  # one-time`) are preserved.
	// Whitespace at start of line (YAML indent) is also preserved so
	// nested blocks under a different parent key wouldn't be touched.
	// Captures: 1=indent+key+colon+space, 2=existing value, 3=optional trailing comment.
	pattern := regexp.MustCompile(`(?m)^(\s*install_token:\s*)("[^"]*"|'[^']*'|[^#\s][^\s#]*)(\s*#.*)?$`)

	matched := false
	out := pattern.ReplaceAllStringFunc(string(data), func(line string) string {
		groups := pattern.FindStringSubmatch(line)
		if len(groups) < 3 {
			return line
		}
		// Already empty (covers `""`, `''`, or whitespace-only). Skip.
		val := groups[2]
		if val == `""` || val == `''` {
			return line
		}
		matched = true
		comment := ""
		if len(groups) >= 4 {
			comment = groups[3]
		}
		return groups[1] + `""` + comment
	})

	if !matched {
		// No-op: the file either doesn't have an install_token line
		// (operator removed it manually) or it's already empty. Either
		// way, no write is needed.
		return nil
	}

	// Preserve the file's mode bits where possible. Cert/key files are
	// 0600; agent.yaml typically inherits whatever the installer set
	// (commonly 0640 or 0644 depending on platform). Read it back and
	// restore on write so we don't loosen perms accidentally.
	info, err := os.Stat(absPath)
	if err != nil {
		return fmt.Errorf("stat %s: %w", absPath, err)
	}
	if err := os.WriteFile(absPath, []byte(out), info.Mode().Perm()); err != nil {
		return fmt.Errorf("rewriting config %s: %w", absPath, err)
	}
	return nil
}

// CertPath returns the agent cert path, relative to DataDir if not absolute.
func (c *Config) CertPath() string {
	if c.Transport.CertFile != "" {
		return c.Transport.CertFile
	}
	return filepath.Join(c.Agent.DataDir, "agent.crt")
}

// KeyPath returns the agent key path.
func (c *Config) KeyPath() string {
	if c.Transport.KeyFile != "" {
		return c.Transport.KeyFile
	}
	return filepath.Join(c.Agent.DataDir, "agent.key")
}

// CAPath returns the server CA bundle path.
func (c *Config) CAPath() string {
	if c.Transport.CAFile != "" {
		return c.Transport.CAFile
	}
	return filepath.Join(c.Agent.DataDir, "ca.crt")
}
