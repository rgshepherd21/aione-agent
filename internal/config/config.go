package config

import (
	"fmt"
	"os"
	"path/filepath"
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
	Log       LogConfig       `yaml:"log"`
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
