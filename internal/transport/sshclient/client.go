// Package sshclient implements the SSH transport for KAL device actions.
//
// Connection model: per-action connect-run-close (Netmiko-style). No pooling.
// Every action gets a fresh SSH handshake with freshly-issued credentials.
// This trades some throughput for a clean security model — short-lived
// per-action credentials never sit on a long-lived connection.
//
// Authentication: dispatches on Config.AuthMethod.
//   - "ssh_key" — Secret is a PEM-encoded SSH private key (the historical
//     v1 default; cEOS-lab and any tenant that hands out keys).
//   - "password" / "ssh_password" — Secret is the SSH password literal
//     (Cisco DevNet sandbox, devices behind RADIUS/TACACS where passwords
//     are the only path).
//
// In both cases, Principal is the SSH username, sourced from the
// platform-issued ActionCred bundle.
//
// Host key checking: configurable via Config.HostKeyCallback. The default is
// ssh.InsecureIgnoreHostKey() — appropriate for greenfield lab use, where
// every device's host key may not have been pinned yet. Production tenants
// should set a tighter callback that pins host keys per device. There's a
// TODO in the executor that wires Device.host_key_fingerprint through to
// this layer once that column lands.
package sshclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
)

// AuthMethod selects how Connect authenticates to the device. The string
// values match what the platform's credential issuer returns in
// ``ActionCred.Type`` so the executor can pass the value through verbatim.
type AuthMethod string

const (
	// AuthMethodPrivateKey: Config.PrivateKeyPEM holds a PEM-encoded SSH key.
	AuthMethodPrivateKey AuthMethod = "ssh_key"
	// AuthMethodPassword: Config.Password holds the SSH password.
	// "password" and "ssh_password" are accepted aliases — both surface
	// from real-world vaults; we normalize on the way in.
	AuthMethodPassword    AuthMethod = "password"
	AuthMethodSSHPassword AuthMethod = "ssh_password"
)

// MaxOutputBytes caps per-command stdout/stderr capture. Sized for 'show
// running-config' on a busy core switch (~200KB of text); bigger configs
// are truncated rather than crash the agent. Mirrors MaxCaptureBytes in
// the shell executor for consistency.
const MaxOutputBytes = 256 * 1024

// DefaultDialTimeout is the SSH TCP/handshake deadline. Devices on
// congested links sometimes take >5s to negotiate; 15s is generous but
// still fails fast on truly unreachable boxes.
const DefaultDialTimeout = 15 * time.Second

// DefaultCommandTimeout is the per-command read deadline. Long enough
// for slow-rendering CLI ('show tech-support' on a chassis switch);
// short enough that a hung session doesn't lock an action forever.
const DefaultCommandTimeout = 60 * time.Second

// Config holds the parameters needed to open an SSH session against a
// network device.
type Config struct {
	// Host is the management IP or hostname of the target device.
	Host string

	// Port defaults to 22 if zero.
	Port int

	// User is the SSH login principal. Sourced from the platform-issued
	// ActionCred.Principal.
	User string

	// AuthMethod selects between key and password auth. Defaults to
	// AuthMethodPrivateKey when zero — preserves the pre-Sprint-I behavior
	// where the only path was ssh_key, so existing call sites that haven't
	// been updated yet keep working as long as PrivateKeyPEM is populated.
	AuthMethod AuthMethod

	// PrivateKeyPEM is the PEM-encoded SSH private key. Sourced from the
	// platform-issued ActionCred.Secret when ``Type`` is ``ssh_key``.
	// Never persisted to disk — used in-memory then discarded. Required
	// when AuthMethod is AuthMethodPrivateKey.
	PrivateKeyPEM []byte

	// Password is the literal SSH password. Required when AuthMethod is
	// AuthMethodPassword or AuthMethodSSHPassword. Same in-memory-only
	// lifecycle as PrivateKeyPEM.
	Password string

	// HostKeyCallback validates the device's host key. Defaults to
	// ssh.InsecureIgnoreHostKey() if nil — see package doc.
	HostKeyCallback ssh.HostKeyCallback

	// DialTimeout caps the TCP/SSH handshake. Defaults to DefaultDialTimeout.
	DialTimeout time.Duration

	// CommandTimeout caps each per-command session. Defaults to DefaultCommandTimeout.
	CommandTimeout time.Duration

	// PreCommands run before the user's commands on every connection —
	// typically vendor-specific terminal setup like ``terminal length 0``
	// (Cisco) or ``set cli screen-length 0`` (Junos) so output isn't paged.
	// Each pre-command's output is discarded; failures are returned as
	// connection errors.
	PreCommands []string
}

// Client wraps an ssh.Client connected to a single network device.
// Single-use by convention: open with Connect, run with Run / RunSequence,
// then Close. Concurrent calls on the same Client are not supported.
type Client struct {
	cfg  Config
	conn *ssh.Client
}

// Connect dials the device and completes the SSH handshake. The provided
// context bounds the handshake itself; once Connect returns, per-command
// timeouts are governed by Config.CommandTimeout.
func Connect(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.Host == "" {
		return nil, errors.New("sshclient: Host is required")
	}
	if cfg.User == "" {
		return nil, errors.New("sshclient: User is required")
	}
	if cfg.Port == 0 {
		cfg.Port = 22
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = DefaultDialTimeout
	}
	if cfg.CommandTimeout == 0 {
		cfg.CommandTimeout = DefaultCommandTimeout
	}
	if cfg.HostKeyCallback == nil {
		// See package doc: lab-default. Production should pin.
		cfg.HostKeyCallback = ssh.InsecureIgnoreHostKey() //nolint:gosec
	}

	// Default AuthMethod — preserve pre-Sprint-I behavior for any caller
	// that hasn't been updated to set the field. If they're passing
	// PrivateKeyPEM, treat it as ssh_key; otherwise leave zero so the
	// switch below errors with a clear message.
	if cfg.AuthMethod == "" && len(cfg.PrivateKeyPEM) > 0 {
		cfg.AuthMethod = AuthMethodPrivateKey
	}

	authMethods, err := buildAuthMethods(cfg)
	if err != nil {
		return nil, err
	}

	clientCfg := &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            authMethods,
		HostKeyCallback: cfg.HostKeyCallback,
		Timeout:         cfg.DialTimeout,
	}

	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))

	// Honor the caller's context for the dial: if ctx is cancelled
	// before the handshake completes, abort.
	dialer := net.Dialer{Timeout: cfg.DialTimeout}
	tcpConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("sshclient: dial %s: %w", addr, err)
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(tcpConn, addr, clientCfg)
	if err != nil {
		_ = tcpConn.Close()
		return nil, fmt.Errorf("sshclient: ssh handshake to %s: %w", addr, err)
	}
	conn := ssh.NewClient(sshConn, chans, reqs)

	c := &Client{cfg: cfg, conn: conn}

	// Run pre-commands (e.g. ``terminal length 0``). Failures abort the
	// connection — if we can't disable paging we'd just pull truncated
	// output later, which is worse than failing fast.
	for _, pre := range cfg.PreCommands {
		if _, _, err := c.run(ctx, pre); err != nil {
			_ = c.Close()
			return nil, fmt.Errorf("sshclient: pre-command %q: %w", pre, err)
		}
	}

	return c, nil
}

// Run executes a single command and returns its stdout (combined with
// stderr — many vendor CLIs blur the two). Output is truncated to
// MaxOutputBytes.
func (c *Client) Run(ctx context.Context, command string) (string, error) {
	if c == nil || c.conn == nil {
		return "", errors.New("sshclient: Run on closed client")
	}
	out, _, err := c.run(ctx, command)
	return out, err
}

// RunSequence executes multiple commands on the same connection (each in
// its own session) and returns the concatenated outputs separated by a
// blank line and a marker comment so callers parsing the result can split
// per command. Stops on the first failure.
func (c *Client) RunSequence(ctx context.Context, commands []string) (string, error) {
	if c == nil || c.conn == nil {
		return "", errors.New("sshclient: RunSequence on closed client")
	}
	var combined bytes.Buffer
	for i, cmd := range commands {
		if i > 0 {
			combined.WriteString("\n")
		}
		fmt.Fprintf(&combined, "! ===== %s =====\n", cmd)
		out, _, err := c.run(ctx, cmd)
		if err != nil {
			return combined.String(), err
		}
		combined.WriteString(out)
	}
	return combined.String(), nil
}

// run is the inner per-command primitive. Returns stdout, stderr, error.
// Bound by ctx (callers' wrap) and Config.CommandTimeout (defense).
func (c *Client) run(ctx context.Context, command string) (string, string, error) {
	session, err := c.conn.NewSession()
	if err != nil {
		return "", "", fmt.Errorf("new session: %w", err)
	}
	defer session.Close()

	// Bound this command by ctx OR cfg.CommandTimeout, whichever is sooner.
	cmdCtx, cancel := context.WithTimeout(ctx, c.cfg.CommandTimeout)
	defer cancel()

	var stdout, stderr cappedBuffer
	stdout.cap = MaxOutputBytes
	stderr.cap = MaxOutputBytes
	session.Stdout = &stdout
	session.Stderr = &stderr

	done := make(chan error, 1)
	go func() { done <- session.Run(command) }()

	select {
	case <-cmdCtx.Done():
		// Best-effort cancel — closing the session forces the goroutine
		// to return and releases server resources.
		_ = session.Signal(ssh.SIGTERM)
		_ = session.Close()
		return stdout.String(), stderr.String(),
			fmt.Errorf("command %q: %w", command, cmdCtx.Err())
	case err := <-done:
		if err != nil {
			// ssh.ExitError is a normal nonzero exit — return it as a
			// command failure with the captured output. ssh.ExitMissingError
			// (server killed the session) and dial errors are also surfaced
			// with their captured-so-far output.
			return stdout.String(), stderr.String(),
				fmt.Errorf("command %q: %w", command, err)
		}
		return stdout.String(), stderr.String(), nil
	}
}

// Close tears down the SSH connection. Idempotent.
func (c *Client) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	return err
}

// buildAuthMethods translates the typed AuthMethod + secret material on
// Config into the slice of ssh.AuthMethod that golang.org/x/crypto/ssh
// expects in ClientConfig.Auth.
//
// Errors here are config errors at the caller, not transient device
// errors — surfacing them with sshclient: prefixes keeps them easy to
// distinguish from network failures during incident triage.
func buildAuthMethods(cfg Config) ([]ssh.AuthMethod, error) {
	switch cfg.AuthMethod {
	case AuthMethodPrivateKey:
		if len(cfg.PrivateKeyPEM) == 0 {
			return nil, errors.New("sshclient: PrivateKeyPEM is required for ssh_key auth")
		}
		signer, err := ssh.ParsePrivateKey(cfg.PrivateKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("sshclient: parse private key: %w", err)
		}
		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil

	case AuthMethodPassword, AuthMethodSSHPassword:
		if cfg.Password == "" {
			return nil, fmt.Errorf("sshclient: Password is required for %q auth", cfg.AuthMethod)
		}
		// Many network devices advertise ``keyboard-interactive`` instead
		// of (or in addition to) plain ``password`` auth — Arista cEOS
		// is the canonical case. OpenSSH's CLI transparently falls back;
		// golang.org/x/crypto/ssh requires us to explicitly offer both.
		// Using the same password for every challenge prompt is the
		// standard pattern for CLI/device auth (one prompt → one
		// answer → success).
		pw := cfg.Password
		kbd := ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
			answers := make([]string, len(questions))
			for i := range questions {
				answers[i] = pw
			}
			return answers, nil
		})
		return []ssh.AuthMethod{ssh.Password(pw), kbd}, nil

	case "":
		return nil, errors.New("sshclient: AuthMethod is required (set ssh_key, password, or ssh_password)")
	}

	return nil, fmt.Errorf("sshclient: unsupported AuthMethod %q (expected ssh_key, password, or ssh_password)", cfg.AuthMethod)
}

// cappedBuffer is a bytes.Buffer that silently drops writes past `cap`
// bytes. Mirrors the helper in the shell executor.
type cappedBuffer struct {
	bytes.Buffer
	cap int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	remaining := b.cap - b.Buffer.Len()
	if remaining <= 0 {
		return len(p), nil
	}
	if len(p) > remaining {
		p = p[:remaining]
	}
	return b.Buffer.Write(p)
}

