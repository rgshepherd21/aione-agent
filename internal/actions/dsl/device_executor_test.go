// Tests for RunDeviceAction (Sprint D / Task #2). These exercise the
// SSH-transport dispatch path end-to-end against the in-process SSH
// server defined in internal/transport/sshclient/client_test.go.
//
// Action YAML is loaded from a tmp dir so each test can author a
// purpose-built action without touching the embedded fallback set.
package dsl

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// ─── Fake credential fetcher ─────────────────────────────────────────────

type fakeFetcher struct {
	cred DeviceCredential
	err  error
	// last call captured for assertions
	calls []fetchCall
}

type fetchCall struct {
	actionID string
	credType string
}

func (f *fakeFetcher) Fetch(_ context.Context, actionID, credType string) (DeviceCredential, error) {
	f.calls = append(f.calls, fetchCall{actionID, credType})
	if f.err != nil {
		return DeviceCredential{}, f.err
	}
	return f.cred, nil
}

// ─── Inline SSH server (self-contained, no cross-package deps) ───────────
//
// Sprint follow-up S1.b: this fake server now drives a PTY + shell
// channel rather than the per-command-exec model from D2/Sprint-I. The
// dsl device executor opens a persistent shell via sshclient.NewShell,
// so the test server has to negotiate pty-req + shell-req and stream
// command echo + canned responses + prompt back over a single channel.
//
// The server doesn't model full Cisco/Arista mode transitions
// (>, #, (config)#) — those are exercised in the sshclient package's
// shell_test.go. Here we just emit a fixed prompt ("Router> ") which
// matches every vendor's AnyPrompt regex; the tests only assert that
// pre_commands and user commands ran and their captured output landed
// in Outcome.Stdout.

type miniServer struct {
	listener net.Listener
	host     ssh.Signer
	authed   ssh.PublicKey // populated for pubkey servers; nil for password servers
	user     string
	password string // populated for password servers; empty for pubkey servers
	resp     map[string]string
	wg       sync.WaitGroup
	closed   chan struct{}

	// hostname is the token used in the prompt. "Router>" matches the
	// cisco_iosxe AnyPrompt regex \S+(?:\(config[^)]*\)#|>|#) — we
	// keep the trailing space so callers can distinguish prompt from
	// command echo on a streaming buffer.
	hostname string
}

func startMiniServer(t *testing.T, user string, authed ssh.PublicKey, resp map[string]string) *miniServer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("hostkey gen: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &miniServer{
		listener: ln,
		host:     hostSigner,
		authed:   authed,
		user:     user,
		resp:     resp,
		closed:   make(chan struct{}),
		hostname: "Router",
	}
	go s.loop(t)
	return s
}

func (s *miniServer) addr() string { return s.listener.Addr().String() }

func (s *miniServer) Close() {
	select {
	case <-s.closed:
		return
	default:
	}
	close(s.closed)
	_ = s.listener.Close()
	s.wg.Wait()
}

func (s *miniServer) loop(t *testing.T) {
	for {
		c, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.closed:
				return
			default:
				return
			}
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConn(t, c)
		}()
	}
}

// handleConn negotiates SSH auth and dispatches accepted session
// channels to handleSession. Auth method is selected by which field
// is populated: ``password`` ⇒ password callback; otherwise pubkey.
func (s *miniServer) handleConn(t *testing.T, c net.Conn) {
	defer c.Close()
	cfg := &ssh.ServerConfig{}
	if s.password != "" {
		pw := s.password
		cfg.PasswordCallback = func(meta ssh.ConnMetadata, attempt []byte) (*ssh.Permissions, error) {
			if meta.User() != s.user {
				return nil, fmt.Errorf("unknown user %q", meta.User())
			}
			if string(attempt) != pw {
				return nil, errors.New("password mismatch")
			}
			return &ssh.Permissions{}, nil
		}
	} else {
		cfg.PublicKeyCallback = func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if meta.User() != s.user {
				return nil, fmt.Errorf("unknown user %q", meta.User())
			}
			if string(key.Marshal()) != string(s.authed.Marshal()) {
				return nil, errors.New("public key mismatch")
			}
			return &ssh.Permissions{}, nil
		}
	}
	cfg.AddHostKey(s.host)
	conn, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	defer conn.Close()
	go ssh.DiscardRequests(reqs)
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "")
			continue
		}
		ch, chReqs, err := newCh.Accept()
		if err != nil {
			continue
		}
		go s.handleSession(t, ch, chReqs)
	}
}

// handleSession negotiates pty-req + shell-req, then runs a tiny
// read-loop: each line received from the client is echoed, the
// command is looked up in s.resp, the canned response is written, and
// a fresh prompt is emitted. ``exit`` (the polite shutdown that
// sshclient.Shell.Close sends) terminates the loop.
func (s *miniServer) handleSession(_ *testing.T, ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()

	gotPty := false
	gotShell := false
	for !gotShell {
		req, ok := <-reqs
		if !ok {
			return
		}
		switch req.Type {
		case "pty-req":
			gotPty = true
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		case "shell":
			if !gotPty {
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
				return
			}
			gotShell = true
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
	go ssh.DiscardRequests(reqs)

	prompt := s.hostname + "> "

	// Initial prompt — sshclient.NewShell waits for this before
	// returning. Without it the new-shell call would time out.
	if _, err := io.WriteString(ch, prompt); err != nil {
		return
	}

	br := newLineReader(ch)
	for {
		line, err := br.ReadLine()
		if err != nil {
			return
		}
		cmd := strings.TrimRight(line, "\r\n")
		// Echo the command — many real PTYs do this regardless of
		// ECHO mode, and sshclient.cleanShellOutput strips it.
		if _, werr := io.WriteString(ch, cmd+"\r\n"); werr != nil {
			return
		}
		// ``exit`` is the graceful shutdown sshclient.Shell.Close sends.
		if cmd == "exit" {
			return
		}
		if out, ok := s.resp[cmd]; ok {
			if out != "" {
				if _, werr := io.WriteString(ch, out); werr != nil {
					return
				}
				if !strings.HasSuffix(out, "\n") && !strings.HasSuffix(out, "\r\n") {
					_, _ = io.WriteString(ch, "\r\n")
				}
			}
		} else {
			// Unknown command: emit a Cisco-shaped error string so
			// the captured stdout is informative if a test fails.
			_, _ = io.WriteString(ch, "% Invalid input detected at '^' marker.\r\n")
		}
		// Issue prompt for next command.
		if _, werr := io.WriteString(ch, prompt); werr != nil {
			return
		}
	}
}

// lineReader returns content up to and including a newline. We avoid
// bufio to sidestep buffering subtleties on the SSH channel (the
// peer's writes may not align with bufio's read-ahead boundaries).
type lineReader struct {
	r   io.Reader
	buf []byte
}

func newLineReader(r io.Reader) *lineReader { return &lineReader{r: r} }

func (lr *lineReader) ReadLine() (string, error) {
	tmp := make([]byte, 1)
	for {
		for i, b := range lr.buf {
			if b == '\n' {
				line := string(lr.buf[:i+1])
				lr.buf = lr.buf[i+1:]
				return line, nil
			}
		}
		n, err := lr.r.Read(tmp)
		if n > 0 {
			lr.buf = append(lr.buf, tmp[:n]...)
		}
		if err != nil {
			if len(lr.buf) > 0 {
				line := string(lr.buf)
				lr.buf = nil
				return line, nil
			}
			return "", err
		}
	}
}

func newKey(t *testing.T) ([]byte, ssh.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("marshal pk: %v", err)
	}
	pubKey, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("pubkey: %v", err)
	}
	return pem.EncodeToMemory(block), pubKey
}

func mustHostPort(t *testing.T, hp string) (string, int) {
	t.Helper()
	h, p, err := net.SplitHostPort(hp)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	var port int
	if _, err := fmt.Sscanf(p, "%d", &port); err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return h, port
}

// ─── Action-construction helper ──────────────────────────────────────────

// buildAction constructs a *KALAction directly from a Raw map, skipping
// schema validation. Sprint D / Task #3 formalized the schema split
// (transport=shell uses `executors:` keyed by OS; transport=ssh/netconf/...
// uses `device_executors:` keyed by vendor). For SSH-mode tests, the
// `executors` arg is populated under the device_executors key; for
// shell-mode tests it goes under `executors`.
func buildAction(id, transport string, executors map[string]interface{}) *KALAction {
	raw := map[string]interface{}{
		"id":             id,
		"version":        1,
		"tier":           1,
		"category":       "network/show",
		"description":    "test action",
		"implementation": "dsl",
		"idempotent":     true,
		"transport":      transport,
		"validators": map[string]interface{}{
			"post_execution": map[string]interface{}{
				"timeout_seconds": 30,
				"exit_code":       0,
			},
		},
		"state_capture": map[string]interface{}{"pre": "none", "post": "stateless"},
		"rollback": map[string]interface{}{
			"possible":  false,
			"rationale": "read-only show command",
		},
		"parameters": map[string]interface{}{
			"schema": map[string]interface{}{
				"type":                 "object",
				"properties":           map[string]interface{}{},
				"additionalProperties": false,
			},
		},
	}
	if transport == "shell" || transport == "" {
		raw["executors"] = executors
	} else {
		raw["device_executors"] = executors
		raw["cred_type"] = "ssh_key"
	}
	return &KALAction{ID: id, Raw: raw}
}

// ciscoShowRunningConfigAction is the canonical D2 test fixture — Cisco
// IOS-XE running-config pull. Mirrors the YAML the C2 backend PR will
// ship under transport: ssh once D3 lands the schema bits.
func ciscoShowRunningConfigAction() *KALAction {
	return buildAction(
		"cisco_ios_show_running_config",
		"ssh",
		map[string]interface{}{
			"cisco_iosxe": map[string]interface{}{
				"pre_commands": []interface{}{"terminal length 0"},
				"command":      "show running-config",
			},
		},
	)
}

// ─── Tests ───────────────────────────────────────────────────────────────

func TestRunDeviceAction_HappyPath(t *testing.T) {
	clientPEM, clientPub := newKey(t)
	srv := startMiniServer(t, "rojadmin", clientPub, map[string]string{
		"terminal length 0":   "",
		"show running-config": "interface GigabitEthernet0/1\n description uplink\n!\n",
	})
	defer srv.Close()

	host, port := mustHostPort(t, srv.addr())

	action := ciscoShowRunningConfigAction()
	fetcher := &fakeFetcher{
		cred: DeviceCredential{
			Type:      "ssh_key",
			Principal: "rojadmin",
			Secret:    string(clientPEM),
			ExpiresAt: time.Now().Add(10 * time.Minute),
		},
	}

	out, err := RunDeviceAction(context.Background(), action, nil,
		DeviceTarget{
			ActionExecutionID: "11111111-2222-3333-4444-555555555555",
			Vendor:            "cisco_iosxe",
			Host:              host,
			Port:              port,
		},
		fetcher,
	)
	if err != nil {
		t.Fatalf("RunDeviceAction: %v", err)
	}
	if !out.Success {
		t.Fatalf("expected Success, got Err=%q AttemptErrs=%v", out.Err, out.AttemptErrs)
	}
	if !strings.Contains(out.Stdout, "interface GigabitEthernet0/1") {
		t.Errorf("unexpected stdout: %q", out.Stdout)
	}
	if out.ExecutorUsed != "ssh:cisco_iosxe" {
		t.Errorf("ExecutorUsed: got %q want ssh:cisco_iosxe", out.ExecutorUsed)
	}
	if len(fetcher.calls) != 1 {
		t.Errorf("expected 1 fetch call, got %d", len(fetcher.calls))
	}
	if fetcher.calls[0].actionID != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("fetch action_id: got %q", fetcher.calls[0].actionID)
	}
	if fetcher.calls[0].credType != "ssh_key" {
		t.Errorf("fetch cred_type: got %q", fetcher.calls[0].credType)
	}
}

func TestRunDeviceAction_RejectsNonSSHTransport(t *testing.T) {
	action := buildAction("test", "shell", map[string]interface{}{
		"linux": map[string]interface{}{
			"binary": "/bin/echo",
			"args":   []interface{}{"hi"},
		},
	})
	_, err := RunDeviceAction(context.Background(), action, nil,
		DeviceTarget{ActionExecutionID: "x", Vendor: "cisco_iosxe", Host: "10.0.0.1"},
		&fakeFetcher{},
	)
	if err == nil {
		t.Fatal("expected error for non-ssh transport")
	}
}

func TestRunDeviceAction_VendorNotSupported(t *testing.T) {
	action := ciscoShowRunningConfigAction()
	_, err := RunDeviceAction(context.Background(), action, nil,
		DeviceTarget{ActionExecutionID: "x", Vendor: "juniper_junos", Host: "10.0.0.1"},
		&fakeFetcher{},
	)
	if err == nil {
		t.Fatal("expected vendor-not-supported error")
	}
	if !strings.Contains(err.Error(), "juniper_junos") {
		t.Errorf("error should name vendor: %v", err)
	}
}

func TestRunDeviceAction_CredentialFetchFailure(t *testing.T) {
	action := ciscoShowRunningConfigAction()
	fetcher := &fakeFetcher{err: errors.New("vault offline")}

	out, err := RunDeviceAction(context.Background(), action, nil,
		DeviceTarget{
			ActionExecutionID: "x", Vendor: "cisco_iosxe", Host: "10.0.0.1",
		},
		fetcher,
	)
	if err == nil {
		t.Fatal("expected error when fetcher fails")
	}
	if !strings.Contains(out.Err, "vault offline") {
		t.Errorf("Outcome.Err should carry the fetcher message: %q", out.Err)
	}
}

func TestRunDeviceAction_RequiresFetcher(t *testing.T) {
	action := ciscoShowRunningConfigAction()
	_, err := RunDeviceAction(context.Background(), action, nil,
		DeviceTarget{ActionExecutionID: "x", Vendor: "cisco_iosxe", Host: "10.0.0.1"},
		nil,
	)
	if err == nil {
		t.Fatal("expected error when fetcher is nil")
	}
}

func TestRunDeviceAction_RequiresActionExecutionID(t *testing.T) {
	action := ciscoShowRunningConfigAction()
	_, err := RunDeviceAction(context.Background(), action, nil,
		DeviceTarget{Vendor: "cisco_iosxe", Host: "10.0.0.1"},
		&fakeFetcher{cred: DeviceCredential{Type: "ssh_key", Principal: "x", Secret: "k"}},
	)
	if err == nil {
		t.Fatal("expected error when ActionExecutionID is empty")
	}
}

func TestRunDeviceAction_RequiresVendor(t *testing.T) {
	action := ciscoShowRunningConfigAction()
	_, err := RunDeviceAction(context.Background(), action, nil,
		DeviceTarget{ActionExecutionID: "x", Host: "10.0.0.1"},
		&fakeFetcher{cred: DeviceCredential{Type: "ssh_key", Principal: "x", Secret: "k"}},
	)
	if err == nil {
		t.Fatal("expected error when Vendor is empty")
	}
}

func TestRunDeviceAction_RejectsNonSSHKeyCredential(t *testing.T) {
	action := ciscoShowRunningConfigAction()
	fetcher := &fakeFetcher{
		cred: DeviceCredential{Type: "api_token", Principal: "x", Secret: "tok_xyz"},
	}
	_, err := RunDeviceAction(context.Background(), action, nil,
		DeviceTarget{ActionExecutionID: "x", Vendor: "cisco_iosxe", Host: "10.0.0.1"},
		fetcher,
	)
	if err == nil {
		t.Fatal("expected error for non-ssh_key cred type")
	}
}

func TestRunDeviceAction_HostFromCredentialAttrs(t *testing.T) {
	clientPEM, clientPub := newKey(t)
	srv := startMiniServer(t, "rojadmin", clientPub, map[string]string{
		"terminal length 0":   "",
		"show running-config": "ok\n",
	})
	defer srv.Close()
	host, port := mustHostPort(t, srv.addr())

	action := ciscoShowRunningConfigAction()
	fetcher := &fakeFetcher{
		cred: DeviceCredential{
			Type:      "ssh_key",
			Principal: "rojadmin",
			Secret:    string(clientPEM),
			Attrs: map[string]string{
				"host": host,
				"port": fmt.Sprintf("%d", port),
			},
			ExpiresAt: time.Now().Add(10 * time.Minute),
		},
	}

	// DeviceTarget host/port left zero — should fall back to cred.Attrs.
	out, err := RunDeviceAction(context.Background(), action, nil,
		DeviceTarget{
			ActionExecutionID: "x",
			Vendor:            "cisco_iosxe",
		},
		fetcher,
	)
	if err != nil {
		t.Fatalf("RunDeviceAction: %v", err)
	}
	if !out.Success {
		t.Fatalf("expected Success: Err=%q", out.Err)
	}
}

// ─── Sprint I: password-auth dispatch ────────────────────────────────────

// startPasswordMiniServer is a sibling of startMiniServer that
// authenticates via PasswordCallback. Mirrors the IOS-XE / DevNet
// sandbox auth model. Both helpers share the same underlying
// miniServer.handleConn path — auth method is selected by which of
// (authed, password) the constructor populated.
func startPasswordMiniServer(t *testing.T, user, password string, resp map[string]string) *miniServer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("hostkey gen: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &miniServer{
		listener: ln,
		host:     hostSigner,
		user:     user,
		password: password,
		resp:     resp,
		closed:   make(chan struct{}),
		hostname: "Router",
	}
	go s.loop(t)
	return s
}

// TestRunDeviceAction_PasswordAuth_DispatchesViaCredType verifies the
// Sprint I behavior: when the issuer hands back ``Type=ssh_password``,
// the executor builds an sshclient.Config that uses Config.Password
// (not PrivateKeyPEM) and the SSH handshake completes against a
// password-only fake server.
func TestRunDeviceAction_PasswordAuth_DispatchesViaCredType(t *testing.T) {
	srv := startPasswordMiniServer(t, "developer", "lastorangerestoreball8876", map[string]string{
		"terminal length 0":   "",
		"show running-config": "Cisco IOS XE Software, Version 17.13.1\n",
	})
	defer srv.Close()
	host, port := mustHostPort(t, srv.addr())

	action := ciscoShowRunningConfigAction()
	fetcher := &fakeFetcher{
		cred: DeviceCredential{
			Type:      "ssh_password",
			Principal: "developer",
			Secret:    "lastorangerestoreball8876",
			Attrs:     map[string]string{"host": host, "port": fmt.Sprintf("%d", port)},
			ExpiresAt: time.Now().Add(10 * time.Minute),
		},
	}

	out, err := RunDeviceAction(context.Background(), action, nil,
		DeviceTarget{ActionExecutionID: "x", Vendor: "cisco_iosxe"},
		fetcher,
	)
	if err != nil {
		t.Fatalf("RunDeviceAction with password auth: %v", err)
	}
	if !out.Success {
		t.Fatalf("expected Success: Err=%q", out.Err)
	}
	if !strings.Contains(out.Stdout, "Cisco IOS XE Software") {
		t.Errorf("unexpected stdout: %q", out.Stdout)
	}
}

// TestRunDeviceAction_PasswordAlias verifies that ``password`` is also
// accepted as a Type alias (some vault backends may emit either string).
func TestRunDeviceAction_PasswordAlias(t *testing.T) {
	srv := startPasswordMiniServer(t, "admin", "letmein", map[string]string{
		"terminal length 0":   "",
		"show running-config": "ok\n",
	})
	defer srv.Close()
	host, port := mustHostPort(t, srv.addr())

	action := ciscoShowRunningConfigAction()
	fetcher := &fakeFetcher{
		cred: DeviceCredential{
			Type:      "password",
			Principal: "admin",
			Secret:    "letmein",
			Attrs:     map[string]string{"host": host, "port": fmt.Sprintf("%d", port)},
			ExpiresAt: time.Now().Add(10 * time.Minute),
		},
	}

	out, err := RunDeviceAction(context.Background(), action, nil,
		DeviceTarget{ActionExecutionID: "x", Vendor: "cisco_iosxe"},
		fetcher,
	)
	if err != nil {
		t.Fatalf("RunDeviceAction password alias: %v", err)
	}
	if !out.Success {
		t.Fatalf("expected Success: Err=%q", out.Err)
	}
}
