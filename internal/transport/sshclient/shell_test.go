// Tests for the persistent-shell SSH transport. Uses an in-process
// fake SSH server that accepts pty-req + shell-req and runs a tiny
// state machine modeling Cisco/Arista CLI mode transitions:
//
//   user EXEC      (>)         [initial state]
//   privileged     (#)         [after ``enable``]
//   config mode    ((config)#) [after ``configure terminal``]
//
// Exit/end pop one mode level. Other commands echo + return canned
// output + the current mode's prompt. This is sufficient to verify:
//
//   * Shell.NewShell waits past the initial prompt before returning.
//   * Send writes a command, reads to the next prompt, and strips
//     command echo + trailing prompt cleanly.
//   * Mode transitions persist across Send calls.
//   * Close terminates the session and the reader goroutine.
//
// No external SSH daemon required — runs in plain ``go test``.
package sshclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
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

// ─── Fake interactive shell server ───────────────────────────────────────

// fakeShellServer is a minimal SSH server that supports pty-req and
// shell-req on a session channel, then drives an interactive state
// machine emulating a Cisco/Arista CLI. Each accepted connection
// runs in its own goroutine until the client closes stdin or exits.
type fakeShellServer struct {
	listener net.Listener
	hostKey  ssh.Signer
	password string // accepted for any user

	// hostname appears in all generated prompts: "<hostname>>"
	hostname string

	// canned holds command → response strings. Commands not in canned
	// produce a "% Invalid input" line. Mode-control commands
	// (enable, configure terminal, exit, end) are handled separately
	// by the state machine and don't go through canned.
	canned map[string]string

	wg     sync.WaitGroup
	closed chan struct{}
}

func newFakeShellServer(t *testing.T, hostname, password string, canned map[string]string) *fakeShellServer {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	s := &fakeShellServer{
		listener: ln,
		hostKey:  hostSigner,
		password: password,
		hostname: hostname,
		canned:   canned,
		closed:   make(chan struct{}),
	}
	go s.serve(t)
	return s
}

func (s *fakeShellServer) addr() string { return s.listener.Addr().String() }

func (s *fakeShellServer) Close() {
	select {
	case <-s.closed:
		return
	default:
	}
	close(s.closed)
	_ = s.listener.Close()
	s.wg.Wait()
}

func (s *fakeShellServer) serve(t *testing.T) {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.closed:
				return
			default:
				t.Logf("fakeShellServer accept: %v", err)
				return
			}
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConn(t, conn)
		}()
	}
}

func (s *fakeShellServer) handleConn(t *testing.T, nConn net.Conn) {
	defer nConn.Close()

	cfg := &ssh.ServerConfig{
		PasswordCallback: func(meta ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if string(pw) != s.password {
				return nil, errors.New("password mismatch")
			}
			return &ssh.Permissions{}, nil
		},
	}
	cfg.AddHostKey(s.hostKey)

	sshConn, chans, reqs, err := ssh.NewServerConn(nConn, cfg)
	if err != nil {
		return
	}
	defer sshConn.Close()
	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "only session supported")
			continue
		}
		ch, chReqs, err := newCh.Accept()
		if err != nil {
			t.Logf("accept channel: %v", err)
			continue
		}
		go s.handleSession(t, ch, chReqs)
	}
}

// handleSession negotiates pty-req and shell-req, then runs the
// mode state machine until the client exits or stdin closes.
func (s *fakeShellServer) handleSession(t *testing.T, ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()

	gotPty := false
	gotShell := false

	// Pre-shell phase: handle pty-req and shell-req.
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

	// Discard any further channel requests in the background.
	go ssh.DiscardRequests(reqs)

	// Mode stack: 0=user EXEC ">", 1=privileged "#", 2=config "(config)#"
	mode := 0
	prompt := func() string {
		switch mode {
		case 2:
			return s.hostname + "(config)# "
		case 1:
			return s.hostname + "# "
		default:
			return s.hostname + "> "
		}
	}

	// Initial prompt.
	if _, err := io.WriteString(ch, prompt()); err != nil {
		return
	}

	// Read commands line by line. The client sends "<cmd>\n".
	br := newLineReader(ch)
	for {
		line, err := br.ReadLine()
		if err != nil {
			return
		}
		cmd := strings.TrimRight(line, "\r\n")
		// Echo the command (mimic real PTY behavior even though we
		// disabled ECHO — many devices echo regardless).
		if _, werr := io.WriteString(ch, cmd+"\r\n"); werr != nil {
			return
		}

		// Mode transitions — handled before canned lookup.
		switch cmd {
		case "enable":
			if mode < 1 {
				mode = 1
			}
			if _, werr := io.WriteString(ch, prompt()); werr != nil {
				return
			}
			continue
		case "configure terminal", "config terminal", "configure":
			if mode == 1 {
				mode = 2
			}
			if _, werr := io.WriteString(ch, prompt()); werr != nil {
				return
			}
			continue
		case "exit", "end":
			if mode > 0 {
				mode--
			} else {
				// User-EXEC ``exit`` ends the session.
				return
			}
			if _, werr := io.WriteString(ch, prompt()); werr != nil {
				return
			}
			continue
		}

		// Canned command lookup.
		if out, ok := s.canned[cmd]; ok {
			if out != "" {
				if _, werr := io.WriteString(ch, out); werr != nil {
					return
				}
				if !strings.HasSuffix(out, "\r\n") && !strings.HasSuffix(out, "\n") {
					_, _ = io.WriteString(ch, "\r\n")
				}
			}
		} else {
			_, _ = io.WriteString(ch, "% Invalid input detected at '^' marker.\r\n")
		}
		// Issue prompt for next command.
		if _, werr := io.WriteString(ch, prompt()); werr != nil {
			return
		}
	}
}

// lineReader wraps an io.Reader exposing a ReadLine method that
// returns content up to and including a newline. We avoid bufio
// to sidestep buffering subtleties on the SSH channel.
type lineReader struct {
	r   io.Reader
	buf []byte
}

func newLineReader(r io.Reader) *lineReader { return &lineReader{r: r} }

func (lr *lineReader) ReadLine() (string, error) {
	tmp := make([]byte, 1)
	for {
		// Look for an existing newline in the buffer first.
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

// ─── Test helpers ────────────────────────────────────────────────────────

// dialFakeShell connects to the fake server with password auth and
// returns a Client suitable for NewShell. Caller closes the Client.
func dialFakeShell(t *testing.T, srv *fakeShellServer) *Client {
	t.Helper()
	host, port := splitHostPort(t, srv.addr())
	cli, err := Connect(context.Background(), Config{
		Host:       host,
		Port:       port,
		User:       "rojadmin",
		AuthMethod: AuthMethodPassword,
		Password:   srv.password,
	})
	if err != nil {
		t.Fatalf("dial fake shell: %v", err)
	}
	return cli
}

// ─── Tests ───────────────────────────────────────────────────────────────

func TestShell_NewShellReadsInitialPrompt(t *testing.T) {
	srv := newFakeShellServer(t, "ceos-1", "secret", map[string]string{})
	defer srv.Close()

	cli := dialFakeShell(t, srv)
	defer cli.Close()

	cfg, err := ShellConfigFor("arista_eos")
	if err != nil {
		t.Fatalf("vendor lookup: %v", err)
	}
	cfg.CommandTimeout = 5 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sh, err := cli.NewShell(ctx, cfg)
	if err != nil {
		t.Fatalf("NewShell: %v", err)
	}
	defer sh.Close()
	// If we got here, the initial prompt matched. There's nothing
	// else to assert structurally — the absence of a hang/timeout
	// is the test.
}

func TestShell_SendCapturesCommandOutput(t *testing.T) {
	srv := newFakeShellServer(t, "ceos-1", "secret", map[string]string{
		"show version":      "Arista vEOS-lab\nSoftware image version: 4.35.4M\nUptime: 2 days",
		"show ip interface": "Ethernet1 is up, line protocol is up",
	})
	defer srv.Close()

	cli := dialFakeShell(t, srv)
	defer cli.Close()

	cfg, _ := ShellConfigFor("arista_eos")
	cfg.CommandTimeout = 5 * time.Second
	sh, err := cli.NewShell(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewShell: %v", err)
	}
	defer sh.Close()

	out, err := sh.Send(context.Background(), "show version")
	if err != nil {
		t.Fatalf("Send show version: %v", err)
	}
	if !strings.Contains(out, "Arista vEOS-lab") {
		t.Errorf("expected output to include 'Arista vEOS-lab', got: %q", out)
	}
	if strings.Contains(out, "ceos-1>") {
		t.Errorf("output should not contain trailing prompt, got: %q", out)
	}
	if strings.HasPrefix(out, "show version") {
		t.Errorf("output should not contain echoed command, got: %q", out)
	}
}

func TestShell_ModeTransitionsPersistAcrossSend(t *testing.T) {
	srv := newFakeShellServer(t, "ceos-1", "secret", map[string]string{
		"interface Ethernet1": "",                  // valid in config mode
		"shutdown":            "",                  // valid in config mode
		"do show running":     "running config…",   // privileged-only "do" command
	})
	defer srv.Close()

	cli := dialFakeShell(t, srv)
	defer cli.Close()

	cfg, _ := ShellConfigFor("arista_eos")
	cfg.CommandTimeout = 5 * time.Second
	sh, err := cli.NewShell(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewShell: %v", err)
	}
	defer sh.Close()

	// Step 1: enable transitions ">" → "#".
	if _, err := sh.Send(context.Background(), "enable"); err != nil {
		t.Fatalf("Send enable: %v", err)
	}
	// Step 2: configure terminal transitions "#" → "(config)#".
	if _, err := sh.Send(context.Background(), "configure terminal"); err != nil {
		t.Fatalf("Send configure terminal: %v", err)
	}
	// Step 3: a config-mode command should succeed cleanly. The fake
	// server returns "" canned output, so we mainly verify no
	// "Invalid input" error sneaks back.
	out, err := sh.Send(context.Background(), "interface Ethernet1")
	if err != nil {
		t.Fatalf("Send interface Ethernet1: %v", err)
	}
	if strings.Contains(out, "Invalid input") {
		t.Errorf("config-mode command rejected unexpectedly: %q", out)
	}

	// Step 4: end pops back to "#".
	if _, err := sh.Send(context.Background(), "end"); err != nil {
		t.Fatalf("Send end: %v", err)
	}
	// Step 5: another end pops back to ">".
	if _, err := sh.Send(context.Background(), "end"); err != nil {
		t.Fatalf("Send end (2): %v", err)
	}
}

func TestShell_CloseIsIdempotent(t *testing.T) {
	srv := newFakeShellServer(t, "ceos-1", "secret", map[string]string{})
	defer srv.Close()

	cli := dialFakeShell(t, srv)
	defer cli.Close()

	cfg, _ := ShellConfigFor("arista_eos")
	cfg.CommandTimeout = 5 * time.Second
	sh, err := cli.NewShell(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewShell: %v", err)
	}

	if err := sh.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := sh.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	if _, err := sh.Send(context.Background(), "show version"); err == nil {
		t.Error("expected error sending on closed shell, got nil")
	}
}

func TestShell_SendTimeoutWhenNoPromptArrives(t *testing.T) {
	// Build a server that swallows commands and never replies — this
	// forces Send to hit its CommandTimeout.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Negotiate SSH but then idle.
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		hostSigner, _ := ssh.NewSignerFromKey(priv)
		cfg := &ssh.ServerConfig{
			PasswordCallback: func(_ ssh.ConnMetadata, _ []byte) (*ssh.Permissions, error) {
				return &ssh.Permissions{}, nil
			},
		}
		cfg.AddHostKey(hostSigner)
		sshConn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
		if err != nil {
			return
		}
		defer sshConn.Close()
		go ssh.DiscardRequests(reqs)
		for newCh := range chans {
			ch, chReqs, err := newCh.Accept()
			if err != nil {
				continue
			}
			go func() {
				for req := range chReqs {
					if req.WantReply {
						_ = req.Reply(true, nil)
					}
				}
				_ = ch.Close()
			}()
			// Never write anything — Shell will wait for prompt and
			// hit its CommandTimeout instead.
		}
	}()

	host, port := splitHostPort(t, listener.Addr().String())
	cli, err := Connect(context.Background(), Config{
		Host:       host,
		Port:       port,
		User:       "x",
		AuthMethod: AuthMethodPassword,
		Password:   "anything",
	})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer cli.Close()

	cfg, _ := ShellConfigFor("arista_eos")
	cfg.CommandTimeout = 250 * time.Millisecond

	start := time.Now()
	_, err = cli.NewShell(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected NewShell to time out without an initial prompt")
	}
	elapsed := time.Since(start)
	if elapsed > 2*time.Second {
		t.Errorf("NewShell hung past timeout: %v", elapsed)
	}
}

func TestShellConfigFor_UnknownVendor(t *testing.T) {
	_, err := ShellConfigFor("totally_made_up_vendor")
	if err == nil {
		t.Fatal("expected error for unknown vendor")
	}
	if !strings.Contains(err.Error(), "totally_made_up_vendor") {
		t.Errorf("error should mention the bad vendor name: %v", err)
	}
	if !strings.Contains(err.Error(), "known:") {
		t.Errorf("error should list known vendors: %v", err)
	}
}

func TestCleanShellOutput_StripsEchoAndPrompt(t *testing.T) {
	cfg, _ := ShellConfigFor("arista_eos")
	raw := "show version\r\nArista vEOS-lab\r\nUptime: 2 days\r\nceos-1> "
	got := cleanShellOutput(raw, "show version", cfg.AnyPrompt)
	want := "Arista vEOS-lab\r\nUptime: 2 days"
	if got != want {
		t.Errorf("clean output mismatch:\n  got:  %q\n  want: %q", got, want)
	}
}

func TestVendorPromptRegexes_MatchExpectedShapes(t *testing.T) {
	cases := []struct {
		vendor string
		input  string
		any    bool
	}{
		{"cisco_iosxe", "Router> ", true},
		{"cisco_iosxe", "Router# ", true},
		{"cisco_iosxe", "Router(config)# ", true},
		{"cisco_iosxe", "Router(config-if)# ", true},
		{"arista_eos", "ceos-1> ", true},
		{"arista_eos", "ceos-1# ", true},
		{"arista_eos", "ceos-1(config)# ", true},
		{"arista_eos", "this is not a prompt", false},
		{"juniper_junos", "user@vmx> ", true},
		{"juniper_junos", "user@vmx# ", true},
		{"juniper_junos", "user@vmx ", false},
	}

	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s/%s", tc.vendor, strings.TrimSpace(tc.input)), func(t *testing.T) {
			cfg, err := ShellConfigFor(tc.vendor)
			if err != nil {
				t.Fatalf("vendor lookup: %v", err)
			}
			got := cfg.AnyPrompt.MatchString(tc.input)
			if got != tc.any {
				t.Errorf("AnyPrompt match for %q: got %v, want %v", tc.input, got, tc.any)
			}
		})
	}
}
