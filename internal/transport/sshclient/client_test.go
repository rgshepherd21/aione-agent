// Tests for sshclient. Spins up an in-process SSH server backed by
// golang.org/x/crypto/ssh, then exercises Connect / Run / RunSequence /
// Close against it. No external SSH daemon required — runs in plain
// `go test`.
package sshclient

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

	"golang.org/x/crypto/ssh"
)

// ─── Test SSH server harness ─────────────────────────────────────────────

// fakeServer is a minimal in-process SSH server. Each command executed
// by a client looks up a canned response in `responses`; unknown
// commands get a nonzero exit + stderr message. Pre-commands set during
// Config construction route through the same handler.
type fakeServer struct {
	listener   net.Listener
	hostKey    ssh.Signer
	authedKey  ssh.PublicKey
	authedUser string

	// passwordOverride, when non-empty, drives PasswordCallback flows
	// (newFakePasswordServer). Empty means key-auth is in use.
	passwordOverride string

	responses map[string]string // command → stdout

	wg     sync.WaitGroup
	closed chan struct{}
}

func newFakeServer(t *testing.T, authedUser string, authedKey ssh.PublicKey, responses map[string]string) *fakeServer {
	t.Helper()

	hostSigner := newEd25519HostSigner(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	s := &fakeServer{
		listener:   listener,
		hostKey:    hostSigner,
		authedKey:  authedKey,
		authedUser: authedUser,
		responses:  responses,
		closed:     make(chan struct{}),
	}
	go s.serve(t)
	return s
}

func (s *fakeServer) addr() string { return s.listener.Addr().String() }

func (s *fakeServer) Close() {
	select {
	case <-s.closed:
		return
	default:
	}
	close(s.closed)
	_ = s.listener.Close()
	s.wg.Wait()
}

func (s *fakeServer) serve(t *testing.T) {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.closed:
				return
			default:
				t.Logf("accept: %v", err)
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

func (s *fakeServer) handleConn(t *testing.T, nConn net.Conn) {
	defer nConn.Close()

	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if meta.User() != s.authedUser {
				return nil, fmt.Errorf("unknown user %q", meta.User())
			}
			if !keysEqual(key, s.authedKey) {
				return nil, errors.New("public key mismatch")
			}
			return &ssh.Permissions{}, nil
		},
	}
	cfg.AddHostKey(s.hostKey)

	sshConn, chans, reqs, err := ssh.NewServerConn(nConn, cfg)
	if err != nil {
		// Auth failures land here — expected in negative tests.
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
		go s.handleSession(ch, chReqs)
	}
}

func (s *fakeServer) handleSession(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	for req := range reqs {
		switch req.Type {
		case "exec":
			cmd := parseExecPayload(req.Payload)
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			out, ok := s.responses[cmd]
			if !ok {
				_, _ = ch.Stderr().Write([]byte("unknown command: " + cmd + "\n"))
				_, _ = ch.SendRequest("exit-status", false, exitStatus(1))
				return
			}
			_, _ = io.WriteString(ch, out)
			_, _ = ch.SendRequest("exit-status", false, exitStatus(0))
			return
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

func parseExecPayload(p []byte) string {
	// First 4 bytes: big-endian length of the command string per RFC 4254.
	if len(p) < 4 {
		return ""
	}
	n := int(p[0])<<24 | int(p[1])<<16 | int(p[2])<<8 | int(p[3])
	if 4+n > len(p) {
		return ""
	}
	return string(p[4 : 4+n])
}

func exitStatus(code uint32) []byte {
	return []byte{
		byte(code >> 24), byte(code >> 16), byte(code >> 8), byte(code),
	}
}

func keysEqual(a, b ssh.PublicKey) bool { return string(a.Marshal()) == string(b.Marshal()) }

// newEd25519HostSigner mints a fresh ed25519 keypair and returns the
// ssh.Signer over its private half. Used for the fake server's host key.
func newEd25519HostSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 gen: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return signer
}

// newClientKeyPair returns (PEM-encoded private key bytes, ssh.PublicKey).
// The PEM bytes are what the production code receives via
// ActionCred.Secret; the ssh.PublicKey is what the fake server pins as
// the authorized identity.
func newClientKeyPair(t *testing.T) ([]byte, ssh.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 gen: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(block)
	pubKey, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	return pemBytes, pubKey
}

func splitHostPort(t *testing.T, hostport string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return host, port
}

// ─── Tests ───────────────────────────────────────────────────────────────

func TestConnect_RunsCommandSuccessfully(t *testing.T) {
	clientPEM, clientPub := newClientKeyPair(t)
	server := newFakeServer(t, "rojadmin", clientPub, map[string]string{
		"show version": "Cisco IOS XE Software, Version 17.9.1\n",
	})
	defer server.Close()

	host, port := splitHostPort(t, server.addr())
	cli, err := Connect(context.Background(), Config{
		Host:          host,
		Port:          port,
		User:          "rojadmin",
		PrivateKeyPEM: clientPEM,
	})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer cli.Close()

	out, err := cli.Run(context.Background(), "show version")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(out, "Cisco IOS XE Software") {
		t.Errorf("unexpected output: %q", out)
	}
}

func TestConnect_RejectsBadKey(t *testing.T) {
	_, serverAuthorizedKey := newClientKeyPair(t)
	wrongPEM, _ := newClientKeyPair(t)
	server := newFakeServer(t, "rojadmin", serverAuthorizedKey, map[string]string{
		"show version": "ok",
	})
	defer server.Close()

	host, port := splitHostPort(t, server.addr())
	_, err := Connect(context.Background(), Config{
		Host:          host,
		Port:          port,
		User:          "rojadmin",
		PrivateKeyPEM: wrongPEM,
	})
	if err == nil {
		t.Fatal("expected handshake failure with mismatched key")
	}
}

func TestConnect_PreCommandsRun(t *testing.T) {
	clientPEM, clientPub := newClientKeyPair(t)
	server := newFakeServer(t, "rojadmin", clientPub, map[string]string{
		"terminal length 0":   "",
		"show running-config": "interface Gi0/1\n description uplink\n!\n",
	})
	defer server.Close()

	host, port := splitHostPort(t, server.addr())
	cli, err := Connect(context.Background(), Config{
		Host:          host,
		Port:          port,
		User:          "rojadmin",
		PrivateKeyPEM: clientPEM,
		PreCommands:   []string{"terminal length 0"},
	})
	if err != nil {
		t.Fatalf("Connect with pre-commands: %v", err)
	}
	defer cli.Close()

	out, err := cli.Run(context.Background(), "show running-config")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(out, "interface Gi0/1") {
		t.Errorf("unexpected output: %q", out)
	}
}

func TestRunSequence_ConcatenatesWithMarkers(t *testing.T) {
	clientPEM, clientPub := newClientKeyPair(t)
	server := newFakeServer(t, "rojadmin", clientPub, map[string]string{
		"show ip route":      "S* 0.0.0.0/0 [1/0] via 192.168.1.1\n",
		"show ip ospf neigh": "Neighbor ID 10.0.0.2 Full/DR\n",
	})
	defer server.Close()

	host, port := splitHostPort(t, server.addr())
	cli, err := Connect(context.Background(), Config{
		Host:          host,
		Port:          port,
		User:          "rojadmin",
		PrivateKeyPEM: clientPEM,
	})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer cli.Close()

	out, err := cli.RunSequence(context.Background(),
		[]string{"show ip route", "show ip ospf neigh"},
	)
	if err != nil {
		t.Fatalf("RunSequence: %v", err)
	}
	if !strings.Contains(out, "===== show ip route =====") {
		t.Errorf("missing marker for first cmd: %q", out)
	}
	if !strings.Contains(out, "===== show ip ospf neigh =====") {
		t.Errorf("missing marker for second cmd: %q", out)
	}
	if !strings.Contains(out, "0.0.0.0/0") {
		t.Errorf("missing first cmd output: %q", out)
	}
	if !strings.Contains(out, "Neighbor ID") {
		t.Errorf("missing second cmd output: %q", out)
	}
}

func TestRun_NonZeroExitReturnsError(t *testing.T) {
	clientPEM, clientPub := newClientKeyPair(t)
	server := newFakeServer(t, "rojadmin", clientPub, map[string]string{
		"show version": "ok",
		// "show garbage" intentionally not in responses → server returns
		// nonzero exit + stderr message.
	})
	defer server.Close()

	host, port := splitHostPort(t, server.addr())
	cli, err := Connect(context.Background(), Config{
		Host:          host,
		Port:          port,
		User:          "rojadmin",
		PrivateKeyPEM: clientPEM,
	})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer cli.Close()

	_, err = cli.Run(context.Background(), "show garbage")
	if err == nil {
		t.Fatal("expected error from unknown command")
	}
}

func TestRun_CancelledContextSurfacedAsError(t *testing.T) {
	// Use a pre-cancelled context rather than racing a tiny timeout
	// against an in-process round-trip. Verifies the run() select-on-
	// ctx.Done branch fires correctly.
	clientPEM, clientPub := newClientKeyPair(t)
	server := newFakeServer(t, "rojadmin", clientPub, map[string]string{
		"show version": "ok",
	})
	defer server.Close()

	host, port := splitHostPort(t, server.addr())
	cli, err := Connect(context.Background(), Config{
		Host:          host,
		Port:          port,
		User:          "rojadmin",
		PrivateKeyPEM: clientPEM,
	})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer cli.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before issuing the command

	_, err = cli.Run(ctx, "show version")
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
	if !strings.Contains(err.Error(), "context") &&
		!strings.Contains(err.Error(), "canceled") &&
		!strings.Contains(err.Error(), "cancelled") {
		t.Errorf("error doesn't look like a cancellation: %v", err)
	}
}

func TestClose_IsIdempotent(t *testing.T) {
	clientPEM, clientPub := newClientKeyPair(t)
	server := newFakeServer(t, "rojadmin", clientPub, map[string]string{
		"show version": "ok",
	})
	defer server.Close()

	host, port := splitHostPort(t, server.addr())
	cli, err := Connect(context.Background(), Config{
		Host:          host,
		Port:          port,
		User:          "rojadmin",
		PrivateKeyPEM: clientPEM,
	})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if err := cli.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := cli.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	if _, err := cli.Run(context.Background(), "show version"); err == nil {
		t.Error("expected error running on closed client")
	}
}

func TestConnect_RequiresUserAndKey(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"no host", Config{User: "x", PrivateKeyPEM: []byte("k")}},
		{"no user", Config{Host: "127.0.0.1", PrivateKeyPEM: []byte("k")}},
		{"no key", Config{Host: "127.0.0.1", User: "x"}},
		{"explicit ssh_key with no key", Config{
			Host: "127.0.0.1", User: "x", AuthMethod: AuthMethodPrivateKey,
		}},
		{"password auth with no password", Config{
			Host: "127.0.0.1", User: "x", AuthMethod: AuthMethodPassword,
		}},
		{"unknown auth method", Config{
			Host: "127.0.0.1", User: "x", AuthMethod: AuthMethod("kerberos"),
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Connect(context.Background(), c.cfg); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

// ─── Password auth tests (Sprint I) ──────────────────────────────────────

// newFakePasswordServer is a sibling of newFakeServer that authenticates
// via PasswordCallback instead of PublicKeyCallback. Mirrors what real
// IOS-XE / DevNet sandboxes look like to the agent.
func newFakePasswordServer(t *testing.T, authedUser, authedPassword string, responses map[string]string) *fakeServer {
	t.Helper()

	hostSigner := newEd25519HostSigner(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	s := &fakeServer{
		listener:   listener,
		hostKey:    hostSigner,
		authedUser: authedUser,
		responses:  responses,
		closed:     make(chan struct{}),
	}
	// Stash the password on the struct so handleConnPassword (below) can
	// reach it without a separate field — keep blast radius small for
	// this Sprint I add.
	s.passwordOverride = authedPassword
	go s.servePassword(t)
	return s
}

func (s *fakeServer) servePassword(t *testing.T) {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.closed:
				return
			default:
				t.Logf("accept: %v", err)
				return
			}
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConnPassword(t, conn)
		}()
	}
}

func (s *fakeServer) handleConnPassword(t *testing.T, nConn net.Conn) {
	defer nConn.Close()

	cfg := &ssh.ServerConfig{
		PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if meta.User() != s.authedUser {
				return nil, fmt.Errorf("unknown user %q", meta.User())
			}
			if string(password) != s.passwordOverride {
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
		go s.handleSession(ch, chReqs)
	}
}

func TestConnect_PasswordAuth_AcceptsCorrectPassword(t *testing.T) {
	server := newFakePasswordServer(t, "developer", "lastorangerestoreball8876", map[string]string{
		"show version": "Cisco IOS XE Software, Version 17.13.1\n",
	})
	defer server.Close()

	host, port := splitHostPort(t, server.addr())
	cli, err := Connect(context.Background(), Config{
		Host:       host,
		Port:       port,
		User:       "developer",
		AuthMethod: AuthMethodPassword,
		Password:   "lastorangerestoreball8876",
	})
	if err != nil {
		t.Fatalf("Connect with password: %v", err)
	}
	defer cli.Close()

	out, err := cli.Run(context.Background(), "show version")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(out, "Cisco IOS XE Software") {
		t.Errorf("unexpected output: %q", out)
	}
}

func TestConnect_PasswordAuth_RejectsWrongPassword(t *testing.T) {
	server := newFakePasswordServer(t, "developer", "right-password", map[string]string{})
	defer server.Close()

	host, port := splitHostPort(t, server.addr())
	_, err := Connect(context.Background(), Config{
		Host:       host,
		Port:       port,
		User:       "developer",
		AuthMethod: AuthMethodPassword,
		Password:   "wrong-password",
	})
	if err == nil {
		t.Fatal("expected handshake failure with wrong password")
	}
}

// ssh_password is an accepted alias for the password auth method —
// mirrors the backend's CredType Literal which uses ssh_password.
func TestConnect_SSHPasswordAlias(t *testing.T) {
	server := newFakePasswordServer(t, "developer", "letmein", map[string]string{
		"show version": "ok\n",
	})
	defer server.Close()

	host, port := splitHostPort(t, server.addr())
	cli, err := Connect(context.Background(), Config{
		Host:       host,
		Port:       port,
		User:       "developer",
		AuthMethod: AuthMethodSSHPassword,
		Password:   "letmein",
	})
	if err != nil {
		t.Fatalf("Connect with ssh_password alias: %v", err)
	}
	defer cli.Close()
}
