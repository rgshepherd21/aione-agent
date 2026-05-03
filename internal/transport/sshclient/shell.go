// Persistent-shell SSH transport (Sprint follow-up S1.a).
//
// The Shell type wraps a single ssh.Session that has requested a PTY
// and entered shell mode. Unlike the per-command-exec model in
// ``client.go`` (where each command opens a fresh session via
// ``session.Run``), Shell preserves CLI mode state across commands —
// after a caller sends ``enable`` on a Cisco/Arista device, the next
// ``configure terminal`` command runs from the same privileged
// context, and an action's body can step through pre-checks,
// configuration mutations, and post-checks within a single login.
//
// This is the transport prerequisite for any KAL action that needs
// stateful CLI: Cisco/Arista config mode, Junos commit/discard,
// post-state verification that depends on commands run after a
// configuration change.
//
// Output capture model
// --------------------
// The session's combined stdout+stderr stream is consumed by a
// single reader goroutine that appends bytes into a ``captureBuffer``
// behind a mutex. ``Send`` writes a command followed by a newline,
// then waits on the buffer's condition variable for the vendor's
// AnyPrompt regex to match the buffer's tail. On match the matched
// prefix is consumed (so the next Send sees a clean buffer) and the
// command echo + trailing prompt are stripped from the returned
// string.
//
// Cancellation
// ------------
// Send honors both the caller's context and the ShellConfig's
// CommandTimeout. The earlier of the two deadlines wins. A canceled
// Send leaves the session in an indeterminate state — by convention
// the caller should Close the Shell rather than try another Send.

package sshclient

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// shellReadBufSize bounds the unconsumed stdout bytes the reader
// goroutine appends to. Sized to comfortably hold a fully-populated
// ``show running-config`` (~1-3 MB on a real Catalyst / Nexus /
// cEOS box, after the persistent-shell ``terminal length 0`` disables
// the pager) with headroom. Bumped from 512 KiB → 4 MiB in Sprint
// follow-up Bucket A.2 (HIGH#1 from the post-S4 code review): the
// 512 KiB cap silently truncated ``show running-config`` output on
// devices with non-trivial config, which would have broken the
// config-snapshot pipeline that S5's discovery walker relies on.
//
// On overflow the reader sets a terminal error (ErrShellOutputOverflow)
// and stops consuming — Send returns that error to the caller rather
// than silently dropping the head of the buffer. Loud-fail beats
// silent-truncation when the output drives downstream parsers like
// the topology graph or config snapshots.
const shellReadBufSize = 4 * 1024 * 1024

// shellPtyTermType is the value sent in the SSH ``pty-req`` channel
// request. ``vt100`` is the broadest-compatible terminal type for
// network device CLIs; ``xterm`` is fine for Linux shells but
// occasionally upsets older IOS releases.
const shellPtyTermType = "vt100"

// Default PTY geometry. Wide enough that prompt detection isn't
// confused by CLI line-wrapping; tall enough that Cisco's pager
// (when enabled) doesn't fire mid-output. Callers should still send
// ``terminal length 0`` (or vendor equivalent) as the first command
// in any shell session that runs commands likely to produce > 24
// rows of output.
const (
	shellPtyCols = 200
	shellPtyRows = 50
)

// Shell is a single SSH session running in shell mode with an
// attached PTY. Send writes commands and reads back their output
// until the next vendor prompt; Close terminates the session. Shell
// is single-use by convention — concurrent Send calls on the same
// Shell are not supported and produce undefined output capture.
type Shell struct {
	session *ssh.Session
	stdin   io.WriteCloser
	cfg     ShellConfig

	// captured holds the unconsumed stdout/stderr bytes plus the
	// reader goroutine's terminal error (if any). The reader
	// goroutine appends; Send waits on the condition variable for
	// either a prompt match or a terminal error.
	captured *captureBuffer

	// readerDone closes when the reader goroutine exits. Used by
	// Close to wait for the goroutine before returning.
	readerDone chan struct{}

	// closed flips on first Close call so subsequent calls are no-ops
	// and post-close Send reports a clear error.
	closed atomic.Bool
}

// captureBuffer is a thread-safe append-only byte buffer signaled by
// a condition variable. Wait broadcasts on every append and on
// reader-goroutine exit, so consumers can poll a regex match against
// the snapshot without busy-waiting.
type captureBuffer struct {
	mu   sync.Mutex
	cond *sync.Cond
	buf  []byte
	err  error // set when the reader goroutine exits
}

func newCaptureBuffer() *captureBuffer {
	cb := &captureBuffer{}
	cb.cond = sync.NewCond(&cb.mu)
	return cb
}

// append copies p into the buffer and broadcasts. Returns the new
// total buffer length.
func (b *captureBuffer) append(p []byte) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	b.cond.Broadcast()
	return len(b.buf)
}

// setErr records the reader goroutine's terminal error and
// broadcasts so any Send waiting on the cond unblocks immediately
// rather than hanging until its own deadline.
func (b *captureBuffer) setErr(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.err == nil {
		b.err = err
	}
	b.cond.Broadcast()
}

// waitForMatch blocks until pattern matches the buffer's content or
// ctx is canceled. On match, the matched prefix is consumed (so the
// next call starts from after the match) and the consumed bytes are
// returned. On reader-error or ctx-cancel before a match, returns
// the error and leaves the buffer unconsumed.
//
// Cancellation works by spawning a goroutine that broadcasts the
// cond on ctx.Done(); the main loop then re-checks ctx.Err() under
// lock and returns. This avoids a busy-wait or a separate timeout
// loop in every caller.
//
// IMPORTANT — pattern-anchoring invariant
// ----------------------------------------
// Every regex passed here (the vendor ShellConfig.AnyPrompt entries
// in prompts.go) MUST be anchored at end-of-string with ``\s*$`` so
// that ``FindIndex`` returns the prompt at the BUFFER TAIL only —
// never some prompt-shaped substring earlier in the streamed output.
// If a future change unanchors a prompt regex, the parser will
// "see" a prompt mid-output, return early with truncated content,
// and the next Send will read what's left of the previous command's
// stdout as if it belonged to its own.
// Bucket A.2 / MEDIUM#8 from the post-S4 code review.
func (b *captureBuffer) waitForMatch(ctx context.Context, pattern *regexp.Regexp) (string, error) {
	// Watcher goroutine that wakes up the cond when ctx is done.
	// We use a child context so the watcher exits cleanly on match.
	watchCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-watchCtx.Done()
		b.mu.Lock()
		b.cond.Broadcast()
		b.mu.Unlock()
	}()

	b.mu.Lock()
	defer b.mu.Unlock()
	for {
		if loc := pattern.FindIndex(b.buf); loc != nil {
			// Consume through the end of the match.
			matched := string(b.buf[:loc[1]])
			b.buf = b.buf[loc[1]:]
			return matched, nil
		}
		if b.err != nil {
			return "", b.err
		}
		if err := ctx.Err(); err != nil {
			return "", err
		}
		b.cond.Wait()
	}
}

// NewShell opens a persistent shell on top of an existing connected
// Client. The shell requests a PTY, enters shell mode, and reads
// until the vendor's AnyPrompt regex matches — i.e. until the device
// has issued its first interactive prompt. Returns the Shell ready
// for Send calls, or an error if any step of session setup fails.
//
// The caller MUST Close the Shell when done; leaving sessions open
// burns slots on the device's vty pool.
func (c *Client) NewShell(ctx context.Context, cfg ShellConfig) (*Shell, error) {
	if c == nil || c.conn == nil {
		return nil, errors.New("sshclient: NewShell on closed or nil Client")
	}
	if cfg.AnyPrompt == nil {
		return nil, errors.New("sshclient: ShellConfig.AnyPrompt is required")
	}

	session, err := c.conn.NewSession()
	if err != nil {
		return nil, fmt.Errorf("sshclient: new session: %w", err)
	}

	// Disable echo on the PTY where possible — many network devices
	// echo the typed command back over stdout, and the Send output
	// stripper accommodates that, but Linux shells may double-echo
	// without ECHO=0. Modes are best-effort; if the server doesn't
	// honor them we still parse correctly.
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty(shellPtyTermType, shellPtyRows, shellPtyCols, modes); err != nil {
		_ = session.Close()
		return nil, fmt.Errorf("sshclient: request pty: %w", err)
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		_ = session.Close()
		return nil, fmt.Errorf("sshclient: stdin pipe: %w", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		_ = session.Close()
		return nil, fmt.Errorf("sshclient: stdout pipe: %w", err)
	}
	// Merge stderr into the same capture buffer — vendor CLIs
	// frequently emit both streams during normal operation and the
	// caller wants both for debugging.
	stderr, err := session.StderrPipe()
	if err != nil {
		_ = session.Close()
		return nil, fmt.Errorf("sshclient: stderr pipe: %w", err)
	}

	if err := session.Shell(); err != nil {
		_ = session.Close()
		return nil, fmt.Errorf("sshclient: enter shell: %w", err)
	}

	s := &Shell{
		session:    session,
		stdin:      stdin,
		cfg:        cfg,
		captured:   newCaptureBuffer(),
		readerDone: make(chan struct{}),
	}

	// Single reader goroutine pulls from a multi-reader that joins
	// stdout and stderr. The goroutine exits when both streams are
	// closed (session ended) or on read error.
	go s.runReader(io.MultiReader(stdout, stderr))

	// Wait for the initial prompt before returning. The deadline is
	// the lower of the caller's ctx and the configured CommandTimeout.
	waitCtx := ctx
	if cfg.CommandTimeout > 0 {
		var cancel context.CancelFunc
		waitCtx, cancel = context.WithTimeout(ctx, cfg.CommandTimeout)
		defer cancel()
	}
	if _, err := s.captured.waitForMatch(waitCtx, cfg.AnyPrompt); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("sshclient: wait for initial prompt: %w", err)
	}

	return s, nil
}

// ErrShellOutputOverflow is the terminal error the reader sets when
// a single command's output would exceed shellReadBufSize. The
// previous policy silently dropped the oldest bytes, which was the
// wrong default for a transport that feeds parsers — a 1.5 MB
// running-config truncated to the last 512 KiB looks like a valid
// config to the parser, which is worse than a loud failure. Any Send
// waiting on the buffer wakes up and returns this error wrapped
// in a "wait for prompt" message; the caller should Close the shell
// and retry with a smaller scope.
var ErrShellOutputOverflow = errors.New("sshclient: shell output exceeded read buffer cap")

// runReader pumps r into the captureBuffer until r returns EOF or an
// error. Runs in its own goroutine; its termination signals via
// readerDone and stamps captured.err.
func (s *Shell) runReader(r io.Reader) {
	defer close(s.readerDone)
	br := bufio.NewReaderSize(r, 4096)
	chunk := make([]byte, 4096)
	for {
		n, err := br.Read(chunk)
		if n > 0 {
			// Bound the buffer with fail-loudly semantics. If the
			// post-append size would exceed shellReadBufSize we set
			// a terminal error rather than silently dropping the
			// head of the buffer — see Bucket A.2 / HIGH#1. The
			// reader exits after stamping the error so subsequent
			// Send calls return promptly instead of hanging on the
			// cond var until a deadline.
			total := s.captured.append(chunk[:n])
			if total > shellReadBufSize {
				s.captured.setErr(fmt.Errorf(
					"%w: %d bytes (cap %d); device output exceeded "+
						"the per-command bound — close the shell and "+
						"retry with a narrower command scope",
					ErrShellOutputOverflow,
					total,
					shellReadBufSize,
				))
				return
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				s.captured.setErr(fmt.Errorf("sshclient: shell reader: %w", err))
			} else {
				s.captured.setErr(io.EOF)
			}
			return
		}
	}
}

// Send writes one command followed by a newline, then waits for the
// next vendor prompt and returns the captured output between the
// command and the prompt — with the echoed command stripped from
// the front and the prompt stripped from the back.
//
// The deadline is the earlier of ctx and ShellConfig.CommandTimeout.
// On context cancel the Shell is left in an indeterminate state and
// the caller should Close it rather than retry.
func (s *Shell) Send(ctx context.Context, command string) (string, error) {
	if s == nil || s.closed.Load() {
		return "", errors.New("sshclient: Send on closed shell")
	}

	// Apply the per-command timeout if the caller didn't supply a
	// shorter deadline.
	if s.cfg.CommandTimeout > 0 {
		if dl, ok := ctx.Deadline(); !ok || dl.After(time.Now().Add(s.cfg.CommandTimeout)) {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, s.cfg.CommandTimeout)
			defer cancel()
		}
	}

	if _, err := io.WriteString(s.stdin, command+"\n"); err != nil {
		return "", fmt.Errorf("sshclient: write command %q: %w", command, err)
	}

	raw, err := s.captured.waitForMatch(ctx, s.cfg.AnyPrompt)
	if err != nil {
		return "", fmt.Errorf("sshclient: wait for prompt after %q: %w", command, err)
	}
	return cleanShellOutput(raw, command, s.cfg.AnyPrompt), nil
}

// Close terminates the shell session. It first writes ``exit`` to
// stdin (best-effort) so the device sees a graceful disconnect, then
// closes stdin and the session, and waits for the reader goroutine
// to exit. Idempotent.
func (s *Shell) Close() error {
	if s == nil || !s.closed.CompareAndSwap(false, true) {
		return nil
	}

	// Best-effort graceful exit. We don't care about the result —
	// the device may have already closed the session, or our stdin
	// may already be in error state.
	_, _ = io.WriteString(s.stdin, "exit\n")
	_ = s.stdin.Close()
	_ = s.session.Close()

	<-s.readerDone
	return nil
}

// cleanShellOutput strips the echoed command from the start of raw
// (vendor PTY echoes input back even with ECHO=0 set in some cases)
// and the trailing prompt match from the end, returning just the
// command's output. Trailing CRs and LFs are also stripped.
func cleanShellOutput(raw, command string, promptRE *regexp.Regexp) string {
	// Strip the echoed command + its trailing newline.
	if strings.HasPrefix(raw, command) {
		raw = raw[len(command):]
		raw = strings.TrimPrefix(raw, "\r")
		raw = strings.TrimPrefix(raw, "\n")
	}
	// Strip the trailing prompt match.
	if loc := promptRE.FindStringIndex(raw); loc != nil {
		raw = raw[:loc[0]]
	}
	// Trim trailing whitespace + line endings — the prompt's leading
	// whitespace often leaves residue.
	raw = strings.TrimRight(raw, " \t\r\n")
	return raw
}

// shellOutputContainsPrompt is exposed for tests that want to assert
// our prompt-detection regex actually matches a sample. Production
// callers should not need this.
func shellOutputContainsPrompt(out string, promptRE *regexp.Regexp) bool {
	return promptRE.MatchString(out)
}
