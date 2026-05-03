// Vendor prompt registry for the persistent-shell SSH transport.
//
// The Shell type opens a single SSH session, requests a PTY, and
// runs commands inside that session by writing to stdin and reading
// stdout until a vendor-specific prompt regex matches. Each vendor
// gets a small set of regexes describing its prompt shapes:
//
//   * InitialPrompt  — the prompt right after the shell first opens.
//                      Cisco/Arista users land in user-EXEC mode at
//                      ``hostname>``. Junos users land in operational
//                      mode at ``user@hostname>``.
//
//   * PrivilegedPrompt — what the prompt looks like after ``enable``
//                        (Cisco/Arista) or in operational mode (Junos
//                        ">" same as initial). Used to detect mode
//                        transitions.
//
//   * ConfigPrompt — config mode, ``hostname(config)#`` (Cisco/Arista)
//                    or ``user@hostname#`` (Junos).
//
//   * AnyPrompt    — union regex that matches any of the above.
//                    The Shell.Send loop reads stdout until this
//                    matches; per-mode disambiguation happens after.
//
// A new vendor entry is one map row plus four regexes — extending
// this registry is the only file change required to onboard another
// CLI dialect.

package sshclient

import (
	"fmt"
	"regexp"
	"sort"
	"time"
)

// ShellConfig describes the prompt shape and timeout for one vendor's CLI.
type ShellConfig struct {
	// Vendor is the canonical slug (matches Device.vendor on the platform
	// side: ``cisco_iosxe``, ``arista_eos``, ``juniper_junos``).
	Vendor string

	// InitialPrompt matches the prompt immediately after shell open.
	InitialPrompt *regexp.Regexp

	// PrivilegedPrompt matches the prompt after the privilege-elevation
	// command for the vendor (typically ``enable`` for Cisco/Arista).
	// May equal InitialPrompt when the vendor doesn't distinguish.
	PrivilegedPrompt *regexp.Regexp

	// ConfigPrompt matches the prompt after entering configuration mode
	// (typically ``configure terminal`` for Cisco/Arista, ``configure``
	// for Junos).
	ConfigPrompt *regexp.Regexp

	// AnyPrompt matches any of the above. This is the regex Shell.Send
	// uses to decide that a command's output is complete and a new
	// prompt has been issued.
	AnyPrompt *regexp.Regexp

	// CommandTimeout is the per-command default deadline. A caller's
	// own context.WithTimeout takes precedence when shorter.
	CommandTimeout time.Duration
}

// vendorShellConfigs is the canonical prompt registry. Entries are
// keyed by vendor slug. Every value's AnyPrompt MUST match strings
// that match Initial/Privileged/ConfigPrompt — the Shell type relies
// on AnyPrompt as the single regex it polls against.
//
// Trailing whitespace + optional CR before the EOL anchor is the
// pragmatic accommodation for Cisco/Arista PTY output, which often
// terminates a prompt with " " (one space) and may include "\r".
//
// IMPORTANT: the regexes are NOT anchored at start (^) because the
// Shell reads into a streaming buffer that may contain residual
// command echo + multi-line output before the prompt. They ARE
// anchored at end ($) so we only match a prompt at the tail of the
// captured buffer, not somewhere in the middle.
var vendorShellConfigs = map[string]ShellConfig{
	"cisco_iosxe": {
		Vendor:           "cisco_iosxe",
		InitialPrompt:    regexp.MustCompile(`\S+>\s*$`),
		PrivilegedPrompt: regexp.MustCompile(`\S+#\s*$`),
		ConfigPrompt:     regexp.MustCompile(`\S+\(config[^)]*\)#\s*$`),
		AnyPrompt:        regexp.MustCompile(`\S+(?:\(config[^)]*\)#|>|#)\s*$`),
		CommandTimeout:   60 * time.Second,
	},
	"cisco_nxos": {
		// NX-OS prompts are essentially identical to IOS-XE in shape;
		// we keep a separate entry so future divergence (e.g. distinct
		// config-mode flavors like ``config-vlan``) can be expressed
		// without breaking the IOS-XE entry.
		Vendor:           "cisco_nxos",
		InitialPrompt:    regexp.MustCompile(`\S+#\s*$`),
		PrivilegedPrompt: regexp.MustCompile(`\S+#\s*$`),
		ConfigPrompt:     regexp.MustCompile(`\S+\(config[^)]*\)#\s*$`),
		AnyPrompt:        regexp.MustCompile(`\S+(?:\(config[^)]*\)#|#)\s*$`),
		CommandTimeout:   60 * time.Second,
	},
	"arista_eos": {
		// EOS mirrors IOS-XE for prompt structure. cEOS-lab on the F7
		// soak host is the canonical test target for this entry.
		Vendor:           "arista_eos",
		InitialPrompt:    regexp.MustCompile(`\S+>\s*$`),
		PrivilegedPrompt: regexp.MustCompile(`\S+#\s*$`),
		ConfigPrompt:     regexp.MustCompile(`\S+\(config[^)]*\)#\s*$`),
		AnyPrompt:        regexp.MustCompile(`\S+(?:\(config[^)]*\)#|>|#)\s*$`),
		CommandTimeout:   60 * time.Second,
	},
	"juniper_junos": {
		// Junos lands in operational mode at ``user@host>`` and uses
		// ``#`` only in config mode. There is no separate enable step
		// — privilege is conveyed by login user, so PrivilegedPrompt
		// is the same as InitialPrompt.
		Vendor:           "juniper_junos",
		InitialPrompt:    regexp.MustCompile(`\S+@\S+>\s*$`),
		PrivilegedPrompt: regexp.MustCompile(`\S+@\S+>\s*$`),
		ConfigPrompt:     regexp.MustCompile(`\S+@\S+#\s*$`),
		AnyPrompt:        regexp.MustCompile(`\S+@\S+[>#]\s*$`),
		CommandTimeout:   60 * time.Second,
	},
}

// ShellConfigFor returns the ShellConfig for a vendor slug, or an
// error listing the known vendors if the slug is unrecognized.
//
// Callers (typically the DSL device executor) pass the vendor field
// of the Device row through to this lookup; an unrecognized vendor
// is a configuration error in the platform's device registration,
// not a runtime device error.
func ShellConfigFor(vendor string) (ShellConfig, error) {
	cfg, ok := vendorShellConfigs[vendor]
	if !ok {
		return ShellConfig{}, fmt.Errorf(
			"sshclient: no shell config for vendor %q (known: %v)",
			vendor, knownVendors(),
		)
	}
	return cfg, nil
}

// knownVendors returns the sorted list of vendor slugs for error
// messages. Sort gives test stability and human-readable diagnostics.
func knownVendors() []string {
	names := make([]string, 0, len(vendorShellConfigs))
	for name := range vendorShellConfigs {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
