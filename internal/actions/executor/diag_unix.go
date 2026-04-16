//go:build !windows

package executor

func diagnosticCommands() map[string][]string {
	return map[string][]string{
		"uptime":    {"uptime"},
		"disk":      {"df", "-h"},
		"memory":    {"free", "-h"},
		"processes": {"ps", "aux", "--no-headers", "--sort=-%cpu"},
		"network":   {"ss", "-tulnp"},
	}
}
