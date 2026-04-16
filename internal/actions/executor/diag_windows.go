//go:build windows

package executor

func diagnosticCommands() map[string][]string {
	return map[string][]string{
		"uptime":    {"cmd.exe", "/C", "net statistics workstation | findstr Statistics"},
		"disk":      {"cmd.exe", "/C", "wmic logicaldisk get size,freespace,caption"},
		"memory":    {"cmd.exe", "/C", "wmic OS get FreePhysicalMemory,TotalVisibleMemorySize"},
		"processes": {"cmd.exe", "/C", "tasklist /fo csv /nh"},
		"network":   {"cmd.exe", "/C", "netstat -an"},
	}
}
