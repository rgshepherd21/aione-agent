//go:build !windows

package config

func dataDir() string {
	return "/var/lib/aione-agent"
}
