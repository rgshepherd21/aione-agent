//go:build !windows

package main

func defaultConfigPath() string {
	return "/etc/aione-agent/agent.yaml"
}
