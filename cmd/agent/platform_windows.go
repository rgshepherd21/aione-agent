//go:build windows

package main

import (
	"os"
	"path/filepath"
)

func defaultConfigPath() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "AIOne", "Agent", "agent.yaml")
}
