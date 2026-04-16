//go:build windows

package config

import (
	"os"
	"path/filepath"
)

func dataDir() string {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	return filepath.Join(programData, "AIOne", "Agent")
}
