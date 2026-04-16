//go:build windows

package updater

import (
	"fmt"
	"os"
)

// replaceExecutable on Windows cannot rename over a running executable.
// We rename the old binary to .old, place the new binary, and leave the
// .old file for cleanup on next startup.
func replaceExecutable(src, dst string) error {
	oldPath := dst + ".old"
	// Remove any leftover from a previous update.
	_ = os.Remove(oldPath)

	if err := os.Rename(dst, oldPath); err != nil {
		return fmt.Errorf("moving current binary to .old: %w", err)
	}
	if err := os.Rename(src, dst); err != nil {
		// Attempt rollback.
		_ = os.Rename(oldPath, dst)
		return fmt.Errorf("placing new binary: %w", err)
	}
	return nil
}
