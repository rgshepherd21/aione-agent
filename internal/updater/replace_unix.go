//go:build !windows

package updater

import "os"

// replaceExecutable atomically replaces dst with src using rename(2).
func replaceExecutable(src, dst string) error {
	return os.Rename(src, dst)
}
