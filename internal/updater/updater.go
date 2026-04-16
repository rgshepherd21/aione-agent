// Package updater checks the AI One distribution endpoint for a newer binary
// and, if found, downloads, verifies (SHA-256), and installs it.  The process
// then exits so the OS service manager can restart it with the new binary.
package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/shepherdtech/aione-agent/internal/config"
	"github.com/shepherdtech/aione-agent/internal/transport"
)

const updateCheckPath = "/v1/updates/latest"

// ReleaseInfo is the response from the update check endpoint.
type ReleaseInfo struct {
	Version     string `json:"version"`
	DownloadURL string `json:"download_url"`
	SHA256      string `json:"sha256"`
	Channel     string `json:"channel"`
	ReleasedAt  string `json:"released_at"`
}

// Updater periodically checks for and applies binary updates.
type Updater struct {
	cfg        config.UpdaterConfig
	client     *transport.Client
	version    string
	httpClient *http.Client
}

// New creates an Updater.
func New(cfg config.UpdaterConfig, client *transport.Client, version string) *Updater {
	return &Updater{
		cfg:     cfg,
		client:  client,
		version: version,
		httpClient: &http.Client{
			Timeout: 5 * time.Minute,
		},
	}
}

// Run checks for updates on the configured interval.  It blocks until ctx
// is cancelled.  When an update is applied the process exits (exit code 0) so
// the service manager restarts it.
func (u *Updater) Run(ctx context.Context) {
	if !u.cfg.Enabled {
		return
	}

	if err := u.checkAndApply(ctx); err != nil {
		log.Warn().Err(err).Msg("update check failed")
	}

	ticker := time.NewTicker(u.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := u.checkAndApply(ctx); err != nil {
				log.Warn().Err(err).Msg("update check failed")
			}
		}
	}
}

// checkAndApply fetches release info and, if a newer version is available,
// downloads and installs the update.
func (u *Updater) checkAndApply(ctx context.Context) error {
	path := fmt.Sprintf("%s?channel=%s&os=%s&arch=%s",
		updateCheckPath, u.cfg.Channel, runtime.GOOS, runtime.GOARCH)

	var info ReleaseInfo
	if err := u.client.GetJSON(ctx, path, &info); err != nil {
		return fmt.Errorf("fetching release info: %w", err)
	}

	if info.Version == u.version {
		log.Debug().Str("version", u.version).Msg("agent is up to date")
		return nil
	}

	log.Info().
		Str("current", u.version).
		Str("available", info.Version).
		Msg("update available, downloading")

	if err := u.download(ctx, info); err != nil {
		return fmt.Errorf("applying update %s: %w", info.Version, err)
	}

	log.Info().Str("version", info.Version).Msg("update applied, restarting")
	os.Exit(0)
	return nil
}

func (u *Updater) download(ctx context.Context, info ReleaseInfo) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, info.DownloadURL, nil)
	if err != nil {
		return fmt.Errorf("building download request: %w", err)
	}

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("downloading update: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned HTTP %d", resp.StatusCode)
	}

	// Write to a temp file next to the current binary.
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locating current executable: %w", err)
	}
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		return fmt.Errorf("resolving executable symlink: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(exePath), ".update-tmp-")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpName := tmp.Name()

	defer func() {
		tmp.Close()
		os.Remove(tmpName) // harmless if rename succeeded
	}()

	hasher := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, hasher), resp.Body); err != nil {
		return fmt.Errorf("writing update: %w", err)
	}
	tmp.Close()

	// Verify checksum.
	got := hex.EncodeToString(hasher.Sum(nil))
	if got != info.SHA256 {
		return fmt.Errorf("checksum mismatch: expected %s got %s", info.SHA256, got)
	}

	// Make executable and atomically replace the current binary.
	if err := os.Chmod(tmpName, 0o755); err != nil {
		return fmt.Errorf("chmod update: %w", err)
	}

	return replaceExecutable(tmpName, exePath)
}

// checkLatest is exported for testing.
func CheckLatest(data []byte) (*ReleaseInfo, error) {
	var info ReleaseInfo
	return &info, json.Unmarshal(data, &info)
}
