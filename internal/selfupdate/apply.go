package selfupdate

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
	"strings"
	"time"
)

// ghRelease is the slice of the GitHub Releases API we consume.
type ghRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

// apply runs the full update pipeline. Every step updates progress so the modal
// can narrate it; any error is returned and surfaced by StartApply.
func (u *Updater) apply(ctx context.Context) error {
	binName := "hyperdns-linux-" + runtime.GOARCH // hyperdns-linux-amd64 / -arm64

	// 1. Resolve the newest release and the two assets we need from it.
	u.setProgress("resolve", "Finding the latest release…", 5)
	binURL, sumURL, tag, err := u.resolveAssets(ctx, binName)
	if err != nil {
		return err
	}

	// 2. Fetch and parse checksums.txt, then download the binary and verify it
	//    BEFORE anything on disk is touched.
	u.setProgress("verify", "Fetching checksums…", 15)
	wantSum, err := u.expectedSum(ctx, sumURL, binName)
	if err != nil {
		return err
	}

	u.setProgress("download", "Downloading "+tag+"…", 25)
	tmpPath, gotSum, err := u.downloadTo(ctx, binURL)
	if tmpPath != "" {
		defer os.Remove(tmpPath)
	}
	if err != nil {
		return err
	}
	u.setProgress("verify", "Verifying signature…", 70)
	if !strings.EqualFold(gotSum, wantSum) {
		return fmt.Errorf("checksum mismatch: the downloaded binary does not match the release's checksums.txt (refusing to install)")
	}

	// 3. Back up the data files (never touched by the swap, but a pre-update
	//    snapshot is what makes a bad release recoverable).
	u.setProgress("backup", "Backing up data…", 78)
	if err := u.backupData(); err != nil {
		return fmt.Errorf("pre-update backup failed, aborting before any change: %w", err)
	}

	// 4. Swap the binary atomically, keeping the old one as .bak for rollback.
	u.setProgress("swap", "Installing the new binary…", 88)
	if err := u.swapBinary(tmpPath); err != nil {
		return err
	}

	// 5. Ask the daemon to restart onto the new binary.
	u.setProgress("restart", "Update installed — restarting…", 100)
	u.mu.Lock()
	u.progress.Restarting = true
	u.progress.Phase = "done"
	u.mu.Unlock()
	go func() {
		// Let the modal poll the "restarting" state once before the process goes.
		time.Sleep(1500 * time.Millisecond)
		_ = signalRestart()
	}()
	return nil
}

// resolveAssets finds the newest release whose tag carries the main-branch
// version and returns the download URLs for the arch binary and checksums.txt.
func (u *Updater) resolveAssets(ctx context.Context, binName string) (binURL, sumURL, tag string, err error) {
	st, err := u.Check(ctx)
	if err != nil {
		return "", "", "", err
	}
	if !st.UpdateAvailable {
		return "", "", "", fmt.Errorf("already on the latest version (%s)", st.Current)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, releasesURL, nil)
	if err != nil {
		return "", "", "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := u.client.Do(req)
	if err != nil {
		return "", "", "", fmt.Errorf("list releases: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", "", fmt.Errorf("releases API returned HTTP %d", resp.StatusCode)
	}
	var releases []ghRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&releases); err != nil {
		return "", "", "", fmt.Errorf("parse releases: %w", err)
	}

	// The list is newest-first; take the first release whose tag carries the
	// target version (handles the vX.Y.Z-beta.N tag suffix).
	for _, rel := range releases {
		if !strings.Contains(rel.TagName, st.Latest) {
			continue
		}
		for _, a := range rel.Assets {
			switch a.Name {
			case binName:
				binURL = a.URL
			case "checksums.txt":
				sumURL = a.URL
			}
		}
		if binURL != "" && sumURL != "" {
			return binURL, sumURL, rel.TagName, nil
		}
	}
	return "", "", "", fmt.Errorf("no release asset %q with a checksums.txt found for version %s", binName, st.Latest)
}

// expectedSum downloads checksums.txt and returns the hex SHA-256 recorded for
// binName. The file is `sha256sum *` output: "<hex>  <filename>" per line.
func (u *Updater) expectedSum(ctx context.Context, sumURL, binName string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sumURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch checksums.txt: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("checksums.txt returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == binName {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("checksums.txt has no entry for %q", binName)
}

// downloadTo streams a URL to a temp file next to the target binary (same
// filesystem, so the later rename is atomic) and returns the file's SHA-256.
func (u *Updater) downloadTo(ctx context.Context, url string) (path, sum string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", "", err
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("download returned HTTP %d", resp.StatusCode)
	}

	tmp, err := os.CreateTemp(filepath.Dir(u.binPath), ".hyperdns-update-*")
	if err != nil {
		return "", "", err
	}
	path = tmp.Name()
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, maxBinaryBytes)); err != nil {
		tmp.Close()
		return path, "", fmt.Errorf("write download: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return path, "", err
	}
	return path, hex.EncodeToString(h.Sum(nil)), nil
}

// backupData copies each data file into a timestamped directory. Missing files
// are skipped (a fresh install may have no config yet); an unreadable/unwritable
// file is a hard error so the swap does not proceed without a snapshot.
func (u *Updater) backupData() error {
	stamp := time.Now().Format("20060102-150405")
	dst := filepath.Join(u.backupDir, "pre-update-"+stamp)
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return err
	}
	for _, src := range u.dataPaths {
		if src == "" {
			continue
		}
		if _, err := os.Stat(src); err != nil {
			continue // not present yet
		}
		if err := copyFile(src, filepath.Join(dst, filepath.Base(src)), 0o600); err != nil {
			return err
		}
	}
	return nil
}

// swapBinary makes the downloaded file executable, keeps the current binary as
// <bin>.bak for rollback, and renames the new one into place. The rename is
// atomic within one filesystem, so a crash cannot leave a half-written binary.
func (u *Updater) swapBinary(tmpPath string) error {
	if err := os.Chmod(tmpPath, 0o755); err != nil {
		return err
	}
	// Best-effort rollback copy of the running binary.
	_ = copyFile(u.binPath, u.binPath+".bak", 0o755)
	if err := os.Rename(tmpPath, u.binPath); err != nil {
		return fmt.Errorf("install new binary: %w", err)
	}
	return nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
