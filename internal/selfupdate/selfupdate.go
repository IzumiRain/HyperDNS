// Package selfupdate implements the dashboard's "check for and apply an update"
// flow (v2.6): it reads the version published on the project's main branch,
// compares it with the running build, and — on Linux under systemd — downloads
// the matching release binary, verifies its SHA-256 against the release's
// checksums.txt, backs up the data files, swaps the binary atomically, and asks
// the daemon to restart onto it.
//
// Security posture: the download host is hard-coded (no operator-supplied URL),
// and a binary is NEVER swapped in unless its SHA-256 matches the value in the
// release's signed checksums.txt. The data key/db/config are backed up before
// anything is replaced and are otherwise never touched, so an update cannot lose
// a subscriber list or an admin credential.
package selfupdate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"hyperdns/internal/version"
)

const (
	ghOwner  = "IzumiRain"
	ghRepo   = "HyperDNS"
	ghBranch = "main"

	rawVersionURL = "https://raw.githubusercontent.com/" + ghOwner + "/" + ghRepo + "/" + ghBranch + "/version.json"
	releasesURL   = "https://api.github.com/repos/" + ghOwner + "/" + ghRepo + "/releases?per_page=30"

	// maxBinaryBytes caps a downloaded release binary. The linux build is ~20 MB;
	// 128 MB is generous headroom that still refuses a decompression-bomb-sized body.
	maxBinaryBytes = 128 << 20
)

// Status is the answer to "is there a newer version?" for the dashboard.
type Status struct {
	Current         string `json:"current"`
	Latest          string `json:"latest"`
	Codename        string `json:"codename,omitempty"`
	Channel         string `json:"channel,omitempty"`
	UpdateAvailable bool   `json:"update_available"`
	Supported       bool   `json:"supported"` // false when auto-apply cannot run here (non-Linux)
	Note            string `json:"note,omitempty"`
}

// Progress is the live state of an in-flight apply, polled by the modal.
type Progress struct {
	Running    bool   `json:"running"`
	Phase      string `json:"phase"` // idle|resolve|download|verify|backup|swap|restart|done|error
	Percent    int    `json:"percent"`
	Message    string `json:"message"`
	Restarting bool   `json:"restarting"`
	Error      string `json:"error,omitempty"`
}

// Updater owns the paths it may touch and the progress of the current apply.
type Updater struct {
	binPath   string   // the running executable (os.Executable)
	dataPaths []string // files to back up before swapping (db, key, config)
	backupDir string   // where timestamped pre-update backups are written
	client    *http.Client

	mu       sync.Mutex
	progress Progress
}

// New builds an Updater. binPath is the running binary to replace; dataPaths are
// the files copied into backupDir before any swap.
func New(binPath string, dataPaths []string, backupDir string) *Updater {
	return &Updater{
		binPath:   binPath,
		dataPaths: dataPaths,
		backupDir: backupDir,
		client: &http.Client{
			Timeout: 3 * time.Minute, // a whole binary download, not a metadata call
		},
	}
}

// Progress returns a copy of the current apply state.
func (u *Updater) Progress() Progress {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.progress
}

func (u *Updater) setProgress(phase, msg string, percent int) {
	u.mu.Lock()
	u.progress.Running = true
	u.progress.Phase = phase
	u.progress.Message = msg
	u.progress.Percent = percent
	u.progress.Error = ""
	u.mu.Unlock()
}

func (u *Updater) fail(err error) {
	u.mu.Lock()
	u.progress.Running = false
	u.progress.Phase = "error"
	u.progress.Error = err.Error()
	u.mu.Unlock()
}

// Check reads the version published on the main branch and compares it with the
// running build. Network failures are returned as errors; a well-formed "no
// update" answer is not an error.
func (u *Updater) Check(ctx context.Context) (Status, error) {
	cur := version.Get()
	st := Status{
		Current:   cur.Version,
		Supported: runtime.GOOS == "linux",
	}
	if !st.Supported {
		st.Note = "Automatic update is available on Linux/systemd installs only."
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawVersionURL, nil)
	if err != nil {
		return st, err
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return st, fmt.Errorf("reach GitHub: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return st, fmt.Errorf("version.json fetch returned HTTP %d", resp.StatusCode)
	}
	var remote struct {
		Version  string `json:"version"`
		Channel  string `json:"channel"`
		Codename string `json:"codename"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&remote); err != nil {
		return st, fmt.Errorf("parse remote version.json: %w", err)
	}
	if remote.Version == "" {
		return st, fmt.Errorf("remote version.json carried no version")
	}
	st.Latest = remote.Version
	st.Channel = remote.Channel
	st.Codename = remote.Codename
	st.UpdateAvailable = compareSemver(remote.Version, cur.Version) > 0
	return st, nil
}

// compareSemver returns >0 when a is a newer version than b, 0 when equal, <0
// otherwise. It compares the dotted numeric fields only (2.6.0 vs 2.5.0); the
// channel/prerelease suffix is deliberately ignored — the version.json on main
// carries no build suffix to compare against.
func compareSemver(a, b string) int {
	as := splitVersion(a)
	bs := splitVersion(b)
	for i := 0; i < len(as) || i < len(bs); i++ {
		var av, bv int
		if i < len(as) {
			av = as[i]
		}
		if i < len(bs) {
			bv = bs[i]
		}
		if av != bv {
			if av > bv {
				return 1
			}
			return -1
		}
	}
	return 0
}

func splitVersion(v string) []int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	// Drop any -beta / +build suffix; compare the numeric core only.
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			break // stop at the first non-numeric field
		}
		out = append(out, n)
	}
	return out
}

// StartApply launches the update in the background if one is not already
// running. It returns immediately; the dashboard polls Progress(). The target
// version string is informational (the release is resolved from GitHub).
func (u *Updater) StartApply() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("automatic update runs on Linux/systemd installs only")
	}
	u.mu.Lock()
	if u.progress.Running {
		u.mu.Unlock()
		return fmt.Errorf("an update is already in progress")
	}
	u.progress = Progress{Running: true, Phase: "resolve", Message: "Starting update…", Percent: 1}
	u.mu.Unlock()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if err := u.apply(ctx); err != nil {
			u.fail(err)
		}
	}()
	return nil
}
