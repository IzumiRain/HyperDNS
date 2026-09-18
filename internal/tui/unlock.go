package tui

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Login-lockout management (Phase C): the tracker lives inside the running
// daemon's memory, and the TUI cannot reach another process's state — nor the
// database, which bbolt has already given to the daemon. The one honest path
// is the daemon's own authenticated endpoint over loopback, which is also why
// this entry works WITHOUT stopping the service: it is the only menu action
// here that does not need the database at all.
//
// The endpoint enforces the second factor when 2FA is on, so this menu walks
// the operator through one extra prompt when it has to.

// unlockRequest is the body handleAuthUnlock accepts.
type unlockRequest struct {
	Code string `json:"code,omitempty"`
}

// unlockMenuEntry drives the whole flow: read the API key and admin path from
// the settings, POST to the endpoint, and — when 2FA answers 401 — prompt for
// a current code and retry once.
func unlockLoginLockouts(baseURL, apiKey, adminPath string) {
	if strings.TrimSpace(apiKey) == "" || strings.TrimSpace(adminPath) == "" {
		fmt.Println("\nThe daemon has no API key or admin path configured; the unlock")
		fmt.Println("endpoint cannot be addressed. Check the dashboard Settings.")
		return
	}

	url := strings.TrimRight(baseURL, "/") + "/" + adminPath + "/api/auth/unlock"

	call := func(code string) (int, []byte, error) {
		body, _ := json.Marshal(unlockRequest{Code: code})
		req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(string(body)))
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", apiKey)
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return 0, nil, err
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		return resp.StatusCode, data, nil
	}

	code := ""
	status, body, err := call(code)
	// A 401 here means the second factor: ask once and retry.
	if status == http.StatusUnauthorized {
		fmt.Print("\nTwo-factor is enabled. Enter a current 6-digit code: ")
		var line string
		fmt.Scanln(&line)
		code = strings.TrimSpace(line)
		status, body, err = call(code)
	}
	if err != nil {
		fmt.Printf("\n%s✗ Could not reach the daemon: %v%s\n", Red, err, Reset)
		fmt.Println("  Is the service running? Check: systemctl status hyperdns")
		return
	}

	switch {
	case status == http.StatusOK:
		fmt.Printf("\n%s✓ Login lockouts cleared.%s\n", Green, Reset)
		fmt.Printf("  Every tracked address can log in again immediately.\n")
	case status == http.StatusUnauthorized:
		fmt.Printf("\n%s✗ Rejected (%d).%s The API key was wrong, or the two-factor\n", Red, status, Reset)
		fmt.Println("  code was. Nothing was cleared.")
	default:
		fmt.Printf("\n%s✗ The daemon answered %d.%s\n", Red, status, Reset)
		fmt.Printf("  %s\n", strings.TrimSpace(string(body)))
	}
}
