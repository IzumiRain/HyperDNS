package httpx

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"hyperdns/internal/database"
	"hyperdns/internal/service"
)

// TestWriteJSONErrorIsParseable is the regression test for the habit this package
// replaced: fmt.Sprintf(`{"error":"%v"}`, err). Both front-ends quote operator input
// back in error text — a refused address, a rejected username — so a quote, a
// backslash or a newline in the message is ordinary, and each one turned the body
// into something res.json() throws on. The operator then saw a generic "the request
// failed" instead of the reason.
func TestWriteJSONErrorIsParseable(t *testing.T) {
	messages := []struct {
		name string
		msg  string
	}{
		{"quoted address", `invalid IP address: "203.0.113.999"`},
		{"backslash", `unexpected \ backslash`},
		{"newline", "a message\nwith a newline"},
		{"tab", "a message\twith a tab"},
		{"nested escapes", `nested "quotes" and \"escapes\"`},
		{"non-ascii", "unicode: کاربر ۱۲۳"},
		{"control chars", "control char: \x00 and \x1f"},
		{"html sensitive", `<script>alert(1)</script> & "co"`},
		{"body that is itself json", `{"error":"a message that is itself JSON"}`},
	}

	for _, tc := range messages {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			WriteJSONError(w, http.StatusBadRequest, tc.msg)

			if w.Code != http.StatusBadRequest {
				t.Errorf("status: want 400, got %d", w.Code)
			}
			if ct := w.Header().Get("Content-Type"); ct != "application/json" {
				t.Errorf("Content-Type: want application/json, got %q", ct)
			}

			var payload map[string]string
			if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
				t.Fatalf("body is not JSON (%v): %s", err, w.Body.String())
			}
			if payload["error"] != tc.msg {
				t.Errorf("message did not round-trip:\n want %q\n  got %q", tc.msg, payload["error"])
			}
		})
	}
}

// TestWriteJSONErrorForNilError covers the one case where a Go error cannot be
// asked for its text: nil. Encoding it as the empty string produces
// {"error":""}, which the dashboard renders as a failure with no reason given.
func TestWriteJSONErrorForNilError(t *testing.T) {
	w := httptest.NewRecorder()
	WriteJSONErrorFor(w, http.StatusInternalServerError, nil)

	var payload map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("body is not JSON (%v): %s", err, w.Body.String())
	}
	if payload["error"] == "" {
		t.Error("a nil error produced an empty message, which reads as a failure with no reason")
	}
}

// TestClientErrorStatus pins the three-way split both front-ends depend on. The
// direction matters in both ways: a mistyped address answered 500 told the operator
// the daemon was broken, and a database write failure answered 404 told an
// integration the client did not exist while the record sat in the list.
func TestClientErrorStatus(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{
			name: "unparseable address is the caller's fault",
			err:  service.ErrInvalidIP,
			want: http.StatusBadRequest,
		},
		{
			name: "wrapped invalid IP is still the caller's fault",
			err:  fmt.Errorf("%w: %q", service.ErrInvalidIP, "203.0.113.999"),
			want: http.StatusBadRequest,
		},
		{
			name: "twice-wrapped invalid IP still unwraps",
			err:  fmt.Errorf("creating client: %w", fmt.Errorf("%w: %q", service.ErrInvalidIP, "nope")),
			want: http.StatusBadRequest,
		},
		{
			name: "an unimplemented quota cycle is the caller's fault too",
			err:  service.ErrInvalidTrafficCycle,
			want: http.StatusBadRequest,
		},
		{
			name: "and still is once the service has wrapped it with the value",
			err:  fmt.Errorf("%w: %q (use daily, weekly, monthly)", service.ErrInvalidTrafficCycle, "yearly"),
			want: http.StatusBadRequest,
		},
		{
			name: "missing client is a 404",
			err:  database.ErrClientNotFound,
			want: http.StatusNotFound,
		},
		{
			name: "wrapped missing client is a 404",
			err:  fmt.Errorf("looking up %q: %w", "NOPE0000", database.ErrClientNotFound),
			want: http.StatusNotFound,
		},
		{
			name: "anything else stays a server fault rather than being guessed at",
			err:  errors.New("bbolt: write failed"),
			want: http.StatusInternalServerError,
		},
		{
			name: "nil is not a success path here, so it stays a 500",
			err:  nil,
			want: http.StatusInternalServerError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClientErrorStatus(tc.err); got != tc.want {
				t.Errorf("ClientErrorStatus(%v): want %d, got %d", tc.err, tc.want, got)
			}
		})
	}
}

// TestWriteClientErrorWritesBothHalves guards against the status and the body
// drifting apart, since WriteClientError exists precisely so no caller has to
// remember to do one after the other.
func TestWriteClientErrorWritesBothHalves(t *testing.T) {
	w := httptest.NewRecorder()
	WriteClientError(w, fmt.Errorf("%w: %q", service.ErrInvalidIP, `203.0.113."9`))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status: want 400, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type: want application/json, got %q", ct)
	}

	var payload map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("body is not JSON (%v): %s", err, w.Body.String())
	}
	if !strings.Contains(payload["error"], "203.0.113.") {
		t.Errorf("the refused address is missing from the message: %q", payload["error"])
	}
}
