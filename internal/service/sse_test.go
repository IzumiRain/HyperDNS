package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"hyperdns/internal/database"
)

// The live-log stream is the one handler in this package that never returns while a
// client is connected, and each subscriber costs a goroutine and a buffered channel.
// That makes the cap a denial-of-service guard rather than a tidiness measure: 64
// held-open connections is trivial for an attacker with a session, and an unbounded
// map is how the daemon is exhausted. These tests pin the refusal, that the refusal
// does not open a half-written stream, and that a slot comes back when a tab closes.

// streamRecorder is an http.ResponseWriter for a response that never ends. The body
// is mutex-guarded because ServeSSE writes from its own goroutine while the test
// reads, and each Flush is signalled so a test can wait for a frame rather than
// sleep. Reading the headers after a signal is safe without a lock: ServeSSE sets
// them all before the first flush and never touches them again.
type streamRecorder struct {
	header  http.Header
	flushed chan struct{}

	mu     sync.Mutex
	status int
	body   strings.Builder
}

func newStreamRecorder() *streamRecorder {
	return &streamRecorder{
		header:  make(http.Header),
		flushed: make(chan struct{}, 64),
		status:  http.StatusOK,
	}
}

func (s *streamRecorder) Header() http.Header { return s.header }

func (s *streamRecorder) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.body.Write(p)
}

func (s *streamRecorder) WriteHeader(code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status = code
}

func (s *streamRecorder) Flush() {
	// Non-blocking: a test that stops reading must not wedge the handler it is
	// exercising, and a dropped signal only ever means "fewer frames to wait on".
	select {
	case s.flushed <- struct{}{}:
	default:
	}
}

// text is everything written so far.
func (s *streamRecorder) text() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.body.String()
}

// awaitFlush waits for the handler to push a frame out, and fails the test rather
// than hanging if the stream stays silent.
func (s *streamRecorder) awaitFlush(t *testing.T) {
	t.Helper()
	select {
	case <-s.flushed:
	case <-time.After(2 * time.Second):
		t.Fatalf("no frame was flushed; body so far: %q", s.text())
	}
}

// subscribe starts one live-log subscriber and returns its recorder with the cancel
// that disconnects it, the way a closed browser tab does. The handler is left
// running until the test ends.
func subscribe(t *testing.T, s *StatsService) (*streamRecorder, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/api/stream/queries", nil).WithContext(ctx)
	rec := newStreamRecorder()

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.ServeSSE(rec, req)
	}()

	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("ServeSSE did not return after the client disconnected")
		}
	})
	return rec, cancel
}

// awaitSubscribers blocks until the service holds exactly n live subscribers. It
// reads the registry directly rather than inferring the count from written frames,
// so it stays correct if the first frame ever becomes conditional.
func awaitSubscribers(t *testing.T, s *StatsService, n int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		s.sseMu.RLock()
		got := len(s.sseClients)
		s.sseMu.RUnlock()
		if got == n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d subscribers registered, want %d", got, n)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestSSEStreamOpensWithAHistorySnapshotAndStaysSameOrigin(t *testing.T) {
	s := NewStatsService(nil, nil, nil)
	defer s.Close()
	s.PushQueryLog(database.QueryLogItem{Domain: "auth.riotgames.com", Action: "PROXY"})

	rec, _ := subscribe(t, s)
	rec.awaitFlush(t)

	for header, want := range map[string]string{
		"Content-Type":      "text/event-stream",
		"Cache-Control":     "no-cache",
		"X-Accel-Buffering": "no",
	} {
		if got := rec.header.Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	// This stream carries every subscriber's query history, and it is authorised by a
	// session cookie or a token in the query string. A permissive CORS header would
	// let any page the operator visits read the log.
	if origin := rec.header.Get("Access-Control-Allow-Origin"); origin != "" {
		t.Errorf("Access-Control-Allow-Origin = %q, want it absent", origin)
	}

	// The dashboard renders the backlog from this first frame; without it the log
	// starts empty on every reload and looks like the resolver answered nothing.
	body := rec.text()
	if !strings.HasPrefix(body, "event: history\ndata: ") {
		t.Fatalf("first frame is not the history snapshot: %q", body)
	}
	if !strings.Contains(body, "auth.riotgames.com") {
		t.Errorf("the snapshot omits a query pushed before the subscriber arrived: %q", body)
	}
}

func TestSSEStreamDeliversAQueryAsItHappens(t *testing.T) {
	s := NewStatsService(nil, nil, nil)
	defer s.Close()

	// The first flush is the history snapshot, and it happens after registration, so
	// waiting for it is what guarantees the push below is not broadcast into an empty
	// registry and silently lost.
	rec, _ := subscribe(t, s)
	rec.awaitFlush(t)

	s.PushQueryLog(database.QueryLogItem{
		ClientIP:    "203.0.113.50",
		AccountName: "Paid Subscriber",
		Protocol:    "UDP",
		Domain:      "playvalorant.com",
		RuleMatched: "Riot Games",
		Action:      "PROXY",
		LatencyMs:   12.5,
	})
	rec.awaitFlush(t)

	frame := rec.text()
	_, live, ok := strings.Cut(frame, "event: query\ndata: ")
	if !ok {
		t.Fatalf("the pushed query never reached the stream: %q", frame)
	}
	payload, _, ok := strings.Cut(live, "\n\n")
	if !ok {
		t.Fatalf("the query frame is not terminated by a blank line: %q", live)
	}

	var item database.QueryLogItem
	if err := json.Unmarshal([]byte(payload), &item); err != nil {
		t.Fatalf("the frame is not a QueryLogItem: %v", err)
	}
	if item.Domain != "playvalorant.com" || item.Action != "PROXY" {
		t.Errorf("frame = %+v, want the query that was pushed", item)
	}
	// PushQueryLog stamps both. The dashboard keys rows on the id and renders the
	// time, so an unstamped item arrives as a duplicate row dated 1 January year 1.
	if item.ID == 0 {
		t.Error("the item reached the client with no id")
	}
	if item.Timestamp.IsZero() {
		t.Error("the item reached the client with no timestamp")
	}
}

func TestSSERefusesTheSubscriberPastTheCapWithoutOpeningAStream(t *testing.T) {
	s := NewStatsService(nil, nil, nil)
	defer s.Close()

	for range maxSSEClients {
		subscribe(t, s)
	}
	awaitSubscribers(t, s, maxSSEClients)

	// Synchronous on purpose: a refused subscriber has to be answered and released,
	// not parked in the event loop alongside the accepted ones.
	rec := httptest.NewRecorder()
	s.ServeSSE(rec, httptest.NewRequest(http.MethodGet, "/api/stream/queries", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body: %s", rec.Code, rec.Body.String())
	}
	// A stream Content-Type on a refusal is the failure the reservation ordering
	// exists to prevent: EventSource would read the error text as the first frame and
	// reconnect forever instead of surfacing a failure the dashboard can show.
	if ct := rec.Header().Get("Content-Type"); strings.HasPrefix(ct, "text/event-stream") {
		t.Errorf("the refusal was sent as an event stream: %q", ct)
	}
	// EventSource reconnects on its own, so without Retry-After every open tab
	// retries at the browser's default interval against an already-full daemon.
	if ra := rec.Header().Get("Retry-After"); ra != "5" {
		t.Errorf("Retry-After = %q, want 5", ra)
	}
	if body := rec.Body.String(); !strings.Contains(body, "too many") {
		t.Errorf("body = %q, want it to say why", body)
	}
	// And the refusal must not have consumed the slot it was denied.
	awaitSubscribers(t, s, maxSSEClients)
}

func TestSSEReleasesTheSlotWhenASubscriberDisconnects(t *testing.T) {
	s := NewStatsService(nil, nil, nil)
	defer s.Close()

	var cancels []context.CancelFunc
	for range maxSSEClients {
		_, cancel := subscribe(t, s)
		cancels = append(cancels, cancel)
	}
	awaitSubscribers(t, s, maxSSEClients)

	// One tab closes. The cap bounds concurrent subscribers, not the number the
	// process will ever serve: a daemon still full after 64 dashboard reloads would
	// need a restart before it could show a live log again.
	cancels[0]()
	awaitSubscribers(t, s, maxSSEClients-1)

	rec, _ := subscribe(t, s)
	rec.awaitFlush(t)
	if ct := rec.header.Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("Content-Type = %q, want the freed slot to be served", ct)
	}
	awaitSubscribers(t, s, maxSSEClients)
}

// unflushableWriter is an http.ResponseWriter with no Flush method — what a
// buffering middleware leaves behind. Frames written through it would sit in a
// buffer until the response ended, which for a stream that never ends means the
// dashboard shows nothing at all.
type unflushableWriter struct {
	header http.Header
	status int
}

func (u *unflushableWriter) Header() http.Header { return u.header }

func (u *unflushableWriter) Write(p []byte) (int, error) { return len(p), nil }

func (u *unflushableWriter) WriteHeader(code int) { u.status = code }

func TestSSERefusesAWriterItCannotFlush(t *testing.T) {
	s := NewStatsService(nil, nil, nil)
	defer s.Close()

	w := &unflushableWriter{header: make(http.Header), status: http.StatusOK}
	s.ServeSSE(w, httptest.NewRequest(http.MethodGet, "/api/stream/queries", nil))

	if w.status != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.status)
	}
	// The check runs before a slot is reserved, so this path cannot fill the registry
	// with subscribers that were never served.
	awaitSubscribers(t, s, 0)
}
