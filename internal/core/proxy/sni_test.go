package proxy

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"hyperdns/internal/database"
)

// recorder is a net.Conn that records the size of every Write, so a test can
// assert how a payload was split without opening a socket. Only Write is ever
// called on it, so the embedded interface may stay nil.
type recorder struct {
	net.Conn
	mu     sync.Mutex
	writes []int
	total  int
	failAt int // 1-based write index that fails; 0 never fails
}

func (r *recorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.writes = append(r.writes, len(p))
	if r.failAt > 0 && len(r.writes) == r.failAt {
		return 0, errors.New("recorder: write failed")
	}
	r.total += len(p)
	return len(p), nil
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.writes)
}

func TestSendFragmentedWholeWrites(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 1000)

	// A chunk size that is absent, negative or at least as large as the payload
	// means no fragmentation at all: one write, unchanged bytes.
	for _, size := range []int{0, -1, 1000, 5000} {
		r := &recorder{}
		if err := SendFragmented(r, data, size, 10); err != nil {
			t.Fatalf("SendFragmented(chunk=%d) returned %v", size, err)
		}
		if r.count() != 1 || r.total != len(data) {
			t.Errorf("SendFragmented(chunk=%d) made %d writes totalling %d, want 1 of %d",
				size, r.count(), r.total, len(data))
		}
	}
}

func TestSendFragmentedSplits(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 1000)

	r := &recorder{}
	if err := SendFragmented(r, data, 100, 0); err != nil {
		t.Fatalf("SendFragmented returned %v", err)
	}
	if r.count() != 10 || r.total != len(data) {
		t.Errorf("SendFragmented(chunk=100) made %d writes totalling %d, want 10 of %d",
			r.count(), r.total, len(data))
	}

	// The packet count is capped however small the configured chunk is: a 1-byte
	// chunk over a full handshake buffer would otherwise emit 16384 packets at a
	// third party, which is amplification the operator did not ask for.
	big := bytes.Repeat([]byte("x"), handshakeBufSize)
	r = &recorder{}
	if err := SendFragmented(r, big, 1, 0); err != nil {
		t.Fatalf("SendFragmented returned %v", err)
	}
	if r.count() > maxFragments {
		t.Errorf("SendFragmented(chunk=1) made %d writes, want at most %d", r.count(), maxFragments)
	}
	if r.total != len(big) {
		t.Errorf("SendFragmented(chunk=1) wrote %d bytes, want %d", r.total, len(big))
	}

	// Every chunk but the last must be the same size, and none larger, so the
	// rounding that enforces the cap cannot produce an oversized final write.
	r = &recorder{}
	if err := SendFragmented(r, data, 30, 0); err != nil {
		t.Fatalf("SendFragmented returned %v", err)
	}
	for i, n := range r.writes {
		if n > r.writes[0] {
			t.Errorf("write %d is %d bytes, larger than the first chunk of %d", i, n, r.writes[0])
		}
	}
}

// TestSendFragmentedBudget checks the total sleep, which is what pins a relay
// goroutine. 100 chunks at 500 ms each is 50 s of held sockets per connection
// from a single config value.
func TestSendFragmentedBudget(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 1000)
	start := time.Now()
	if err := SendFragmented(&recorder{}, data, 10, 500); err != nil {
		t.Fatalf("SendFragmented returned %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*maxFragmentBudget {
		t.Errorf("SendFragmented took %v, want at most the %v budget", elapsed, maxFragmentBudget)
	}
}

func TestSendFragmentedWriteError(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 1000)
	r := &recorder{failAt: 2}
	if err := SendFragmented(r, data, 100, 0); err == nil {
		t.Fatal("SendFragmented returned nil, want the underlying write error")
	}
	if r.count() != 2 {
		t.Errorf("SendFragmented made %d writes, want it to stop at the failing 2nd", r.count())
	}
}

func TestHandshakeComplete(t *testing.T) {
	cases := []struct {
		buf   string
		isTLS bool
		want  bool
		why   string
	}{
		{"", true, false, "an empty buffer"},
		{"\x16\x03\x01", true, false, "a record header cut short"},
		{"\x16\x03\x01\x00\x04abc", true, false, "a record still missing a byte"},
		{"\x16\x03\x01\x00\x04abcd", true, true, "a complete record"},
		{"\x16\x03\x01\x00\x04abcde", true, true, "a record plus trailing bytes"},
		{"GET / HTTP/1.1\r\nHost: a\r\n", false, false, "headers that have not ended"},
		{"GET / HTTP/1.1\r\nHost: a\r\n\r\n", false, true, "a CRLF-terminated header block"},
		{"GET / HTTP/1.1\nHost: a\n\n", false, true, "an LF-terminated header block"},
	}
	for _, tc := range cases {
		if got := handshakeComplete([]byte(tc.buf), tc.isTLS); got != tc.want {
			t.Errorf("handshakeComplete(%s) = %v, want %v", tc.why, got, tc.want)
		}
	}
}

// TestReadHandshakeSplitRecord covers the failure this loop was written for: a
// single Read was assumed to deliver the whole ClientHello, so a hello split
// across TCP segments — routine once post-quantum key shares push it past one
// segment — parsed as garbage and the connection was dropped without a word.
func TestReadHandshakeSplitRecord(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	const bodyLen = 300
	record := make([]byte, 5+bodyLen)
	record[0], record[1], record[2] = 0x16, 0x03, 0x01
	record[3], record[4] = byte(bodyLen>>8), byte(bodyLen&0xff)
	for i := 5; i < len(record); i++ {
		record[i] = byte(i)
	}

	go func() {
		_, _ = client.Write(record[:20])
		time.Sleep(10 * time.Millisecond)
		_, _ = client.Write(record[20:150])
		time.Sleep(10 * time.Millisecond)
		_, _ = client.Write(record[150:])
	}()

	buf := make([]byte, handshakeBufSize)
	n, err := readHandshake(server, buf, true)
	if err != nil {
		t.Fatalf("readHandshake returned %v", err)
	}
	if n != len(record) {
		t.Fatalf("readHandshake read %d bytes, want the whole %d-byte record", n, len(record))
	}
	if !bytes.Equal(buf[:n], record) {
		t.Error("readHandshake reassembled the record incorrectly")
	}
}

// TestReadHandshakeReturnsEarly asserts the read stops as soon as the message is
// complete instead of holding the connection for the whole handshake timeout.
func TestReadHandshakeReturnsEarly(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	req := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	go func() { _, _ = client.Write([]byte(req)) }()

	buf := make([]byte, handshakeBufSize)
	start := time.Now()
	n, err := readHandshake(server, buf, false)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("readHandshake returned %v", err)
	}
	if string(buf[:n]) != req {
		t.Errorf("readHandshake read %q, want %q", buf[:n], req)
	}
	if elapsed >= handshakeTimeout {
		t.Errorf("readHandshake took %v; it waited for the deadline instead of the terminator", elapsed)
	}
}

// TestReadHandshakeSilentPeer covers a connection that is opened and abandoned:
// the read must fail on the deadline rather than block a goroutine and a slot.
func TestReadHandshakeSilentPeer(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Closing without writing is the cheap version of the same attack, and it
	// must be distinguishable from a short but usable message.
	go func() {
		time.Sleep(10 * time.Millisecond)
		_ = client.Close()
	}()

	buf := make([]byte, handshakeBufSize)
	n, err := readHandshake(server, buf, true)
	if err == nil {
		t.Fatalf("readHandshake returned (%d, nil), want an error for a peer that sent nothing", n)
	}
	if n != 0 {
		t.Errorf("readHandshake reported %d bytes read, want 0", n)
	}
}

// TestReadHandshakePartialThenClose covers a peer that sends an incomplete
// record and hangs up: whatever arrived is handed to the parser, which refuses
// it, rather than being discarded silently by the read loop.
func TestReadHandshakePartialThenClose(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		_, _ = client.Write([]byte{0x16, 0x03, 0x01, 0x01, 0x00, 0x01})
		_ = client.Close()
	}()

	buf := make([]byte, handshakeBufSize)
	n, err := readHandshake(server, buf, true)
	if err != nil {
		t.Fatalf("readHandshake returned %v, want the partial bytes", err)
	}
	if n != 6 {
		t.Fatalf("readHandshake read %d bytes, want 6", n)
	}
	if _, err := ExtractSNI(buf[:n]); err == nil {
		t.Error("ExtractSNI accepted a truncated ClientHello")
	}
}

// TestUnreadableDestinationIsCountedSeparately is the regression test for the
// silent drop that let cm.steampowered.com be advertised as proxied for months.
// A connection whose opening bytes name no destination used to return with no
// counter and no log line at all, so a preset pointing clients at a service this
// relay cannot carry produced no evidence anywhere: DNS answered, TCP connected,
// and the client waited for a peer that would never speak.
//
// The two counters must stay disjoint. A single "dropped" total cannot separate
// "the guards refused a blocked target" — healthy — from "a name is sending
// clients somewhere I cannot carry them", which is a configuration fault whose
// only symptom is a game that will not connect.
func TestUnreadableDestinationIsCountedSeparately(t *testing.T) {
	s := NewServer(database.SNIProxySettings{}, "127.0.0.1", "", nil)

	client, server := net.Pipe()
	defer client.Close()

	// Four bytes that are neither a TLS record nor an HTTP method, then hang up so
	// readHandshake returns the partial buffer instead of waiting out its deadline.
	// This is what a binary protocol on a proxied port actually looks like.
	go func() {
		_, _ = client.Write([]byte{0x00, 0x01, 0x02, 0x03})
		_ = client.Close()
	}()

	s.handleConnection(context.Background(), server, false, 8393)

	refused, unreadable := s.GuardStats()
	if unreadable != 1 {
		t.Errorf("unreadable = %d, want 1", unreadable)
	}
	if refused != 0 {
		t.Errorf("refused = %d, want 0: an unreadable connection is not a refusal, and "+
			"counting it as both makes the two indistinguishable when added", refused)
	}

	// And it must not be mistaken for a relay: the card on the dashboard reads
	// "N relays" from these, and a connection that never dialled anywhere is not one.
	active, total, sent, recv := s.GetStats()
	if active != 0 || total != 0 || sent != 0 || recv != 0 {
		t.Errorf("GetStats() = (%d, %d, %d, %d), want all zero", active, total, sent, recv)
	}
}

// TestGuardStatsStartsAtZero pins the reassuring case. The dashboard renders
// "no drops" only when both are zero, so a counter that started non-zero would
// put a permanent warning on a healthy server.
func TestGuardStatsStartsAtZero(t *testing.T) {
	s := NewServer(database.SNIProxySettings{}, "127.0.0.1", "", nil)
	if refused, unreadable := s.GuardStats(); refused != 0 || unreadable != 0 {
		t.Errorf("GuardStats() = (%d, %d) on a fresh server, want (0, 0)", refused, unreadable)
	}
}

// TestFullRelayTableIsRefusedNotUnreadable covers the other side of the split: a
// connection dropped because every relay slot was taken is a decision, so it
// belongs in refused and must leave unreadable alone. Without this, saturation
// would raise the amber "unreadable" warning and send an operator looking for a
// DNS misconfiguration that does not exist.
func TestFullRelayTableIsRefusedNotUnreadable(t *testing.T) {
	s := NewServer(database.SNIProxySettings{}, "127.0.0.1", "", nil)

	// Fill the semaphore so the slot acquisition below takes its default branch.
	for range cap(s.slots) {
		s.slots <- struct{}{}
	}

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Nothing is ever read from this connection, so the peer need not write: the
	// drop happens before the handshake read.
	s.handleConnection(context.Background(), server, true, 443)

	refused, unreadable := s.GuardStats()
	if refused != 1 {
		t.Errorf("refused = %d, want 1", refused)
	}
	if unreadable != 0 {
		t.Errorf("unreadable = %d, want 0: a full relay table is a refusal, not an "+
			"unreadable destination, and conflating them points the operator at the wrong fault", unreadable)
	}
}
