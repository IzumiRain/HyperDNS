package proxy

import (
	"net"
	"time"
)

// Fragmentation is paid per relayed connection, so its cost has to be bounded
// independently of what the operator puts in the config: a 1-byte chunk with a
// 100 ms delay over a 16 KiB ClientHello would emit 16384 packets to a third
// party and pin the goroutine for half an hour. Splitting the record across a
// few dozen segments already defeats SNI-inspecting DPI, so both the packet
// count and the total sleep are capped.
const (
	maxFragments      = 64
	maxFragmentBudget = 2 * time.Second
)

// SendFragmented writes data in chunks with a micro-delay to bypass DPI SNI
// inspection.
func SendFragmented(conn net.Conn, data []byte, chunkSize int, delayMs int) error {
	total := len(data)
	if chunkSize <= 0 || chunkSize >= total {
		_, err := conn.Write(data)
		return err
	}

	// Raise the chunk size until the write count fits the cap, rounding up so
	// the last chunk is never larger than the rest.
	if n := (total + chunkSize - 1) / chunkSize; n > maxFragments {
		chunkSize = (total + maxFragments - 1) / maxFragments
	}
	fragments := (total + chunkSize - 1) / chunkSize

	delay := time.Duration(delayMs) * time.Millisecond
	if delay < 0 {
		delay = 0
	}
	if gaps := time.Duration(fragments - 1); gaps > 0 && delay*gaps > maxFragmentBudget {
		delay = maxFragmentBudget / gaps
	}

	for offset := 0; offset < total; offset += chunkSize {
		end := min(offset+chunkSize, total)
		if _, err := conn.Write(data[offset:end]); err != nil {
			return err
		}
		if end < total && delay > 0 {
			time.Sleep(delay)
		}
	}
	return nil
}
