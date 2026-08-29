package sniproxy

import (
	"net"
	"time"
)

// SendFragmented writes data in chunks with a micro-delay to bypass DPI SNI inspection.
func SendFragmented(conn net.Conn, data []byte, chunkSize int, delayMs int) error {
	if chunkSize <= 0 || chunkSize >= len(data) {
		_, err := conn.Write(data)
		return err
	}

	total := len(data)
	offset := 0

	for offset < total {
		end := offset + chunkSize
		if end > total {
			end = total
		}

		chunk := data[offset:end]
		if _, err := conn.Write(chunk); err != nil {
			return err
		}

		offset = end
		if offset < total && delayMs > 0 {
			time.Sleep(time.Duration(delayMs) * time.Millisecond)
		}
	}

	return nil
}
