package sniproxy

import (
	"testing"
)

func TestExtractHTTPHost(t *testing.T) {
	req := "GET / HTTP/1.1\r\nHost: discord.com:80\r\nUser-Agent: curl/7.68.0\r\nAccept: */*\r\n\r\n"
	host, err := ExtractHTTPHost([]byte(req))
	if err != nil {
		t.Fatalf("ExtractHTTPHost failed: %v", err)
	}

	if host != "discord.com" {
		t.Fatalf("expected host 'discord.com', got %q", host)
	}
}

func TestExtractSNI_Invalid(t *testing.T) {
	_, err := ExtractSNI([]byte("not a tls packet"))
	if err == nil {
		t.Fatalf("expected error for non-TLS data")
	}
}
