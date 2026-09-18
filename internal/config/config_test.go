package config

import (
	"os"
	"testing"
	"time"
)

func TestRegisterClientIP_StrictOneIP(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Access.Clients = []Client{
		{
			ID:         "1001",
			Name:       "Test Gamer",
			Token:      "test-token-123",
			AllowedIPs: []string{"1.1.1.1"},
			ExpiresAt:  time.Now().Add(24 * time.Hour),
			Enabled:    true,
		},
	}

	// 1. Same IP registration (duplicate)
	cl, alreadyPresent, err := cfg.RegisterClientIP("test-token-123", "1.1.1.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !alreadyPresent {
		t.Errorf("expected alreadyPresent=true for same IP, got false")
	}
	if len(cl.AllowedIPs) != 1 || cl.AllowedIPs[0] != "1.1.1.1" {
		t.Errorf("expected allowed IPs [1.1.1.1], got %v", cl.AllowedIPs)
	}

	// 2. New IP registration (should replace old IP with strictly 1 IP)
	cl, alreadyPresent, err = cfg.RegisterClientIP("test-token-123", "2.2.2.2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if alreadyPresent {
		t.Errorf("expected alreadyPresent=false for new IP, got true")
	}
	if len(cl.AllowedIPs) != 1 || cl.AllowedIPs[0] != "2.2.2.2" {
		t.Errorf("expected allowed IPs [2.2.2.2], got %v", cl.AllowedIPs)
	}

	// Check GetValidClientByIP
	if _, ok := cfg.GetValidClientByIP("2.2.2.2"); !ok {
		t.Errorf("expected 2.2.2.2 to be valid client IP")
	}
	if _, ok := cfg.GetValidClientByIP("1.1.1.1"); ok {
		t.Errorf("expected old IP 1.1.1.1 to be removed / deactivated")
	}
}

func TestRegisterClientIP_ExpiredAccount(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Access.Clients = []Client{
		{
			ID:         "1002",
			Name:       "Expired User",
			Token:      "expired-token-456",
			AllowedIPs: []string{"3.3.3.3"},
			ExpiresAt:  time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
			Enabled:    true,
		},
	}

	cl, _, err := cfg.RegisterClientIP("expired-token-456", "4.4.4.4")
	if err != os.ErrDeadlineExceeded {
		t.Fatalf("expected ErrDeadlineExceeded, got %v", err)
	}
	if cl.Enabled {
		t.Errorf("expected expired client to be disabled/deactivated")
	}
	if len(cl.AllowedIPs) != 0 {
		t.Errorf("expected allowed IPs to be cleared, got %v", cl.AllowedIPs)
	}

	// Should not be valid
	if _, ok := cfg.GetValidClientByIP("3.3.3.3"); ok {
		t.Errorf("expected 3.3.3.3 to be invalid")
	}
	if _, ok := cfg.GetValidClientByIP("4.4.4.4"); ok {
		t.Errorf("expected 4.4.4.4 to be invalid")
	}
}

func TestCheckAndDeactivateExpiredClients(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Access.Clients = []Client{
		{
			ID:         "1003",
			Name:       "Active User",
			AllowedIPs: []string{"5.5.5.5"},
			ExpiresAt:  time.Now().Add(1 * time.Hour),
			Enabled:    true,
		},
		{
			ID:         "1004",
			Name:       "Expired User",
			AllowedIPs: []string{"6.6.6.6"},
			ExpiresAt:  time.Now().Add(-10 * time.Minute),
			Enabled:    true,
		},
	}

	deactivated := cfg.CheckAndDeactivateExpiredClients()
	if deactivated != 1 {
		t.Errorf("expected 1 deactivated client, got %d", deactivated)
	}

	if !cfg.Access.Clients[0].Enabled {
		t.Errorf("expected client 1003 to remain active")
	}
	if cfg.Access.Clients[1].Enabled {
		t.Errorf("expected client 1004 to be deactivated")
	}
	if len(cfg.Access.Clients[1].AllowedIPs) != 0 {
		t.Errorf("expected client 1004 allowed IPs to be cleared")
	}
}
