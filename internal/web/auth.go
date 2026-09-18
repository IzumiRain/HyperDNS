package web

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"time"

	"hyperdns/internal/config"
)

type AuthManager struct {
	cfg      *config.Config
	mu       sync.RWMutex
	sessions map[string]time.Time
}

func NewAuthManager(cfg *config.Config) *AuthManager {
	return &AuthManager{
		cfg:      cfg,
		sessions: make(map[string]time.Time),
	}
}

func (a *AuthManager) Authenticate(username, password string) (string, bool) {
	uMatch := subtle.ConstantTimeCompare([]byte(username), []byte(a.cfg.Server.AdminUsername)) == 1
	pMatch := subtle.ConstantTimeCompare([]byte(password), []byte(a.cfg.Server.AdminPassword)) == 1

	if !uMatch || !pMatch {
		return "", false
	}

	b := make([]byte, 32)
	_, _ = rand.Read(b)
	hash := sha256.Sum256(b)
	token := hex.EncodeToString(hash[:])

	a.mu.Lock()
	a.sessions[token] = time.Now().Add(7 * 24 * time.Hour)
	a.mu.Unlock()

	return token, true
}

func (a *AuthManager) ValidateToken(token string) bool {
	if token == "" {
		return false
	}

	// 1. Direct API Key Validation (Constant-time comparison)
	if a.cfg.Server.APIKey != "" && subtle.ConstantTimeCompare([]byte(token), []byte(a.cfg.Server.APIKey)) == 1 {
		return true
	}

	// 2. Web Session Token Validation
	a.mu.RLock()
	exp, ok := a.sessions[token]
	a.mu.RUnlock()

	if !ok || time.Now().After(exp) {
		return false
	}
	return true
}

func (a *AuthManager) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := ""

		// Check X-API-Key Header
		if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
			token = apiKey
		}

		// Check Authorization Header (Bearer token or Bearer API key)
		if token == "" {
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				token = strings.TrimPrefix(authHeader, "Bearer ")
			} else if strings.HasPrefix(authHeader, "ApiKey ") {
				token = strings.TrimPrefix(authHeader, "ApiKey ")
			}
		}

		// Check Cookie
		if token == "" {
			if cookie, err := r.Cookie("hyperdns_session"); err == nil {
				token = cookie.Value
			}
		}

		// Check Query Parameter (?api_key=... or ?auth_token=...)
		if token == "" {
			if qKey := r.URL.Query().Get("api_key"); qKey != "" {
				token = qKey
			} else {
				token = r.URL.Query().Get("auth_token")
			}
		}

		if !a.ValidateToken(token) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"success":false,"error":"Unauthorized: Invalid or missing API Key / Session Token"}`))
			return
		}

		next(w, r)
	}
}
