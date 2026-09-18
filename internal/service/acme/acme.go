// Package acme implements the daemon's own ACME (RFC 8555) certificate client
// for Let's Encrypt, replacing the certbot/acme.sh shells the v2.1 installer
// and dashboard spawned.
//
// Why in-process: the shell tools had two structural problems no flag could
// fix. They need to BIND port 80 themselves (--standalone / acme.sh's socat),
// which the daemon's own SNI proxy already holds — every dashboard issuance
// died on "port 80 is not free". And the offline installer curl-installed
// them from the internet, which a machine with no internet cannot do. An
// in-process client serves the HTTP-01 challenge out of the port-80 listener
// that is already running, ships inside the single binary, and adds no module:
// golang.org/x/crypto/acme was already an indirect dependency of this build.
//
// Scope kept deliberately small: one domain (the panel domain), HTTP-01 only,
// renewal at <=30 days remaining, single-flight issuance. No autocert Manager:
// it wants to own the HTTP listener outright, and here port 80 is shared with
// the proxy relay.
package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
)

// Manager owns the ACME account and one certificate lineage.
type Manager struct {
	// DirectoryURL is the ACME directory. Empty means Let's Encrypt production;
	// tests inject the pebble/staging URL.
	DirectoryURL string

	// AccountKeyPEM is the persisted ACME account key (ECDSA P-256, PKCS 8).
	// The account is registered on first use and this key signs every later
	// order; losing it means re-registering, which Let's Encrypt allows but
	// rate-limits, so it is stored like any other setting.
	AccountKeyPEM []byte

	// ContactEmail rides the registration (Let's Encrypt expiry notices).
	ContactEmail string

	// CertDir is where issued pairs land (atomic temp+rename).
	CertDir string

	mu           sync.Mutex
	client       *acme.Client
	accountKey   crypto.Signer
	running      bool
	lastResult   string
	lastRunAt    time.Time
	run          RunState
	pendingToken map[string]string // challenge token -> response body
	// pendingDomains is the set of names the in-flight tokens are proving.
	// The port-80 listener's Host check reads this instead of a captured
	// copy of the panel domain: a domain saved from the dashboard while the
	// daemon runs starts an issuance for the NEW name immediately, and a
	// proxy still comparing against its boot-time copy would refuse the
	// validation the manager just asked for — the re-save could then never
	// succeed until a restart nobody told the operator to do.
	pendingDomains map[string]bool
}

// Result is the outcome of one issuance attempt, for logging and the UI.
type Result struct {
	Issued   bool
	Detail   string
	CertPEM  []byte
	KeyPEM   []byte
	NotAfter time.Time
}

// renewBefore is how much remaining validity triggers a renewal check.
const renewBefore = 30 * 24 * time.Hour

// NewManager builds a manager from persisted state. accountKeyPEM may be nil
// on a first run; the key is created during the first issuance and surfaced
// through AccountKeyPEM afterwards so the caller can persist it.
func NewManager(directoryURL, contactEmail, certDir string, accountKeyPEM []byte) *Manager {
	return &Manager{
		DirectoryURL:   directoryURL,
		ContactEmail:   contactEmail,
		CertDir:        certDir,
		AccountKeyPEM:  accountKeyPEM,
		pendingToken:   map[string]string{},
		pendingDomains: map[string]bool{},
	}
}

// ChallengeResponse answers an HTTP-01 request: the response body for a token
// this manager is currently proving for the named Host, or ok=false. This is
// what the port-80 listener calls — the whole reason issuance no longer needs
// to stop the proxy.
//
// The Host is checked against the domain the in-flight token belongs to, not
// against any configured-but-stale copy: the manager is the only component
// that knows which validation it is actually waiting for right now.
//
// A default port is stripped from the Host before the lookup. A validator
// that sends "Host: dns.example.com:80" — legal HTTP/1.1, and what some
// non-Go ACME clients emit — otherwise misses the pendingDomains entry and
// the challenge falls through to the relay path, failing an otherwise sound
// issuance.
func (m *Manager) ChallengeResponse(host, token string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	body, ok := m.pendingToken[token]
	if !ok {
		return "", false
	}
	if !m.pendingDomains[stripHostPort(strings.ToLower(strings.TrimSpace(host)))] {
		return "", false
	}
	return body, true
}

// stripHostPort removes a trailing ":port" from an authority-form Host value.
// The optional leading bracket of an IPv6 literal is respected; a bare
// "::1"-style literal is left alone (it can never match a pending domain
// anyway, and mangling it changes nothing).
func stripHostPort(host string) string {
	i := strings.LastIndexByte(host, ':')
	if i < 0 {
		return host
	}
	if strings.Contains(host[:i], "]") || !strings.Contains(host[:i], ":") {
		if p := host[i+1:]; p != "" {
			isDigits := true
			for _, r := range p {
				if r < '0' || r > '9' {
					isDigits = false
					break
				}
			}
			if isDigits {
				return host[:i]
			}
		}
	}
	return host
}

// Running reports whether an issuance is in flight (single-flight, so a
// leaning operator cannot burn the duplicate-certificate quota).
func (m *Manager) Running() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}

// AccountKey returns a copy of the ACME account key PEM. The daily renewal
// loop persists this field from its own goroutine while a first issuance can
// still be writing it under the mutex — a bare read of the slice header was a
// genuine data race, and a torn read handed the loop a nil or stale key to
// persist.
func (m *Manager) AccountKey() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.AccountKeyPEM) == 0 {
		return nil
	}
	out := make([]byte, len(m.AccountKeyPEM))
	copy(out, m.AccountKeyPEM)
	return out
}

// LastResult returns the detail string of the last completed attempt.
func (m *Manager) LastResult() (string, time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastResult, m.lastRunAt
}

// RunState is the live picture of the issuance in flight (or the last one),
// for the dashboard's progress bars. One Manager runs one issuance at a time
// (single-flight below), and the Purpose names which surface the certificate
// is being issued for, so each settings section can tell whether the run it
// is watching is its own.
type RunState struct {
	Running   bool      `json:"running"`
	Purpose   string    `json:"purpose"` // "panel" | "subscription" | "dot"
	Domain    string    `json:"domain"`
	Stage     string    `json:"stage"`    // start, account, order, challenge, authorize, ready, finalize, fetched, done
	Progress  int       `json:"progress"` // 0-100; the web apply step completes it to 100
	Detail    string    `json:"detail"`
	StartedAt time.Time `json:"started_at"`
	Err       string    `json:"error,omitempty"`
}

// State returns a copy of the current run state.
func (m *Manager) State() RunState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.run
}

// NeedsRenewal reports whether the certificate in PEM form expires within the
// renewal window. A parse failure reads as "needs renewal" — the safe
// direction is to try, not to keep serving a possibly-broken pair.
func NeedsRenewal(certPEM []byte) bool {
	leaf, err := parseLeaf(certPEM)
	if err != nil {
		return true
	}
	return time.Until(leaf.NotAfter) < renewBefore
}

func parseLeaf(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("no CERTIFICATE block in PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

// Issue obtains (or renews) a certificate for domain via HTTP-01, using
// challengeResponse as the source the port-80 listener serves tokens from.
// purpose names the surface the certificate is for ("panel", "subscription",
// "dot") and rides RunState so each settings section can recognise its own
// run. The returned Result carries the pair in memory; the caller decides
// whether to persist and hot-swap.
func (m *Manager) Issue(ctx context.Context, domain, purpose string) (*Result, error) {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return nil, fmt.Errorf("an issuance is already running")
	}
	m.running = true
	m.run = RunState{Running: true, Purpose: purpose, Domain: domain, Stage: "start", Progress: 5, StartedAt: time.Now()}
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.running = false
		m.run.Running = false
		m.lastRunAt = time.Now()
		m.mu.Unlock()
	}()

	client, key, keyPEM, err := m.ensureClient(ctx)
	if err != nil {
		m.fail("account", 10, fmt.Sprintf("ACME account setup failed: %v", err))
		return nil, err
	}
	_ = key
	m.mu.Lock()
	m.AccountKeyPEM = keyPEM
	m.mu.Unlock()

	// The RFC 8555 order flow: AuthorizeOrder -> complete each authorization's
	// http-01 challenge -> WaitOrder reaches "ready" -> CreateOrderCert
	// finalizes with the CSR.
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(domain))
	if err != nil {
		m.fail("order", 25, fmt.Sprintf("order creation failed for %s: %v", domain, err))
		return nil, err
	}

	// Complete every authorization the order carries (one, for one domain).
	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			m.fail("authorize", 30, fmt.Sprintf("could not read the authorization for %s: %v", domain, err))
			return nil, err
		}
		if authz.Status == acme.StatusValid {
			continue // still valid from a recent issuance
		}
		var chal *acme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == "http-01" {
				chal = c
				break
			}
		}
		if chal == nil {
			m.fail("challenge", 35, fmt.Sprintf("the CA offered no http-01 challenge for %s", domain))
			return nil, fmt.Errorf("no http-01 challenge offered")
		}

		// Register the token -> response mapping BEFORE telling the CA it may
		// validate; the port-80 listener reads it on the CA's callback.
		body, err := client.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			m.fail("challenge", 40, fmt.Sprintf("could not derive the challenge response: %v", err))
			return nil, err
		}
		m.mu.Lock()
		m.pendingToken[chal.Token] = body
		m.pendingDomains[strings.ToLower(domain)] = true
		m.mu.Unlock()
		cleanup := func() {
			m.mu.Lock()
			delete(m.pendingToken, chal.Token)
			delete(m.pendingDomains, strings.ToLower(domain))
			m.mu.Unlock()
		}

		if _, err := client.Accept(ctx, chal); err != nil {
			cleanup()
			m.fail("challenge", 45, fmt.Sprintf("the CA refused the challenge acceptance: %v", err))
			return nil, err
		}
		if _, err := client.WaitAuthorization(ctx, authz.URI); err != nil {
			cleanup()
			m.fail("authorize", 60, fmt.Sprintf("validation did not complete — is port 80 reachable from the internet for %s? (%v)", domain, err))
			return nil, err
		}
		cleanup()
	}

	if _, err := client.WaitOrder(ctx, order.URI); err != nil {
		m.fail("ready", 75, fmt.Sprintf("the order never became ready: %v", err))
		return nil, err
	}

	// CSR from a fresh key: the certificate key never leaves this process
	// except through the returned PEM pair.
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		m.fail("finalize", 80, fmt.Sprintf("key generation failed: %v", err))
		return nil, err
	}
	csr, err := certRequest(csrKey, domain)
	if err != nil {
		m.fail("finalize", 80, fmt.Sprintf("CSR build failed: %v", err))
		return nil, err
	}
	der, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		m.fail("finalize", 85, fmt.Sprintf("the CA refused the certificate request: %v", err))
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der[0]})
	for _, extra := range der[1:] {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: extra})...)
	}
	keyDER, err := x509.MarshalECPrivateKey(csrKey)
	if err != nil {
		m.fail("finalize", 85, fmt.Sprintf("key marshalling failed: %v", err))
		return nil, err
	}
	keyPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	leaf, err := parseLeaf(certPEM)
	if err != nil {
		m.fail("fetched", 90, fmt.Sprintf("the issued certificate did not parse: %v", err))
		return nil, err
	}
	m.stage("fetched", 90, fmt.Sprintf("certificate issued for %s, valid until %s", domain, leaf.NotAfter.Format(time.RFC3339)))
	return &Result{
		Issued:   true,
		Detail:   fmt.Sprintf("certificate issued for %s (expires %s)", domain, leaf.NotAfter.Format("2006-01-02")),
		CertPEM:  certPEM,
		KeyPEM:   keyPEMBytes,
		NotAfter: leaf.NotAfter,
	}, nil
}

// ensureClient lazily builds the ACME client, registering the account on
// first use and reusing the persisted account key afterwards.
//
// The lock covers only the key material and the fields read alongside it —
// deliberately NOT the network calls. ChallengeResponse takes this same mutex
// on every plain-HTTP connection the port-80 listener accepts, before the
// access gate; holding the mutex across a registration round-trip (which on a
// blackholed network runs until the issue timeout) stalled the challenge path
// behind unauthenticated traffic and starved the CA's own validation behind
// the pile-up (Mantis A-5). A fresh key is published to AccountKeyPEM before
// the lock is released, so a reader (the renewal loop's persistence) and a
// retrying caller see the same key the registration is using.
func (m *Manager) ensureClient(ctx context.Context) (*acme.Client, crypto.Signer, []byte, error) {
	m.mu.Lock()
	var key crypto.Signer
	var keyPEM []byte
	if len(m.AccountKeyPEM) > 0 {
		k, err := parseAccountKey(m.AccountKeyPEM)
		if err != nil {
			m.mu.Unlock()
			return nil, nil, nil, fmt.Errorf("stored account key unreadable: %w", err)
		}
		key = k
		keyPEM = make([]byte, len(m.AccountKeyPEM))
		copy(keyPEM, m.AccountKeyPEM)
	} else {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			m.mu.Unlock()
			return nil, nil, nil, err
		}
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			m.mu.Unlock()
			return nil, nil, nil, err
		}
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		key = k
		m.AccountKeyPEM = keyPEM
	}
	directoryURL := m.DirectoryURL
	contactEmail := m.ContactEmail
	m.mu.Unlock()

	client := &acme.Client{Key: key, DirectoryURL: directoryURL}
	acct := &acme.Account{Contact: []string{}}
	if contactEmail != "" {
		acct.Contact = append(acct.Contact, "mailto:"+contactEmail)
	}
	// Register is idempotent for an existing key: the CA returns the existing
	// account, and the ToS prompt answers true (the operator opted in by
	// saving a domain in the panel).
	if _, err := client.Register(ctx, acct, func(string) bool { return true }); err != nil {
		// A key that already has an account reports an acceptable error on
		// re-registration (100/urn:ietf:params:acme:error:accountDoesNotExist
		// is the only fatal one). Retry as an update.
		if _, uerr := client.UpdateReg(ctx, acct); uerr != nil {
			return nil, nil, nil, fmt.Errorf("account registration failed: %w", err)
		}
	}

	m.mu.Lock()
	m.client = client
	m.mu.Unlock()
	return client, key, keyPEM, nil
}

func parseAccountKey(pemBytes []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block")
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if ec, ok := k.(*ecdsa.PrivateKey); ok {
			return ec, nil
		}
		return nil, fmt.Errorf("account key is not ECDSA")
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	return nil, fmt.Errorf("account key is neither PKCS8 nor SEC1 ECDSA")
}

// certRequest builds a CSR for exactly one DNS name.
func certRequest(key crypto.Signer, domain string) ([]byte, error) {
	tpl := &x509.CertificateRequest{
		DNSNames: []string{domain},
	}
	return x509.CreateCertificateRequest(rand.Reader, tpl, key)
}

// Persist writes a certificate pair atomically (temp file + rename) so a
// crash mid-write can never leave a half-truncated cert where the daemon will
// load it on the next boot.
func Persist(certDir, domain string, certPEM, keyPEM []byte) (string, string, error) {
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		return "", "", err
	}
	certPath := filepath.Join(certDir, domain+".crt")
	keyPath := filepath.Join(certDir, domain+".key")
	if err := atomicWrite(certPath, certPEM, 0o644); err != nil {
		return "", "", err
	}
	if err := atomicWrite(keyPath, keyPEM, 0o600); err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".acme-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// stage records progress while the run is alive. It also keeps lastResult in
// step so LastResult callers (the renewal loop, logs) see the same story.
func (m *Manager) stage(stage string, progress int, detail string) {
	m.mu.Lock()
	m.lastResult = detail
	m.lastRunAt = time.Now()
	r := m.run
	r.Stage, r.Progress, r.Detail = stage, progress, detail
	r.Err = ""
	m.run = r
	m.mu.Unlock()
	log.Printf("[ACME] %s", detail)
}

// fail is stage() for a terminal error: Running was already cleared by the
// deferred closer, so only the state fields are stamped.
func (m *Manager) fail(stage string, progress int, detail string) {
	m.mu.Lock()
	m.lastResult = detail
	m.lastRunAt = time.Now()
	r := m.run
	r.Stage, r.Progress, r.Detail, r.Err = stage, progress, detail, detail
	m.run = r
	m.mu.Unlock()
	log.Printf("[ACME] %s", detail)
}

// Complete stamps the terminal 100 for a purpose whose web apply step
// succeeded (persist + validate + hot-swap). The manager itself stops at 90
// ("fetched") because the apply lives in the caller.
func (m *Manager) Complete(detail string) {
	m.mu.Lock()
	m.lastResult = detail
	m.lastRunAt = time.Now()
	r := m.run
	r.Stage, r.Progress, r.Detail, r.Err = "done", 100, detail, ""
	m.run = r
	m.mu.Unlock()
	log.Printf("[ACME] %s", detail)
}

// ApplyFailed marks the run failed during the caller's apply step — the
// certificate was issued and is on disk, but never went live. Without this
// the status poll reads running:false, stage "fetched", progress 90, error
// "": a progress bar that looks merely unfinished and gives the operator
// nothing to act on.
func (m *Manager) ApplyFailed(detail string) {
	m.fail("apply", 95, detail)
}
