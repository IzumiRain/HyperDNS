package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"hyperdns/internal/database"
	"hyperdns/internal/httpx"
	"hyperdns/internal/service/acme"
)

// ACME issuance for the operator's own domain.
//
// This is the only place in the daemon that runs another program, and it runs it
// with the daemon's own privileges — root on a normal install, because the resolver
// binds port 53. That is why the two strings the operator types are validated
// before they are used. exec.Command passes an argv slice and starts no shell, so
// there is nothing to inject a command into; but certbot parses those arguments
// itself, a value beginning with "-" is read as an option rather than as the domain
// it was meant to be, and certbot has options that execute commands (--deploy-hook,
// --pre-hook). "Whatever was in the text box" must not reach the argv of a root
// process unchecked.
//
// The validation is also, mostly, just what an ACME certificate requires. Refusing
// here rather than letting certbot refuse later is what turns a confusing failure
// minutes afterwards into an answer the operator can act on now.

const (
	// acmeIssueTimeout bounds one certbot run. HTTP-01 for a single name is a short
	// exchange with the ACME server plus one inbound request, so five minutes is
	// already generous. The bound exists because certbot can block on network I/O
	// indefinitely, and an issuance that never returns would hold both a root process
	// and the single-flight gate below for the rest of the daemon's life.
	acmeIssueTimeout = 5 * time.Minute

	// acmeChallengePort is where the ACME server connects to verify the name. It is
	// not configurable: RFC 8555 §8.3 fixes HTTP-01 at port 80.
	acmeChallengePort = 80

	// maxACMEDomainLength and maxACMEEmailLength are the DNS name limit (RFC 1035
	// §2.3.4) and the SMTP path limit (RFC 5321 §4.5.3.1.3).
	maxACMEDomainLength = 253
	maxACMEEmailLength  = 254
)

// validACMEDomain returns the name to request a certificate for, lower-cased and
// trimmed, or an error phrased for the operator who typed it.
//
// The order of the checks is deliberate. A value that would be read as an option
// is refused as that, before any attempt to describe it as a malformed name; and an
// IP literal is named as an IP literal rather than reported as "not fully
// qualified", which is what "::1" would otherwise get told.
func validACMEDomain(raw string) (string, error) {
	domain := strings.ToLower(strings.TrimSpace(raw))

	switch {
	case domain == "":
		return "", errors.New("domain cannot be empty")
	case strings.HasPrefix(domain, "-"):
		return "", errors.New("domain cannot start with '-'")
	case len(domain) > maxACMEDomainLength:
		return "", fmt.Errorf("domain cannot be longer than %d characters (this one is %d)", maxACMEDomainLength, len(domain))
	case strings.HasPrefix(domain, "*."):
		return "", errors.New("a wildcard certificate needs the DNS-01 challenge, which this button cannot perform; issue one manually with certbot's DNS plugin")
	case strings.HasSuffix(domain, "."):
		return "", errors.New("domain cannot end with '.'")
	case net.ParseIP(domain) != nil:
		return "", errors.New("a certificate cannot be issued for an IP address; use a domain name pointed at this server")
	case !strings.Contains(domain, "."):
		return "", errors.New("domain must be a fully qualified name, such as dns.example.com")
	}

	for label := range strings.SplitSeq(domain, ".") {
		if err := validACMELabel(label); err != nil {
			return "", err
		}
	}
	return domain, nil
}

// validACMELabel enforces the label rules the ACME server would apply anyway (RFC
// 1035 §2.3.1 and RFC 1123 §2.1): one to sixty-three bytes of letters, digits and
// hyphens, not beginning or ending with a hyphen. It assumes an already lower-cased
// label, which is what validACMEDomain hands it.
//
// Non-ASCII is refused by naming the punycode form, because that is the thing the
// operator then has to go and look up. Both an empty label and a stray character are
// quoted back, since "dns..example.com" and "dns example.com" are typing mistakes
// whose cause is not visible in a message that does not repeat the input.
func validACMELabel(label string) error {
	switch {
	case label == "":
		return errors.New("domain cannot contain an empty part (a leading dot, or two dots in a row)")
	case len(label) > 63:
		return fmt.Errorf("each part of the domain must be 63 characters or fewer; %q is %d", label, len(label))
	case strings.HasPrefix(label, "-"), strings.HasSuffix(label, "-"):
		return fmt.Errorf("no part of the domain may start or end with '-'; %q does", label)
	}

	for _, r := range label {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
		case r > 127:
			return errors.New("domain must be ASCII; enter the punycode form of an internationalised name (it begins with 'xn--')")
		default:
			return fmt.Errorf("domain may contain only letters, digits, '-' and '.'; %q is not allowed", r)
		}
	}
	return nil
}

// validACMEEmail returns the ACME registration contact. An empty value is allowed
// and returns "": the account is then registered without a contact, and the operator
// loses only the expiry reminders Let's Encrypt would otherwise have sent.
//
// This is not an RFC 5322 parser and does not try to be. It refuses the shapes that
// would reach certbot's argv as something other than an address, and the ones the
// ACME server would reject minutes after the operator had been told it worked. The
// address is returned as typed, because the part before '@' is case-sensitive.
func validACMEEmail(raw string) (string, error) {
	email := strings.TrimSpace(raw)
	if email == "" {
		return "", nil
	}

	switch {
	case strings.HasPrefix(email, "-"):
		return "", errors.New("email cannot start with '-'")
	case len(email) > maxACMEEmailLength:
		return "", fmt.Errorf("email cannot be longer than %d characters (this one is %d)", maxACMEEmailLength, len(email))
	case strings.Count(email, "@") != 1:
		return "", errors.New("email must contain exactly one '@'")
	}

	local, host, _ := strings.Cut(email, "@")
	switch {
	case local == "", host == "":
		return "", errors.New("email needs a name and a domain, as in you@example.com")
	case !strings.Contains(host, "."):
		return "", errors.New("the domain after '@' must be a fully qualified name, as in you@example.com")
	}

	for _, r := range email {
		if r <= ' ' || r == 0x7f {
			return "", errors.New("email cannot contain spaces or control characters")
		}
	}
	return email, nil
}

// handleTLSSettings stores the domain a certificate should be issued for, then starts
// one issuance attempt behind it.
//
// The two effects are reported separately, and that is the point. Storing the domain
// is what the operator asked for, and is what /api/config and the subscriber portal
// will show from now on. Issuance is best-effort: it needs certbot installed, port 80
// free, and the name already resolving to this machine, none of which the daemon
// controls. The handler this replaces answered {"success":true} either way, so a
// domain that could never be issued for looked exactly like one that had been.
// Issuance purposes. The three Let's Encrypt buttons in the dashboard each
// name the surface their certificate belongs to; the strings are hoisted
// into constants so the handler body contains no bare `"panel":`-shaped
// literals (a shape the contract tests read as response keys).
const (
	acmePurposePanel        = "panel"
	acmePurposeSubscription = "subscription"
	acmePurposeDOT          = "dot"
)

func (ws *WebServer) handleTLSSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		httpx.WriteMethodNotAllowed(w, "POST")
		return
	}

	// BuildHandler already caps every body. Two short strings need far less than that,
	// and the tighter limit is stated here so it sits beside the payload it describes.
	var req struct {
		Domain  string `json:"domain"`
		Email   string `json:"email"`
		Purpose string `json:"purpose"` // "panel" (default) | "subscription" | "dot"
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		httpx.WriteJSONError(w, http.StatusBadRequest, "the request body could not be read as JSON")
		return
	}

	purpose := req.Purpose
	switch purpose {
	case "", acmePurposePanel:
		purpose = acmePurposePanel
	case acmePurposeSubscription, acmePurposeDOT:
	default:
		httpx.WriteJSONError(w, http.StatusBadRequest, "purpose must be panel, subscription, or dot")
		return
	}

	// A non-panel purpose with an empty domain is the "back to the panel
	// domain" gesture: clear the custom name, apply immediately, no issuance.
	if purpose == acmePurposeSubscription || purpose == acmePurposeDOT {
		if strings.TrimSpace(req.Domain) == "" {
			problem := ws.applyIssuedPurpose("", purpose, "", "")
			if problem != "" {
				httpx.WriteJSONError(w, http.StatusInternalServerError, problem)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"domain":  "",
				"issuing": false,
				"detail":  "custom domain cleared — the panel's name and certificate apply again.",
			})
			return
		}
	}

	domain, err := validACMEDomain(req.Domain)
	if err != nil {
		httpx.WriteJSONErrorFor(w, http.StatusBadRequest, err)
		return
	}
	email, err := validACMEEmail(req.Email)
	if err != nil {
		httpx.WriteJSONErrorFor(w, http.StatusBadRequest, err)
		return
	}

	if purpose == acmePurposePanel {
		// The panel purpose keeps today's contract: the domain is part of the
		// TLS record (it is load-bearing for the whole HTTPS panel), so it is
		// stored up front and the issuance follows.
		if err := ws.tlsSettings.SetACME(domain, email, func(s *database.TLSSettings) error {
			return ws.db.SetSetting("tls", s)
		}); err != nil {
			log.Printf("[TLS] storing domain %s failed: %v", domain, err)
			httpx.WriteJSONError(w, http.StatusInternalServerError, "the domain could not be stored; see the daemon log")
			return
		}
		// A valid pair for the name may already be on disk (an operator renaming
		// back to a previously issued name, a re-save after a failed swap — or
		// the plain re-save, where the stored pair is already the valid pair for
		// this exact name). Applying it synchronously spends no Let's Encrypt
		// quota and closes the divergence window the same moment the domain is
		// saved — the subscription surface's fast path, now the panel's.
		//
		// The condition must not compare the resolved paths against the stored
		// ones: when they are equal the pair is already valid AND already
		// applied, so the comparison's "different paths only" reading sent every
		// ordinary re-save to startACMEIssuance anyway. Let's Encrypt allows five
		// duplicate certificates per hostname per week, so repeated saves of an
		// unchanged domain burned that quota and could block a later real
		// renewal. A pair that validates for the domain is sufficient.
		if c, k, resErr := ws.panelCertificatePair(); resErr == nil {
			if problem := ws.applyIssuedPurpose(domain, acmePurposePanel, c, k); problem != "" {
				httpx.WriteJSONError(w, http.StatusInternalServerError, problem)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"domain":  domain,
				"issuing": false,
				"detail":  "a valid certificate for " + domain + " was already on this server — it has been applied without contacting Let's Encrypt.",
			})
			return
		}
		issuing, detail := ws.startACMEIssuance(domain, email, purpose)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"domain":  domain,
			"issuing": issuing,
			"detail":  detail,
		})
		return
	}

	// subscription / dot: the settings record changes ONLY on success, so a
	// typo'd or unissuable name can never leave the daemon serving a cert for
	// the wrong host — the field-report "Not Secure after changing the
	// domain" bug. If a valid pair is already on disk for this name, apply it
	// synchronously without spending Let's Encrypt quota.
	if ws.acmeManager != nil {
		certPath := filepath.Join(ws.acmeManager.CertDir, domain+".crt")
		keyPath := filepath.Join(ws.acmeManager.CertDir, domain+".key")
		if err := ValidatePanelCertificate(certPath, keyPath, domain); err == nil {
			if problem := ws.applyIssuedPurpose(domain, purpose, certPath, keyPath); problem != "" {
				httpx.WriteJSONError(w, http.StatusInternalServerError, problem)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"domain":  domain,
				"issuing": false,
				"detail":  "a valid certificate for " + domain + " was already on this server — it has been applied without contacting Let's Encrypt.",
			})
			return
		}
	}

	issuing, detail := ws.startACMEIssuance(domain, email, purpose)
	if !issuing {
		httpx.WriteJSONError(w, http.StatusConflict, detail)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"domain":  domain,
		"issuing": true,
		"detail":  detail,
	})
}

// handleACMEStatus answers the progress poll: the manager's live RunState
// plus the last completed result, so a section can render its bar while a run
// is in flight and the outcome after it lands.
func (ws *WebServer) handleACMEStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		httpx.WriteMethodNotAllowed(w, "GET, HEAD")
		return
	}
	if ws.acmeManager == nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"running": false})
		return
	}
	state := ws.acmeManager.State()
	lastDetail, lastAt := ws.acmeManager.LastResult()
	_ = json.NewEncoder(w).Encode(map[string]any{
		"running":     state.Running,
		"purpose":     state.Purpose,
		"domain":      state.Domain,
		"stage":       state.Stage,
		"progress":    state.Progress,
		"detail":      state.Detail,
		"error":       state.Err,
		"last_detail": lastDetail,
		"last_run_at": lastAt,
	})
}

// startACMEIssuance decides whether an embedded issuance can usefully be
// started and, if it can, starts one. It returns whether a run is now in
// flight, and a sentence for the operator either way.
//
// v2.2.0: the run is the in-daemon ACME client (internal/service/acme), not a
// certbot shell. The two v2.1 failures this fixes are structural: certbot
// needed to be installed by the OS (an offline install could not), and it
// needed port 80 free (this daemon's own SNI proxy held it). The embedded
// client serves the HTTP-01 challenge out of the running port-80 listener and
// ships inside the binary.
//
// The gate is taken before anything else, so a second Save neither spawns a
// second order nor burns Let's Encrypt's duplicate-certificate quota (five
// per name per week). For non-panel purposes the refusal names the in-flight
// run so both buttons can say what is happening.
func (ws *WebServer) startACMEIssuance(domain, email, purpose string) (bool, string) {
	if ws.acmeManager == nil {
		return false, "domain saved. Automatic issuance is not available in this build — point cert_path and key_path at a certificate you already hold."
	}
	if !ws.acmeRunning.CompareAndSwap(false, true) {
		inFlight := ws.acmeManager.State()
		if inFlight.Running {
			return false, fmt.Sprintf("an issuance for %s (%s) is already running — wait for it to finish.", inFlight.Domain, inFlight.Purpose)
		}
		return false, "an issuance is already running; its result will be in the daemon log."
	}
	go ws.runEmbeddedACME(domain, email, purpose)
	return true, fmt.Sprintf("requesting a certificate for %s over the built-in ACME client — this usually takes under a minute; watch the progress bar.", domain)
}

// runEmbeddedACME performs one issuance and applies the result to the surface
// its purpose names. It holds the single-flight gate for its lifetime. The
// manager reports progress (0-90); applyIssuedPurpose + Complete close the
// run at 100 when the certificate is on disk, validated, and live.
func (ws *WebServer) runEmbeddedACME(domain, email, purpose string) {
	defer ws.acmeRunning.Store(false)

	ctx, cancel := context.WithTimeout(context.Background(), acmeIssueTimeout)
	defer cancel()

	ws.acmeManager.ContactEmail = email
	res, err := ws.acmeManager.Issue(ctx, domain, purpose)
	if err != nil {
		log.Printf("[TLS] embedded ACME for %s (%s) failed: %v", domain, purpose, err)
		return
	}
	certPath, keyPath, err := acme.Persist(ws.acmeManager.CertDir, domain, res.CertPEM, res.KeyPEM)
	if err != nil {
		log.Printf("[TLS] embedded ACME issued for %s but persisting failed: %v", domain, err)
		// The run is over and it failed — say so on the poll, which otherwise
		// still shows the successful "fetched/90" stage Issue left behind.
		ws.acmeManager.ApplyFailed("the certificate was issued but could not be written to disk: " + err.Error())
		return
	}
	// Promote the stored paths only after the pair is on disk and passes the
	// same validator the panel listener applies — a save that pointed the
	// daemon at a not-yet-existing file is the fail-closed boot loop the
	// v2.1 ACME panel already had to recover from by hand.
	if err := ValidatePanelCertificate(certPath, keyPath, domain); err != nil {
		log.Printf("[TLS] embedded ACME result for %s did not validate: %v", domain, err)
		ws.acmeManager.ApplyFailed("the issued certificate did not validate: " + err.Error())
		return
	}
	if problem := ws.applyIssuedPurpose(domain, purpose, certPath, keyPath); problem != "" {
		log.Printf("[TLS] embedded ACME for %s (%s) issued but could not be applied: %s", domain, purpose, problem)
		ws.acmeManager.ApplyFailed(problem)
		return
	}
	ws.acmeManager.Complete(fmt.Sprintf("certificate for %s issued and applied — links and listeners updated.", domain))
}

// applyIssuedPurpose moves an issued (or cleared, paths empty) certificate
// into the surface the purpose names: the subscription record + listener, the
// DoT/DoH listeners, or the panel record + holder. It returns "" on success
// and a human problem otherwise; nothing partial persists.
func (ws *WebServer) applyIssuedPurpose(domain, purpose, certPath, keyPath string) string {
	switch purpose {
	case "panel":
		if err := ws.tlsSettings.SetCertPaths(certPath, keyPath, func(s *database.TLSSettings) error {
			return ws.db.SetSetting("tls", s)
		}); err != nil {
			return fmt.Sprintf("could not persist the new certificate paths: %v", err)
		}
		if ws.certHolder != nil {
			if err := ws.certHolder.Load(certPath, keyPath); err != nil {
				log.Printf("[TLS] certificate is on disk and persisted but the live swap failed (%v) — it loads at next restart", err)
			} else {
				log.Printf("[TLS] serving the newly issued certificate for %s without restart", domain)
			}
		} else {
			log.Printf("[TLS] certificate for %s issued and persisted; it loads at next restart", domain)
		}
		return ""

	case acmePurposeSubscription:
		// The record's own paths point at the ACME pair; UsePanelCertificate
		// is forced off so subscriberTLSConfig serves exactly this cert. An
		// empty domain (the clear gesture) restores the panel-cert default.
		// prev is the rollback copy: the bind below shuts the old listener
		// down before it can know the new bind succeeds, so a bind failure
		// must undo the record too — a portal left down with its record naming
		// a domain nothing serves is the one partial-apply state this switch
		// refuses to leave behind. It is a copy of the SAME snapshot (not a
		// second lock acquisition): a concurrent save landing between two
		// acquisitions would make the rollback restore a superseded record
		// and silently discard the operator's save.
		snap := ws.subSettings.Snapshot()
		prev := snap
		if domain == "" {
			snap.Domain = ""
			snap.CertPath = ""
			snap.KeyPath = ""
			snap.UsePanelCertificate = true
		} else {
			snap.Domain = domain
			snap.CertPath = certPath
			snap.KeyPath = keyPath
			snap.UsePanelCertificate = false
		}
		if err := ws.subSettings.Apply(snap, func(s *database.SubscriptionSettings) error {
			return ws.db.SetSetting("subscription", s)
		}); err != nil {
			return fmt.Sprintf("could not persist the subscription settings: %v", err)
		}
		// Rebind so the OLD domain's cert stops being served this moment: the
		// bind path shuts the previous listener down before binding the new
		// one, and the new listener serves the new pair.
		if problem := ws.bindSubscriberListener(context.Background(), false); problem != nil {
			// The record moved but the portal is down. Restore the previous
			// record so what is persisted and what is served agree again; if
			// even the rollback write fails there is nothing left to do but
			// say so — the daemon log is the operator's next stop either way.
			if rbErr := ws.subSettings.Apply(prev, func(s *database.SubscriptionSettings) error {
				return ws.db.SetSetting("subscription", s)
			}); rbErr != nil {
				log.Printf("[Web] subscription record could not be restored after the listener rebind failed: %v", rbErr)
			} else if rebindErr := ws.bindSubscriberListener(context.Background(), false); rebindErr != nil {
				log.Printf("[Web] subscription listener could not be restored after rollback: %v", rebindErr)
			}
			return "the certificate was issued, but the portal listener could not be rebound to it and the previous settings were restored: " + problem.Error()
		}
		log.Printf("[Web] Subscription domain applied (%q) and the listener rebound to its certificate", domain)
		return ""

	case acmePurposeDOT:
		// The whole dot apply — record persist, holder state, listener rebind —
		// runs under one mutex. A clear racing a re-issue used to be able to
		// interleave "record says domain, listeners say panel": the rebind hook
		// is two steps on the DNS server and the last writer must win the
		// record AND the listeners together, not one after the other.
		ws.dotHolderMu.Lock()
		problem := ws.applyDotPurpose(domain, certPath, keyPath)
		ws.dotHolderMu.Unlock()
		return problem
	}
	return "unknown purpose " + purpose
}

// applyDotPurpose is the body of the dot case, called under dotHolderMu.
func (ws *WebServer) applyDotPurpose(domain, certPath, keyPath string) string {
	prevHolder := ws.dotCertHolder
	if err := ws.tlsSettings.SetDoTDomain(domain, func(s *database.TLSSettings) error {
		return ws.db.SetSetting("tls", s)
	}); err != nil {
		return fmt.Sprintf("could not persist the DoH/DoT domain: %v", err)
	}
	if domain == "" {
		// Cleared: detach the dedicated source and rebuild the listeners so
		// they come back on the panel certificate. The field must mirror
		// what the listeners now carry — leaving the holder here would let
		// a later issuance hot-swap a certificate into listeners that were
		// rebuilt without any source, and nothing would change live.
		ws.dotCertHolder = nil
		if ws.dnsRebind != nil {
			if err := ws.dnsRebind(nil); err != nil {
				ws.dotCertHolder = prevHolder
				return "the domain was cleared, but the DoH/DoT listeners could not be rebound: " + err.Error()
			}
		}
		log.Printf("[TLS] DoH/DoT custom domain cleared — the panel certificate applies")
		return ""
	}
	// A holder that already exists serves every renewal and every rename by
	// hot-swapping the pair through its closure — no rebind, no dropped
	// handshake.
	if holder := ws.dotCertHolder; holder != nil {
		if err := holder.Load(certPath, keyPath); err != nil {
			return fmt.Sprintf("the certificate is on disk but could not be loaded into the DoT/DoH listeners: %v", err)
		}
		log.Printf("[TLS] DoH/DoT listeners now serve %s", domain)
		return ""
	}
	// No holder was wired at boot (the domain was configured without a
	// valid pair, so main left the source nil and the listeners were built
	// riding the panel certificate). Construct the holder here and rebuild
	// the listeners onto it — the first issuance must take effect live, not
	// only after a restart.
	newHolder := NewCertHolderLoading(certPath, keyPath)
	if newHolder == nil {
		return fmt.Sprintf("the certificate for %s is on disk but could not be loaded into the DoT/DoH listeners", domain)
	}
	ws.dotCertHolder = newHolder
	if ws.dnsRebind != nil {
		if err := ws.dnsRebind(newHolder); err != nil {
			ws.dotCertHolder = prevHolder
			return "the certificate is live in the holder, but the DoH/DoT listeners could not be rebuilt onto it: " + err.Error()
		}
		log.Printf("[TLS] DoH/DoT listeners rebuilt and now serve %s", domain)
	} else {
		log.Printf("[TLS] certificate for %s loaded; the DoH/DoT listeners pick it up at next restart", domain)
	}
	return ""
}

// RenewIfDue is the daily-loop entry point for the panel certificate: when
// the configured domain's stored certificate is within the renewal window (or
// absent entirely — a failed boot issuance the operator never re-saved), it
// runs one issuance through the same single-flighted path the dashboard Save
// uses. Safe to call on any cadence — the gate and NeedsRenewal make a
// too-early call a no-op.
func (ws *WebServer) RenewIfDue() {
	domain, email := ws.tlsSettings.ACMEContact()
	ws.renewPurposeIfDue(acmePurposePanel, domain, email)
}

// RenewSubscriptionIfDue renews the subscription portal's own certificate.
// The record rides the panel certificate unless a distinct domain with its
// own ACME pair is configured; only the latter needs its own renewal — the
// panel renewal covers every record that mirrors the panel's name.
func (ws *WebServer) RenewSubscriptionIfDue() {
	if ws.subSettings == nil {
		return
	}
	snap := ws.subSettings.Snapshot()
	if !snap.Enabled || snap.Domain == "" || snap.UsePanelCertificate {
		return
	}
	// A panel without a domain (IP-addressed) is not "the same origin" — the
	// subscription portal on its own ACME domain is a supported shape and its
	// pair still needs its own renewal. Skip only a genuine mirror.
	if panel := ws.effectivePanelDomain(); panel != "" && strings.EqualFold(snap.Domain, panel) {
		return
	}
	_, email := ws.tlsSettings.ACMEContact()
	ws.renewPurposeIfDue(acmePurposeSubscription, snap.Domain, email)
}

// RenewDOTIfDue renews the DoH/DoT transports' dedicated certificate. Without
// this the custom Android Private DNS domain served an expired certificate
// around day 90 — the holder hot-swaps whatever is issued, but nothing ever
// issued it after the first grant.
func (ws *WebServer) RenewDOTIfDue() {
	domain := strings.TrimSpace(ws.tlsSettings.GetDoTDomain())
	if domain == "" {
		return
	}
	_, email := ws.tlsSettings.ACMEContact()
	ws.renewPurposeIfDue(acmePurposeDOT, domain, email)
}

// renewPurposeIfDue runs one single-flighted issuance for the named purpose
// when the certificate that purpose serves is inside the renewal window, or
// unreadable, or missing outright. The three call sites are the daily loop's
// whole renewal surface; every one of them resolves the pair the same way
// the live listener does, so a renewal never spends Let's Encrypt quota on a
// name nothing serves.
func (ws *WebServer) renewPurposeIfDue(purpose, domain, email string) {
	if strings.TrimSpace(domain) == "" || ws.acmeManager == nil {
		return
	}
	var certPath string
	if purpose == acmePurposePanel {
		// The resolver's pair, not the raw stored path — after a rename the
		// stored path can name a different domain's certificate, and renewing
		// THAT is a quota spend for a name nobody serves. A resolution error
		// means no valid pair covers the configured domain — precisely the
		// state a failed boot issuance leaves behind — so fall through to the
		// issue branch: the daily check is the last chance to recover it.
		if p, _, err := ws.panelCertificatePair(); err == nil {
			certPath = p
		}
	} else {
		certPath = filepath.Join(ws.acmeDir(), domain+".crt")
	}
	if certPath != "" {
		if certPEM, err := os.ReadFile(certPath); err == nil && !acme.NeedsRenewal(certPEM) {
			return
		}
	}
	if !ws.acmeRunning.CompareAndSwap(false, true) {
		return // a dashboard Save is already in flight
	}
	go ws.runEmbeddedACME(domain, email, purpose)
}

// StartACMEIfNeeded runs ONE embedded issuance at daemon startup when the
// operator has configured a domain but no usable certificate covers it yet
// (fresh installs where the installer answered the domain prompt). It is
// synchronous and bounded by acmeIssueTimeout: main calls it before the TLS
// config is loaded, so the panel either comes up with a real certificate or
// fails closed with the actionable error — never "Not secure".
//
// "Usable" is checked with the same validator the panel listener applies, and
// that validator refuses a self-signed certificate for a configured domain.
// That refusal is the fix for the field failure: the fallback generator names
// the configured domain in its SAN, so the old date-and-hostname-only check
// saw the self-signed pair as "a usable certificate is already in place" and
// never issued anything — the daemon then served the fallback and every
// browser showed Not secure.
//
// The challenge for this issuance is served by the SNI proxy's port-80
// listener (or the manager's own listener when the proxy is off), which main
// binds before calling here — that ordering is what lets issuance happen
// while the daemon runs, instead of the v2.1 dance of stopping the service
// so certbot could have port 80.
func (ws *WebServer) StartACMEIfNeeded() {
	domain, email := ws.tlsSettings.ACMEContact()
	if strings.TrimSpace(domain) == "" {
		return
	}
	// The resolver, not the raw stored paths: a renamed domain whose ACME
	// pair is already on disk must boot straight to serving it — issuing
	// again would burn quota for a certificate this server already holds,
	// and failing closed here would loop a healthy install.
	if _, _, err := ws.panelCertificatePair(); err == nil {
		return // a usable, CA-signed certificate is already in place
	}
	if ws.acmeManager == nil {
		log.Printf("[TLS] No trusted certificate for %s and the embedded ACME client is not wired — panel start will fail closed. Point cert_path/key_path at a real certificate.", domain)
		return
	}
	log.Printf("[TLS] No trusted certificate for %s; requesting one from Let's Encrypt over the built-in client (up to %s)...", domain, acmeIssueTimeout)
	// Take the same single-flight gate the Save path takes. Startup is
	// synchronous and runs before the panel serves, so in a normal boot no Save
	// can race it; but a Save that lands during this window (the panel's own
	// health probe, an operator's second tab, a retry) would find the gate free
	// and start a second issuance for the same name. The gate is the one
	// contract that says "exactly one issuance per name at a time" — a path
	// that skips it makes that promise optional. runEmbeddedACME clears it on
	// return, so holding it here costs the startup run nothing.
	if !ws.acmeRunning.CompareAndSwap(false, true) {
		log.Printf("[TLS] an embedded ACME run is already in progress; startup issuance skipped")
		return
	}
	ws.runEmbeddedACME(domain, email, "panel")
	if _, _, err := ws.panelCertificatePair(); err != nil {
		log.Printf("[TLS] Certificate for %s is still not usable after issuance: %v", domain, err)
	}
}
