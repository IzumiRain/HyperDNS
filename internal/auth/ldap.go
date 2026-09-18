package auth

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

// The LDAP side of the v2.1 authentication settings.
//
// go-ldap v3.4.11 (MIT) is the maintained client this plan pinned; everything
// policy-shaped around it — who may log in, what gets logged, how lockout is
// counted — stays in the web package. What this file owns is the transport and
// the bind/search/bind flow, with the two hard edges the plan demands:
// a bounded connection timeout and TLS certificate verification that is never
// silently relaxed.
//
// Errors produced here are safe to show an operator: they name the failure
// stage ("directory unreachable", "invalid credentials") but never carry a
// password, a bind password, or a full LDAP URL with credentials embedded in
// it. The callers log these strings verbatim precisely because of that.

// ErrLDAPDisabled is returned by the authenticator when the directory is not
// configured, so a caller can distinguish "LDAP is off" from a failure.
var ErrLDAPDisabled = errors.New("ldap is not configured")

// LDAPConfig is one immutable snapshot of the directory settings a login
// attempt runs against. It is a plain struct rather than a pointer-shared
// record so an authenticator cannot observe a settings save mid-flight.
type LDAPConfig struct {
	ServerURL    string // ldap://host:port or ldaps://host:port
	BindDN       string // service account DN ("cn=svc,dc=example,dc=com"); empty = anonymous bind
	BindPassword string
	BaseDN       string // where user searches start ("ou=people,dc=example,dc=com")
	UserAttr     string // the attribute the login name is matched against ("uid", "sAMAccountName")
	Timeout      time.Duration
}

// Normalized returns the config with defaults applied: a 5-second timeout when
// none was set and "uid" as the user attribute when the operator left it blank.
func (c LDAPConfig) Normalized() LDAPConfig {
	if c.Timeout <= 0 {
		c.Timeout = 5 * time.Second
	}
	if strings.TrimSpace(c.UserAttr) == "" {
		c.UserAttr = "uid"
	}
	return c
}

// Configured reports whether the config names a directory at all.
func (c LDAPConfig) Configured() bool {
	return strings.TrimSpace(c.ServerURL) != "" && strings.TrimSpace(c.BaseDN) != ""
}

// LDAPAuthenticator performs one bind/search/bind login against a directory.
// The interface exists for tests: the web package fakes it to exercise every
// login-path branch without standing up a real directory.
type LDAPAuthenticator interface {
	Authenticate(username, password string, cfg LDAPConfig) error
}

// GoLDAPAuthenticator is the production implementation on go-ldap.
type GoLDAPAuthenticator struct{}

// Authenticate runs the standard bind/search/bind flow:
//
//  1. connect (with the configured timeout; ldaps:// verifies the server
//     certificate against the system roots — InsecureSkipVerify is never set);
//  2. bind as the service account (or anonymously when no bind DN is set);
//  3. search BaseDN for exactly one entry whose UserAttr equals the username
//     (the value is escaped per RFC 4515 by go-ldap's EscapeFilter, so a
//     username cannot inject a filter clause);
//  4. bind as the found user's DN with the supplied password — the only proof
//     that matters, and the one step that says whether the login is real.
//
// Returned errors are stage-named and credential-free.
func (GoLDAPAuthenticator) Authenticate(username, password string, cfg LDAPConfig) error {
	cfg = cfg.Normalized()
	if !cfg.Configured() {
		return ErrLDAPDisabled
	}
	if username == "" || password == "" {
		return errors.New("invalid credentials")
	}

	conn, err := ldap.DialURL(cfg.ServerURL, ldap.DialWithTLSConfig(&tls.Config{
		MinVersion: tls.VersionTLS12,
		// Deliberately NOT InsecureSkipVerify: an LDAP server presenting a
		// certificate no client accepts is a misconfiguration to surface, not
		// to paper over. ldaps:// without verification would be an
		// attacker-chosen credential forwarder.
	}), ldap.DialWithDialer(&net.Dialer{Timeout: cfg.Timeout}))
	if err != nil {
		return fmt.Errorf("directory unreachable: %s", describeConnErr(err))
	}
	defer conn.Close()
	conn.SetTimeout(cfg.Timeout)

	if cfg.BindDN != "" {
		if err := conn.Bind(cfg.BindDN, cfg.BindPassword); err != nil {
			if isInvalidCredentials(err) {
				return errors.New("invalid credentials")
			}
			return fmt.Errorf("directory bind failed: %w", err)
		}
	}

	filter := fmt.Sprintf("(%s=%s)", cfg.UserAttr, ldap.EscapeFilter(username))
	req := ldap.NewSearchRequest(
		cfg.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, // at most 2 entries: one is fine, two means the filter was too loose
		int(cfg.Timeout.Seconds()), false,
		filter,
		[]string{"dn"},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return fmt.Errorf("user search failed: %w", err)
	}
	if len(res.Entries) != 1 {
		// Zero entries and several entries get the same answer: either way the
		// caller learns nothing about which usernames exist.
		return errors.New("invalid credentials")
	}
	userDN := res.Entries[0].DN

	if err := conn.Bind(userDN, password); err != nil {
		if isInvalidCredentials(err) {
			return errors.New("invalid credentials")
		}
		return fmt.Errorf("directory bind failed: %w", err)
	}
	return nil
}

// isInvalidCredentials recognises the LDAP invalid-credentials result so the
// two bind steps can answer the same string the local path answers — an
// attacker probing both paths must not learn which one exists.
func isInvalidCredentials(err error) bool {
	var ldapErr *ldap.Error
	if errors.As(err, &ldapErr) {
		return ldapErr.ResultCode == ldap.LDAPResultInvalidCredentials
	}
	return false
}

// describeConnErr strips anything that could carry the URL or credentials from
// a dial/TLS failure: DialURL errors embed the URL, and the URL is what the
// plan says never to log verbatim when it can contain credentials.
func describeConnErr(err error) string {
	msg := err.Error()
	if i := strings.Index(msg, "://"); i > 0 {
		// Keep the scheme name ("ldaps"), drop everything from the address on.
		return msg[:i]
	}
	return msg
}
