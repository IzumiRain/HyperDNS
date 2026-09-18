package web

import (
	"crypto/tls"
	"log"
	"sync"

	"hyperdns/internal/service/acme"
)

// certHolder is the process-lifetime TLS certificate source with hot-swap.
//
// Before v2.2.0, LoadOrGenerateTLSConfig built one *tls.Config at startup and
// every listener held it for the daemon's whole life, so a renewed
// certificate was only ever served after a restart — and a renewal that
// landed while the operator was away meant a dash to the server the day the
// old one expired. The holder keeps a single GetCertificate closure over an
// atomically-replaced pair: listeners built once keep serving whatever the
// holder currently holds, and Swap promotes a new pair without a restart.
//
// Swap validates before promoting (the same fail-closed rule the panel
// listener applies at boot), so a corrupt or self-swap-in of the wrong pair
// can never displace a working certificate.
type certHolder struct {
	mu   sync.RWMutex
	cert *tls.Certificate
}

// newCertHolder wraps an initial pair. A nil cert is allowed: the holder then
// answers every handshake with no certificate, which is only useful for
// setups that never enable TLS — the same shape LoadOrGenerateTLSConfig's nil
// return already had.
func newCertHolder(cert *tls.Certificate) *certHolder {
	return &certHolder{cert: cert}
}

// GetCertificate is the tls.Config closure. It never fails: an absent
// certificate returns nil and the handshake itself errors, which is the
// pre-v2.2.0 behaviour of a config with no pair.
func (h *certHolder) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.cert, nil
}

// Swap promotes a new pair under the write lock. Callers validate first.
func (h *certHolder) Swap(cert *tls.Certificate) {
	h.mu.Lock()
	h.cert = cert
	h.mu.Unlock()
	log.Printf("[TLS] live certificate swapped")
}

// Load builds the pair from disk and swaps it in. It returns the load error
// without touching the current certificate when the pair does not parse.
func (h *certHolder) Load(certPath, keyPath string) error {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return err
	}
	h.Swap(&cert)
	return nil
}

// SetACMEManager attaches the embedded ACME client (test seam: nil in
// harnesses that never issue).
func (ws *WebServer) SetACMEManager(m *acme.Manager) {
	ws.acmeManager = m
}

// SetCertHolder attaches the hot-swap certificate source (test seam).
func (ws *WebServer) SetCertHolder(h *certHolder) {
	ws.certHolderMu.Lock()
	ws.certHolder = h
	ws.certHolderMu.Unlock()
}

// CertHolder is the exported name for the hot-swap certificate source; main
// builds the DoT/DoT holder before the DNS server exists.
type CertHolder = certHolder

// NewCertHolderLoading builds a holder primed with the pair from disk,
// failing if the pair cannot be loaded (the caller decides whether that is
// fatal). Used by main for the DoT/DoH listeners' dedicated certificate.
func NewCertHolderLoading(certPath, keyPath string) *certHolder {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil
	}
	return newCertHolder(&cert)
}

// SetDOTCertHolder attaches the DoH/DoT dedicated certificate source, and
// SetDNSRebinder the listener-rebuild hook. Main wires both after the DNS
// server exists.
//
// The rebind callback receives the source the listeners must carry from now
// on — the holder when a dedicated domain first lands or changes, nil when
// the domain is cleared and the transports must fall back to the panel
// certificate. It returns the rebind error: a rebuild that left a listener
// down must reach the operator as a failed save, not a success log. Passing
// the source through the callback (rather than having the web server mutate
// DNS state and then ask for a bare rebind) is what keeps "the record says
// no dedicated domain" and "the listeners serve no dedicated certificate"
// the same fact.
func (ws *WebServer) SetDOTCertHolder(h *certHolder, rebind func(src *certHolder) error) {
	ws.dotCertHolder = h
	ws.dnsRebind = rebind
}
