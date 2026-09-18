package service

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"hyperdns/internal/database"
)

func LoadOrGenerateTLSConfig(tlsCfg *database.TLSSettings) (*tls.Config, error) {
	if tlsCfg == nil {
		tlsCfg = &database.TLSSettings{}
	}

	// When a panel domain is configured, only a certificate a public CA
	// vouches for may be served. The self-signed fallback names the configured
	// domain in its SAN and passes every date and hostname check, so accepting
	// it here is what put the "Not secure" banner on a domain install: the
	// fallback was generated, written to the very paths the panel validator
	// then re-read, and served as if it were a real certificate. With a domain
	// there is no fallback — a missing trusted certificate is an error the
	// caller reports, and the ACME paths (daemon startup, dashboard button
	// startup, dashboard button) are how one arrives.
	if tlsCfg.Domain != "" {
		certCandidates := []string{
			fmt.Sprintf("/etc/letsencrypt/live/%s/fullchain.pem", tlsCfg.Domain),
			tlsCfg.CertPath,
			"/opt/hyperdns/certs/cert.pem",
			"certs/cert.pem",
		}
		keyCandidates := []string{
			fmt.Sprintf("/etc/letsencrypt/live/%s/privkey.pem", tlsCfg.Domain),
			tlsCfg.KeyPath,
			"/opt/hyperdns/certs/key.pem",
			"certs/key.pem",
		}
		for i := range certCandidates {
			cPath, kPath := certCandidates[i], keyCandidates[i]
			if cPath == "" || kPath == "" {
				continue
			}
			cert, err := tls.LoadX509KeyPair(cPath, kPath)
			if err != nil {
				continue
			}
			leaf, parseErr := x509.ParseCertificate(cert.Certificate[0])
			if parseErr != nil {
				continue
			}
			if bytes.Equal(leaf.RawIssuer, leaf.RawSubject) {
				log.Printf("[TLS] Skipping self-signed certificate at %s — a configured panel domain must be served a CA-signed certificate", cPath)
				continue
			}
			// The panel validator (ValidatePanelCertificate) checks dates and
			// hostname; this loop used to check neither, so the resolver's TLS
			// transports accepted material the panel would have refused: an
			// expired pair (a renewal that quietly failed, or a backup restored
			// over a newer one) put DoT and DoH live with a certificate every
			// client rejects, and a pair naming some other host was served to
			// subscribers who pinned the configured domain. One shared pair of
			// checks keeps both surfaces agreeing about what "valid" means.
			now := time.Now()
			if now.Before(leaf.NotBefore) {
				log.Printf("[TLS] Skipping certificate at %s — not valid before %s", cPath, leaf.NotBefore.UTC().Format(time.RFC3339))
				continue
			}
			if now.After(leaf.NotAfter) {
				log.Printf("[TLS] Skipping expired certificate at %s — expired %s", cPath, leaf.NotAfter.UTC().Format(time.RFC3339))
				continue
			}
			if err := leaf.VerifyHostname(tlsCfg.Domain); err != nil {
				log.Printf("[TLS] Skipping certificate at %s — it does not cover domain %q: %v", cPath, tlsCfg.Domain, err)
				continue
			}
			log.Printf("[TLS] Loaded valid TLS certificate from %s and %s", cPath, kPath)
			return &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			}, nil
		}
		return nil, fmt.Errorf("panel domain %q is configured but no CA-signed certificate covers it (a self-signed fallback is never served for a domain) — save the domain again in the dashboard so the built-in ACME client can request one, or point cert_path/key_path at a real certificate", tlsCfg.Domain)
	}

	certCandidates := []string{
		tlsCfg.CertPath,
		"/opt/hyperdns/certs/cert.pem",
		"certs/cert.pem",
	}
	keyCandidates := []string{
		tlsCfg.KeyPath,
		"/opt/hyperdns/certs/key.pem",
		"certs/key.pem",
	}

	for i := range certCandidates {
		cPath := certCandidates[i]
		kPath := keyCandidates[i]
		if cPath == "" || kPath == "" {
			continue
		}
		cert, err := tls.LoadX509KeyPair(cPath, kPath)
		if err == nil {
			log.Printf("[TLS] Loaded valid TLS certificate from %s and %s", cPath, kPath)
			return &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			}, nil
		}
	}

	// Generate fallback self-signed certificate
	certPath := "/opt/hyperdns/certs/cert.pem"
	keyPath := "/opt/hyperdns/certs/key.pem"
	if _, err := os.Stat("/opt/hyperdns"); err != nil {
		certPath = "certs/cert.pem"
		keyPath = "certs/key.pem"
	}

	log.Printf("[TLS] No valid custom certificate found. Generating self-signed fallback cert at %s...", certPath)
	if err := generateSelfSignedCert(certPath, keyPath, tlsCfg.Domain); err != nil {
		return nil, fmt.Errorf("failed to generate self-signed cert: %w", err)
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load newly generated self-signed cert: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func generateSelfSignedCert(certPath, keyPath, customDomain string) error {
	_ = os.MkdirAll(filepath.Dir(certPath), 0755)
	_ = os.MkdirAll(filepath.Dir(keyPath), 0755)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return err
	}

	dnsNames := []string{"localhost", "hyperdns.local"}
	if customDomain != "" {
		dnsNames = append(dnsNames, customDomain)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"HyperDNS Controller"},
			CommonName:   "HyperDNS Standalone",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(3650 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	certOut, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return err
	}

	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyOut.Close()

	b, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}); err != nil {
		return err
	}

	return nil
}
