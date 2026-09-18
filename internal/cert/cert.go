package cert

import (
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

	"hyperdns/internal/config"
)

func LoadOrGenerateTLSConfig(cfg *config.Config) (*tls.Config, error) {
	tlsCfg := &cfg.TLS

	// Candidate paths to look for valid certificates
	certCandidates := []string{
		tlsCfg.CertFile,
		"/opt/hyperdns/certs/cert.pem",
		"certs/cert.pem",
	}
	keyCandidates := []string{
		tlsCfg.KeyFile,
		"/opt/hyperdns/certs/key.pem",
		"certs/key.pem",
	}

	if tlsCfg.Domain != "" {
		certCandidates = append([]string{
			fmt.Sprintf("/etc/letsencrypt/live/%s/fullchain.pem", tlsCfg.Domain),
		}, certCandidates...)
		keyCandidates = append([]string{
			fmt.Sprintf("/etc/letsencrypt/live/%s/privkey.pem", tlsCfg.Domain),
		}, keyCandidates...)
	}

	// 1. Try loading certificates from candidate paths
	for i := range certCandidates {
		cPath := certCandidates[i]
		kPath := keyCandidates[i]
		if cPath == "" || kPath == "" {
			continue
		}
		if _, err1 := os.Stat(cPath); err1 == nil {
			if _, err2 := os.Stat(kPath); err2 == nil {
				cer, err := tls.LoadX509KeyPair(cPath, kPath)
				if err == nil {
					log.Printf("[TLS] Loaded valid TLS certificate from %s and %s", cPath, kPath)
					return &tls.Config{
						Certificates: []tls.Certificate{cer},
						MinVersion:   tls.VersionTLS12,
					}, nil
				}
			}
		}
	}

	// 2. Generate a high-grade in-memory / self-signed certificate if no file exists
	certPEM, keyPEM, err := generateSelfSignedCert(cfg.Server.PublicIP, tlsCfg.Domain)
	if err != nil {
		return nil, err
	}

	targetCert := tlsCfg.CertFile
	if targetCert == "" {
		targetCert = "/opt/hyperdns/certs/cert.pem"
	}
	targetKey := tlsCfg.KeyFile
	if targetKey == "" {
		targetKey = "/opt/hyperdns/certs/key.pem"
	}

	// Save to disk if not already existing
	if _, err := os.Stat(targetCert); os.IsNotExist(err) {
		_ = os.MkdirAll(filepath.Dir(targetCert), 0755)
		_ = os.WriteFile(targetCert, certPEM, 0644)
		_ = os.WriteFile(targetKey, keyPEM, 0600)
	}

	cer, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	log.Println("[TLS] Initialized self-signed TLS certificate for DoT and DoH.")
	return &tls.Config{
		Certificates: []tls.Certificate{cer},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func generateSelfSignedCert(publicIP, domain string) ([]byte, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"HyperDNS Security Gateway"},
			CommonName:   "hyperdns.local",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if domain != "" {
		template.DNSNames = append(template.DNSNames, domain)
		template.Subject.CommonName = domain
	}
	template.DNSNames = append(template.DNSNames, "localhost", "hyperdns.local")

	if publicIP != "" {
		if ip := net.ParseIP(publicIP); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		}
	}
	template.IPAddresses = append(template.IPAddresses, net.ParseIP("127.0.0.1"), net.ParseIP("::1"))

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	return certPEM, keyPEM, nil
}
