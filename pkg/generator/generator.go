package generator

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/tejeswar0625/cert-rotator/pkg/logger"
)

const (
	keySize      = 2048
	certValidity = 365 * 24 * time.Hour
)

type KeyPair struct {
	CertPEM []byte
	KeyPEM  []byte
	Cert    *x509.Certificate
}

type Generator struct{}

func New() *Generator {
	return &Generator{}
}

func (g *Generator) GenerateKey() (*rsa.PrivateKey, error) {
	logger.Debug("generator", "",
		"Generating new RSA 2048 private key. This key will never leave the node — it stays in /etc/kubernetes/pki/.",
		slog.Int("key_size_bits", keySize),
	)

	key, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, fmt.Errorf("generating RSA key: %w", err)
	}

	logger.Debug("generator", "", "RSA private key generated successfully.")
	return key, nil
}

func (g *Generator) BuildTemplate(existing *x509.Certificate) (*x509.Certificate, error) {
	logger.Debug("generator", "",
		"Building x509 certificate template from existing cert. "+
			"SANs, IP addresses, key usages, and extended key usages are mirrored exactly. "+
			"A mismatch in any of these fields would silently break connectivity to control plane components.",
		slog.String("cert_subject", existing.Subject.CommonName),
		slog.String("dns_names", fmt.Sprintf("%v", existing.DNSNames)),
		slog.String("ip_addresses", fmt.Sprintf("%v", existing.IPAddresses)),
		slog.String("new_expiry", time.Now().Add(certValidity).Format(time.RFC3339)),
	)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generating serial number: %w", err)
	}

	now := time.Now()

	ips := make([]net.IP, len(existing.IPAddresses))
	copy(ips, existing.IPAddresses)

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         existing.Subject.CommonName,
			Organization:       existing.Subject.Organization,
			OrganizationalUnit: existing.Subject.OrganizationalUnit,
			Country:            existing.Subject.Country,
		},
		NotBefore:             now.Add(-10 * time.Minute),
		NotAfter:              now.Add(certValidity),
		DNSNames:              existing.DNSNames,
		IPAddresses:           ips,
		URIs:                  existing.URIs,
		KeyUsage:              existing.KeyUsage,
		ExtKeyUsage:           existing.ExtKeyUsage,
		IsCA:                  existing.IsCA,
		BasicConstraintsValid: existing.BasicConstraintsValid,
		ExtraExtensions:       filterExtensions(existing),
	}

	logger.Debug("generator", "",
		"Certificate template built successfully.",
		slog.String("cert_subject", template.Subject.CommonName),
		slog.Int("dns_names_count", len(template.DNSNames)),
		slog.Int("ip_addresses_count", len(template.IPAddresses)),
	)

	return template, nil
}

func (g *Generator) LoadExistingCert(certPath string) (*x509.Certificate, error) {
	logger.Debug("generator", "",
		"Loading existing certificate from disk to extract SANs and key usages.",
		slog.String("path", certPath),
	)

	data, err := readPEMFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("reading cert %s: %w", certPath, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", certPath)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing cert %s: %w", certPath, err)
	}

	logger.Debug("generator", "",
		"Existing certificate loaded successfully.",
		slog.String("path", certPath),
		slog.String("subject", cert.Subject.CommonName),
		slog.String("expiry", cert.NotAfter.Format(time.RFC3339)),
		slog.String("dns_names", fmt.Sprintf("%v", cert.DNSNames)),
		slog.String("ip_addresses", fmt.Sprintf("%v", cert.IPAddresses)),
	)

	return cert, nil
}

func (g *Generator) EncodeKeyPEM(key *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

func (g *Generator) EncodeCertPEM(certDER []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
}

func (g *Generator) LoadCAKey(keyPath string) (*rsa.PrivateKey, error) {
	logger.Debug("generator", "",
		"Loading CA private key. This key is used to sign the new certificate. It never leaves the node.",
		slog.String("path", keyPath),
	)

	data, err := readPEMFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("reading CA key %s: %w", keyPath, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in CA key %s", keyPath)
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		pkcs8Key, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("parsing CA key %s (tried PKCS1 and PKCS8): %w", keyPath, err)
		}
		rsaKey, ok := pkcs8Key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("CA key %s is not RSA", keyPath)
		}
		logger.Debug("generator", "", "CA key loaded successfully (PKCS8 format).",
			slog.String("path", keyPath),
		)
		return rsaKey, nil
	}

	logger.Debug("generator", "", "CA key loaded successfully (PKCS1 format).",
		slog.String("path", keyPath),
	)
	return key, nil
}

func (g *Generator) LoadCACert(certPath string) (*x509.Certificate, error) {
	logger.Debug("generator", "",
		"Loading CA certificate.",
		slog.String("path", certPath),
	)
	return g.LoadExistingCert(certPath)
}

func filterExtensions(cert *x509.Certificate) []pkix.Extension {
	handled := map[string]bool{
		"2.5.29.17": true,
		"2.5.29.15": true,
		"2.5.29.37": true,
		"2.5.29.19": true,
		"2.5.29.14": true,
		"2.5.29.35": true,
	}

	var extras []pkix.Extension
	for _, ext := range cert.Extensions {
		if !handled[ext.Id.String()] {
			extras = append(extras, ext)
		}
	}
	return extras
}

func readPEMFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file %s: %w", path, err)
	}
	return data, nil
}
