package signer

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"log/slog"

	"github.com/tejeswar0625/cert-rotator/pkg/logger"
)

type Signer struct{}

func New() *Signer {
	return &Signer{}
}

func (s *Signer) Sign(
	template *x509.Certificate,
	caCert *x509.Certificate,
	caKey *rsa.PrivateKey,
	pubKey *rsa.PublicKey,
) ([]byte, error) {
	logger.Debug("signer", "",
		"Signing certificate with CA key.",
		slog.String("cert_subject", template.Subject.CommonName),
		slog.String("signed_by_ca", caCert.Subject.CommonName),
		slog.String("expiry", template.NotAfter.String()),
	)

	certDER, err := x509.CreateCertificate(
		rand.Reader,
		template,
		caCert,
		pubKey,
		caKey,
	)
	if err != nil {
		return nil, fmt.Errorf("signing certificate %s: %w", template.Subject.CommonName, err)
	}

	logger.Info("signer", "",
		"Certificate signed successfully.",
		slog.String("cert_subject", template.Subject.CommonName),
		slog.String("signed_by_ca", caCert.Subject.CommonName),
	)

	return certDER, nil
}

func (s *Signer) SignWithSelfKey(
	existing *x509.Certificate,
	caCert *x509.Certificate,
	caKey *rsa.PrivateKey,
	gen interface {
		GenerateKey() (*rsa.PrivateKey, error)
		BuildTemplate(existing *x509.Certificate) (*x509.Certificate, error)
		EncodeKeyPEM(key *rsa.PrivateKey) []byte
		EncodeCertPEM(certDER []byte) []byte
	},
) (certPEM []byte, keyPEM []byte, err error) {
	logger.Info("signer", "",
		"Starting cert renewal for existing certificate. Will generate a new key, mirror existing SANs and key usages exactly, then sign with the correct CA.",
		slog.String("cert_subject", existing.Subject.CommonName),
		slog.String("dns_names", fmt.Sprintf("%v", existing.DNSNames)),
		slog.String("ca", caCert.Subject.CommonName),
	)

	// Step 1: generate new private key
	logger.Debug("signer", "", "Generating new RSA 2048 private key.")
	newKey, err := gen.GenerateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("generating key: %w", err)
	}

	// Step 2: build template mirroring existing cert
	logger.Debug("signer", "",
		"Building certificate template. Mirroring SANs, IP addresses, key usages, and extended key usages from existing cert exactly. A mismatch here would break connectivity.",
		slog.String("cert", existing.Subject.CommonName),
		slog.String("dns_names", fmt.Sprintf("%v", existing.DNSNames)),
		slog.Int("ip_count", len(existing.IPAddresses)),
	)
	template, err := gen.BuildTemplate(existing)
	if err != nil {
		return nil, nil, fmt.Errorf("building template: %w", err)
	}

	// Step 3: sign with CA
	certDER, err := s.Sign(template, caCert, caKey, &newKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	// Step 4: encode to PEM
	certPEM = gen.EncodeCertPEM(certDER)
	keyPEM = gen.EncodeKeyPEM(newKey)

	logger.Info("signer", "",
		"Certificate renewal complete. New cert and key generated and ready to be written to disk.",
		slog.String("cert_subject", existing.Subject.CommonName),
		slog.String("new_expiry", template.NotAfter.String()),
	)

	return certPEM, keyPEM, nil
}

func CAForCert(certName string) (caCertPath string, caKeyPath string) {
	switch certName {
	case "etcd-server", "etcd-peer", "etcd-healthcheck-client", "apiserver-etcd-client":
		logger.Debug("signer", "",
			"Using etcd CA for this cert. etcd certs must be signed by the etcd CA, not the main cluster CA.",
			slog.String("cert", certName),
			slog.String("ca", "etcd-ca"),
		)
		return "/etc/kubernetes/pki/etcd/ca.crt", "/etc/kubernetes/pki/etcd/ca.key"
	case "front-proxy-client":
		logger.Debug("signer", "",
			"Using front-proxy CA for this cert.",
			slog.String("cert", certName),
			slog.String("ca", "front-proxy-ca"),
		)
		return "/etc/kubernetes/pki/front-proxy-ca.crt", "/etc/kubernetes/pki/front-proxy-ca.key"
	default:
		logger.Debug("signer", "",
			"Using main cluster CA for this cert.",
			slog.String("cert", certName),
			slog.String("ca", "ca"),
		)
		return "/etc/kubernetes/pki/ca.crt", "/etc/kubernetes/pki/ca.key"
	}
}
