package signer

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/tejeswar0625/cert-rotator/pkg/generator"
)

// generateTestCA creates a self-signed CA cert and key for testing
func generateTestCA(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test-ca",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("creating CA cert: %v", err)
	}

	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parsing CA cert: %v", err)
	}

	return caCert, caKey
}

// generateTestLeafCert creates a leaf cert signed by the given CA
func generateTestLeafCert(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey) *x509.Certificate {
	t.Helper()

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating leaf key: %v", err)
	}

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "kube-apiserver",
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		DNSNames:    []string{"kubernetes", "kubernetes.default"},
		IPAddresses: []net.IP{net.ParseIP("10.96.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("creating leaf cert: %v", err)
	}

	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parsing leaf cert: %v", err)
	}

	return leafCert
}

func TestSign_ValidCert(t *testing.T) {
	caCert, caKey := generateTestCA(t)

	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating new key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "kube-apiserver"},
		NotBefore:    time.Now().Add(-10 * time.Minute),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	s := New()
	certDER, err := s.Sign(template, caCert, caKey, &newKey.PublicKey)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if len(certDER) == 0 {
		t.Fatal("expected non-empty DER bytes")
	}

	// Parse the signed cert and verify it
	signed, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parsing signed cert: %v", err)
	}

	// Verify signed by CA
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	_, err = signed.Verify(x509.VerifyOptions{Roots: pool})
	if err != nil {
		t.Errorf("cert verification failed — not signed by CA: %v", err)
	}
}

func TestSign_SubjectPreserved(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	newKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "kube-apiserver",
			Organization: []string{"kubernetes"},
		},
		NotBefore: time.Now().Add(-10 * time.Minute),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
	}

	s := New()
	certDER, err := s.Sign(template, caCert, caKey, &newKey.PublicKey)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	signed, _ := x509.ParseCertificate(certDER)
	if signed.Subject.CommonName != "kube-apiserver" {
		t.Errorf("CN not preserved: got %s", signed.Subject.CommonName)
	}
	if len(signed.Subject.Organization) == 0 || signed.Subject.Organization[0] != "kubernetes" {
		t.Errorf("Organization not preserved: got %v", signed.Subject.Organization)
	}
}

func TestSignWithSelfKey_SANsPreserved(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	existing := generateTestLeafCert(t, caCert, caKey)

	g := generator.New()
	s := New()

	certPEM, keyPEM, err := s.SignWithSelfKey(existing, caCert, caKey, g)
	if err != nil {
		t.Fatalf("SignWithSelfKey failed: %v", err)
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		t.Fatal("expected non-empty PEM output")
	}

	// Parse and verify SANs are preserved
	block, _ := pem.Decode(certPEM)
	newCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing new cert: %v", err)
	}

	if len(newCert.DNSNames) != len(existing.DNSNames) {
		t.Errorf("DNS names count mismatch: got %d want %d",
			len(newCert.DNSNames), len(existing.DNSNames))
	}
	if len(newCert.IPAddresses) != len(existing.IPAddresses) {
		t.Errorf("IP count mismatch: got %d want %d",
			len(newCert.IPAddresses), len(existing.IPAddresses))
	}
}

func TestSignWithSelfKey_SignedByCA(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	existing := generateTestLeafCert(t, caCert, caKey)

	g := generator.New()
	s := New()

	certPEM, _, err := s.SignWithSelfKey(existing, caCert, caKey, g)
	if err != nil {
		t.Fatalf("SignWithSelfKey failed: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	newCert, _ := x509.ParseCertificate(block.Bytes)

	// Verify new cert is signed by the same CA
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	_, err = newCert.Verify(x509.VerifyOptions{Roots: pool})
	if err != nil {
		t.Errorf("new cert not verified by CA: %v", err)
	}
}

func TestSignWithSelfKey_NewKeyEachTime(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	existing := generateTestLeafCert(t, caCert, caKey)

	g := generator.New()
	s := New()

	_, key1PEM, _ := s.SignWithSelfKey(existing, caCert, caKey, g)
	_, key2PEM, _ := s.SignWithSelfKey(existing, caCert, caKey, g)

	// Keys should be different each time
	if string(key1PEM) == string(key2PEM) {
		t.Error("expected different keys on each call, got identical")
	}
}

func TestCAForCert(t *testing.T) {
	tests := []struct {
		certName    string
		expectedCA  string
		expectedKey string
	}{
		{"etcd-server", "/etc/kubernetes/pki/etcd/ca.crt", "/etc/kubernetes/pki/etcd/ca.key"},
		{"etcd-peer", "/etc/kubernetes/pki/etcd/ca.crt", "/etc/kubernetes/pki/etcd/ca.key"},
		{"etcd-healthcheck-client", "/etc/kubernetes/pki/etcd/ca.crt", "/etc/kubernetes/pki/etcd/ca.key"},
		{"apiserver-etcd-client", "/etc/kubernetes/pki/etcd/ca.crt", "/etc/kubernetes/pki/etcd/ca.key"},
		{"front-proxy-client", "/etc/kubernetes/pki/front-proxy-ca.crt", "/etc/kubernetes/pki/front-proxy-ca.key"},
		{"apiserver", "/etc/kubernetes/pki/ca.crt", "/etc/kubernetes/pki/ca.key"},
		{"apiserver-kubelet-client", "/etc/kubernetes/pki/ca.crt", "/etc/kubernetes/pki/ca.key"},
		{"admin.conf", "/etc/kubernetes/pki/ca.crt", "/etc/kubernetes/pki/ca.key"},
	}

	for _, tt := range tests {
		t.Run(tt.certName, func(t *testing.T) {
			caCert, caKey := CAForCert(tt.certName)
			if caCert != tt.expectedCA {
				t.Errorf("CA cert path: got %s want %s", caCert, tt.expectedCA)
			}
			if caKey != tt.expectedKey {
				t.Errorf("CA key path: got %s want %s", caKey, tt.expectedKey)
			}
		})
	}
}
