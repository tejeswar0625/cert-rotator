package generator

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// helpers

func generateSelfSignedCert(t *testing.T, opts x509.Certificate) (certPEM, keyPEM []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &opts, &opts, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating cert: %v", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshalling key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return
}

func writeTempFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}
	return path
}

func sampleCertTemplate() x509.Certificate {
	return x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "kube-apiserver",
			Organization: []string{"kubernetes"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		DNSNames:              []string{"kubernetes", "kubernetes.default", "kubernetes.default.svc"},
		IPAddresses:           []net.IP{net.ParseIP("10.96.0.1"), net.ParseIP("192.168.1.10")},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
}

// tests

func TestGenerateKey(t *testing.T) {
	g := New()
	key, err := g.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
	if key.N.BitLen() != 2048 {
		t.Errorf("expected 2048 bit key, got %d", key.N.BitLen())
	}
}

func TestGenerateKey_Unique(t *testing.T) {
	g := New()
	key1, _ := g.GenerateKey()
	key2, _ := g.GenerateKey()

	// Two generated keys should never be identical
	if key1.N.Cmp(key2.N) == 0 {
		t.Error("expected unique keys, got identical moduli")
	}
}

func TestBuildTemplate_MirrorsSANs(t *testing.T) {
	tmpl := sampleCertTemplate()
	certPEM, _ := generateSelfSignedCert(t, tmpl)

	block, _ := pem.Decode(certPEM)
	existing, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing cert: %v", err)
	}

	g := New()
	newTemplate, err := g.BuildTemplate(existing)
	if err != nil {
		t.Fatalf("BuildTemplate failed: %v", err)
	}

	// DNS names must match exactly
	if len(newTemplate.DNSNames) != len(existing.DNSNames) {
		t.Errorf("DNS names count mismatch: got %d want %d",
			len(newTemplate.DNSNames), len(existing.DNSNames))
	}
	for i, dns := range existing.DNSNames {
		if newTemplate.DNSNames[i] != dns {
			t.Errorf("DNS name mismatch at index %d: got %s want %s",
				i, newTemplate.DNSNames[i], dns)
		}
	}

	// IP addresses must match exactly
	if len(newTemplate.IPAddresses) != len(existing.IPAddresses) {
		t.Errorf("IP count mismatch: got %d want %d",
			len(newTemplate.IPAddresses), len(existing.IPAddresses))
	}
	for i, ip := range existing.IPAddresses {
		if !newTemplate.IPAddresses[i].Equal(ip) {
			t.Errorf("IP mismatch at index %d: got %s want %s",
				i, newTemplate.IPAddresses[i], ip)
		}
	}
}

func TestBuildTemplate_MirrorsKeyUsage(t *testing.T) {
	tmpl := sampleCertTemplate()
	certPEM, _ := generateSelfSignedCert(t, tmpl)

	block, _ := pem.Decode(certPEM)
	existing, _ := x509.ParseCertificate(block.Bytes)

	g := New()
	newTemplate, err := g.BuildTemplate(existing)
	if err != nil {
		t.Fatalf("BuildTemplate failed: %v", err)
	}

	if newTemplate.KeyUsage != existing.KeyUsage {
		t.Errorf("KeyUsage mismatch: got %v want %v",
			newTemplate.KeyUsage, existing.KeyUsage)
	}
	if len(newTemplate.ExtKeyUsage) != len(existing.ExtKeyUsage) {
		t.Errorf("ExtKeyUsage count mismatch: got %d want %d",
			len(newTemplate.ExtKeyUsage), len(existing.ExtKeyUsage))
	}
}

func TestBuildTemplate_NewValidity(t *testing.T) {
	tmpl := sampleCertTemplate()
	certPEM, _ := generateSelfSignedCert(t, tmpl)

	block, _ := pem.Decode(certPEM)
	existing, _ := x509.ParseCertificate(block.Bytes)

	g := New()
	newTemplate, err := g.BuildTemplate(existing)
	if err != nil {
		t.Fatalf("BuildTemplate failed: %v", err)
	}

	// New cert should expire ~365 days from now
	expectedExpiry := time.Now().Add(certValidity)
	diff := newTemplate.NotAfter.Sub(expectedExpiry)
	if diff < -time.Minute || diff > time.Minute {
		t.Errorf("unexpected NotAfter: got %v, want ~%v", newTemplate.NotAfter, expectedExpiry)
	}

	// NotBefore should be slightly in the past (clock skew backdating)
	if newTemplate.NotBefore.After(time.Now()) {
		t.Error("NotBefore should be in the past for clock skew handling")
	}
}

func TestBuildTemplate_NewSerial(t *testing.T) {
	tmpl := sampleCertTemplate()
	certPEM, _ := generateSelfSignedCert(t, tmpl)

	block, _ := pem.Decode(certPEM)
	existing, _ := x509.ParseCertificate(block.Bytes)

	g := New()
	t1, _ := g.BuildTemplate(existing)
	t2, _ := g.BuildTemplate(existing)

	// Each template should have a unique serial
	if t1.SerialNumber.Cmp(t2.SerialNumber) == 0 {
		t.Error("expected unique serials for each template, got identical")
	}
}

func TestLoadExistingCert_Valid(t *testing.T) {
	dir := t.TempDir()
	tmpl := sampleCertTemplate()
	certPEM, _ := generateSelfSignedCert(t, tmpl)
	path := writeTempFile(t, dir, "apiserver.crt", certPEM)

	g := New()
	cert, err := g.LoadExistingCert(path)
	if err != nil {
		t.Fatalf("LoadExistingCert failed: %v", err)
	}
	if cert.Subject.CommonName != "kube-apiserver" {
		t.Errorf("unexpected CN: got %s", cert.Subject.CommonName)
	}
}

func TestLoadExistingCert_Missing(t *testing.T) {
	g := New()
	_, err := g.LoadExistingCert("/nonexistent/cert.crt")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadExistingCert_InvalidPEM(t *testing.T) {
	dir := t.TempDir()
	path := writeTempFile(t, dir, "bad.crt", []byte("not a pem"))

	g := New()
	_, err := g.LoadExistingCert(path)
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestEncodeKeyPEM(t *testing.T) {
	g := New()
	key, _ := g.GenerateKey()
	keyPEM := g.EncodeKeyPEM(key)

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		t.Fatal("expected valid PEM block")
	}
	if block.Type != "RSA PRIVATE KEY" {
		t.Errorf("expected RSA PRIVATE KEY, got %s", block.Type)
	}
}

func TestEncodeCertPEM(t *testing.T) {
	tmpl := sampleCertTemplate()
	certPEM, _ := generateSelfSignedCert(t, tmpl)

	block, _ := pem.Decode(certPEM)

	g := New()
	encoded := g.EncodeCertPEM(block.Bytes)

	reBlock, _ := pem.Decode(encoded)
	if reBlock == nil {
		t.Fatal("expected valid PEM block after re-encoding")
	}
	if reBlock.Type != "CERTIFICATE" {
		t.Errorf("expected CERTIFICATE, got %s", reBlock.Type)
	}
}
