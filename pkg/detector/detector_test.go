package detector

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

// generateTestCert creates a self-signed cert for testing
func generateTestCert(t *testing.T, opts testCertOpts) (certPEM []byte, keyPEM []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating test key: %v", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generating serial: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: opts.commonName,
		},
		NotBefore:   opts.notBefore,
		NotAfter:    opts.notAfter,
		DNSNames:    opts.dnsNames,
		IPAddresses: opts.ipAddresses,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating test cert: %v", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshalling test key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	return certPEM, keyPEM
}

type testCertOpts struct {
	commonName  string
	notBefore   time.Time
	notAfter    time.Time
	dnsNames    []string
	ipAddresses []net.IP
}

// writeCertFile writes a PEM cert to a temp dir and returns the path
func writeCertFile(t *testing.T, dir, filename string, certPEM []byte) string {
	t.Helper()
	path := filepath.Join(dir, filename)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("creating dir: %v", err)
	}
	if err := os.WriteFile(path, certPEM, 0644); err != nil {
		t.Fatalf("writing cert file: %v", err)
	}
	return path
}

func TestClassify_OK(t *testing.T) {
	d := New("/tmp/pki", "/tmp/kube", 30)
	status := d.classify(60)
	if status != StatusOK {
		t.Errorf("expected OK for 60 days residual, got %s", status)
	}
}

func TestClassify_Approaching(t *testing.T) {
	d := New("/tmp/pki", "/tmp/kube", 30)
	status := d.classify(15)
	if status != StatusApproaching {
		t.Errorf("expected APPROACHING for 15 days residual, got %s", status)
	}
}

func TestClassify_AtThreshold(t *testing.T) {
	d := New("/tmp/pki", "/tmp/kube", 30)
	status := d.classify(30)
	if status != StatusApproaching {
		t.Errorf("expected APPROACHING at exactly threshold (30 days), got %s", status)
	}
}

func TestClassify_Expired(t *testing.T) {
	d := New("/tmp/pki", "/tmp/kube", 30)
	status := d.classify(0)
	if status != StatusExpired {
		t.Errorf("expected EXPIRED for 0 days residual, got %s", status)
	}
}

func TestClassify_AlreadyExpired(t *testing.T) {
	d := New("/tmp/pki", "/tmp/kube", 30)
	status := d.classify(-5)
	if status != StatusExpired {
		t.Errorf("expected EXPIRED for negative residual, got %s", status)
	}
}

func TestParseCert_ValidCert(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()

	certPEM, _ := generateTestCert(t, testCertOpts{
		commonName: "kube-apiserver",
		notBefore:  now.Add(-24 * time.Hour),
		notAfter:   now.Add(365 * 24 * time.Hour),
		dnsNames:   []string{"kubernetes", "kubernetes.default"},
		ipAddresses: []net.IP{
			net.ParseIP("10.96.0.1"),
			net.ParseIP("192.168.1.100"),
		},
	})

	writeCertFile(t, dir, "apiserver.crt", certPEM)

	d := New(dir, dir, 30)
	info, err := d.parseCert("apiserver", filepath.Join(dir, "apiserver.crt"))
	if err != nil {
		t.Fatalf("parseCert failed: %v", err)
	}

	if info.Name != "apiserver" {
		t.Errorf("expected name apiserver, got %s", info.Name)
	}
	if info.Subject != "kube-apiserver" {
		t.Errorf("expected subject kube-apiserver, got %s", info.Subject)
	}
	if len(info.DNSNames) != 2 {
		t.Errorf("expected 2 DNS names, got %d", len(info.DNSNames))
	}
	if len(info.IPAddresses) != 2 {
		t.Errorf("expected 2 IP addresses, got %d", len(info.IPAddresses))
	}
	if info.ResidualDays < 364 {
		t.Errorf("expected ~365 residual days, got %d", info.ResidualDays)
	}
}

func TestParseCert_ExpiredCert(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()

	certPEM, _ := generateTestCert(t, testCertOpts{
		commonName: "kube-apiserver",
		notBefore:  now.Add(-400 * 24 * time.Hour),
		notAfter:   now.Add(-5 * 24 * time.Hour), // expired 5 days ago
	})

	writeCertFile(t, dir, "apiserver.crt", certPEM)

	d := New(dir, dir, 30)
	info, err := d.parseCert("apiserver", filepath.Join(dir, "apiserver.crt"))
	if err != nil {
		t.Fatalf("parseCert failed: %v", err)
	}

	if info.ResidualDays > 0 {
		t.Errorf("expected negative residual for expired cert, got %d", info.ResidualDays)
	}

	status := d.classify(info.ResidualDays)
	if status != StatusExpired {
		t.Errorf("expected EXPIRED status, got %s", status)
	}
}

func TestParseCert_MissingFile(t *testing.T) {
	d := New("/tmp/pki", "/tmp/kube", 30)
	_, err := d.parseCert("apiserver", "/nonexistent/path/apiserver.crt")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestParseCert_InvalidPEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.crt")
	os.WriteFile(path, []byte("this is not a valid PEM file"), 0644)

	d := New(dir, dir, 30)
	_, err := d.parseCert("bad", path)
	if err == nil {
		t.Error("expected error for invalid PEM, got nil")
	}
}

func TestDetectionResult_NeedsRenewal(t *testing.T) {
	tests := []struct {
		name     string
		certs    []CertInfo
		expected bool
	}{
		{
			name: "all OK",
			certs: []CertInfo{
				{Status: StatusOK},
				{Status: StatusOK},
			},
			expected: false,
		},
		{
			name: "one approaching",
			certs: []CertInfo{
				{Status: StatusOK},
				{Status: StatusApproaching},
			},
			expected: true,
		},
		{
			name: "one expired",
			certs: []CertInfo{
				{Status: StatusOK},
				{Status: StatusExpired},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &DetectionResult{Certs: tt.certs}
			if result.NeedsRenewal() != tt.expected {
				t.Errorf("NeedsRenewal() = %v, want %v", result.NeedsRenewal(), tt.expected)
			}
		})
	}
}

func TestDetectionResult_IsUrgent(t *testing.T) {
	tests := []struct {
		name     string
		certs    []CertInfo
		expected bool
	}{
		{
			name:     "no expired certs",
			certs:    []CertInfo{{Status: StatusOK}, {Status: StatusApproaching}},
			expected: false,
		},
		{
			name:     "has expired cert",
			certs:    []CertInfo{{Status: StatusOK}, {Status: StatusExpired}},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &DetectionResult{Certs: tt.certs}
			if result.IsUrgent() != tt.expected {
				t.Errorf("IsUrgent() = %v, want %v", result.IsUrgent(), tt.expected)
			}
		})
	}
}
