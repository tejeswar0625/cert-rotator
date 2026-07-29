package writer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteCert_CreatesFile(t *testing.T) {
	dir := t.TempDir()
	w := New(dir, false)

	certPEM := []byte("-----BEGIN CERTIFICATE-----\nfakecert\n-----END CERTIFICATE-----\n")
	if err := w.WriteCert("apiserver.crt", certPEM); err != nil {
		t.Fatalf("WriteCert failed: %v", err)
	}

	path := filepath.Join(dir, "apiserver.crt")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("cert file not created: %v", err)
	}
}

func TestWriteCert_CorrectPermissions(t *testing.T) {
	dir := t.TempDir()
	w := New(dir, false)

	certPEM := []byte("fake cert data")
	if err := w.WriteCert("apiserver.crt", certPEM); err != nil {
		t.Fatalf("WriteCert failed: %v", err)
	}

	info, err := os.Stat(filepath.Join(dir, "apiserver.crt"))
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if info.Mode() != 0644 {
		t.Errorf("expected 0644 permissions, got %v", info.Mode())
	}
}

func TestWriteKey_CorrectPermissions(t *testing.T) {
	dir := t.TempDir()
	w := New(dir, false)

	keyPEM := []byte("fake key data")
	if err := w.WriteKey("apiserver.key", keyPEM); err != nil {
		t.Fatalf("WriteKey failed: %v", err)
	}

	info, err := os.Stat(filepath.Join(dir, "apiserver.key"))
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if info.Mode() != 0600 {
		t.Errorf("expected 0600 permissions for key, got %v", info.Mode())
	}
}

func TestWriteCert_CreatesSubdirs(t *testing.T) {
	dir := t.TempDir()
	w := New(dir, false)

	certPEM := []byte("fake etcd cert")
	if err := w.WriteCert("etcd/server.crt", certPEM); err != nil {
		t.Fatalf("WriteCert failed for nested path: %v", err)
	}

	path := filepath.Join(dir, "etcd", "server.crt")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("nested cert file not created: %v", err)
	}
}

func TestWriteCertKeyPair(t *testing.T) {
	dir := t.TempDir()
	w := New(dir, false)

	certPEM := []byte("fake cert")
	keyPEM := []byte("fake key")

	if err := w.WriteCertKeyPair("apiserver.crt", "apiserver.key", certPEM, keyPEM); err != nil {
		t.Fatalf("WriteCertKeyPair failed: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "apiserver.crt")); err != nil {
		t.Error("cert file missing")
	}
	if _, err := os.Stat(filepath.Join(dir, "apiserver.key")); err != nil {
		t.Error("key file missing")
	}
}

func TestDryRun_NoFilesCreated(t *testing.T) {
	dir := t.TempDir()
	w := New(dir, true) // dry run

	if err := w.WriteCert("apiserver.crt", []byte("fake")); err != nil {
		t.Fatalf("dry run WriteCert failed: %v", err)
	}

	path := filepath.Join(dir, "apiserver.crt")
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("dry run should not create files")
	}
}

func TestWriteAllCerts(t *testing.T) {
	dir := t.TempDir()
	// create etcd subdir
	os.MkdirAll(filepath.Join(dir, "etcd"), 0755)
	w := New(dir, false)

	pairs := map[string][2][]byte{
		"apiserver":   {[]byte("cert"), []byte("key")},
		"etcd-server": {[]byte("cert"), []byte("key")},
	}

	if err := w.WriteAllCerts(pairs); err != nil {
		t.Fatalf("WriteAllCerts failed: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "apiserver.crt")); err != nil {
		t.Error("apiserver.crt missing")
	}
	if _, err := os.Stat(filepath.Join(dir, "etcd", "server.crt")); err != nil {
		t.Error("etcd/server.crt missing")
	}
}

func TestVerify_AllFilesPresent(t *testing.T) {
	dir := t.TempDir()
	w := New(dir, false)

	// Write all expected cert files
	for _, paths := range CertPaths {
		for _, relPath := range paths {
			full := filepath.Join(dir, relPath)
			os.MkdirAll(filepath.Dir(full), 0755)
			os.WriteFile(full, []byte("fake"), 0644)
		}
	}

	if err := w.Verify(); err != nil {
		t.Errorf("Verify failed with all files present: %v", err)
	}
}

func TestVerify_MissingFile(t *testing.T) {
	dir := t.TempDir()
	w := New(dir, false)
	// Don't create any files

	if err := w.Verify(); err == nil {
		t.Error("expected Verify to fail with missing files")
	}
}

func TestVerify_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	w := New(dir, false)

	// Write all files but leave one empty
	for name, paths := range CertPaths {
		for i, relPath := range paths {
			full := filepath.Join(dir, relPath)
			os.MkdirAll(filepath.Dir(full), 0755)
			if name == "apiserver" && i == 0 {
				os.WriteFile(full, []byte{}, 0644) // empty
			} else {
				os.WriteFile(full, []byte("fake"), 0644)
			}
		}
	}

	if err := w.Verify(); err == nil {
		t.Error("expected Verify to fail with empty file")
	}
}
