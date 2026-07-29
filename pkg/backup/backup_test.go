package backup

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// setupFakePKI creates a fake PKI directory structure with dummy cert files
func setupFakePKI(t *testing.T) (pkiDir, kubeconfigDir string) {
	t.Helper()
	base := t.TempDir()
	pkiDir = filepath.Join(base, "pki")
	kubeconfigDir = filepath.Join(base, "kubernetes")

	// Create all expected PKI files
	files := []string{
		"ca.crt", "ca.key",
		"apiserver.crt", "apiserver.key",
		"apiserver-etcd-client.crt", "apiserver-etcd-client.key",
		"apiserver-kubelet-client.crt", "apiserver-kubelet-client.key",
		"front-proxy-ca.crt", "front-proxy-ca.key",
		"front-proxy-client.crt", "front-proxy-client.key",
		"etcd/ca.crt", "etcd/ca.key",
		"etcd/server.crt", "etcd/server.key",
		"etcd/peer.crt", "etcd/peer.key",
		"etcd/healthcheck-client.crt", "etcd/healthcheck-client.key",
	}
	for _, f := range files {
		full := filepath.Join(pkiDir, f)
		os.MkdirAll(filepath.Dir(full), 0755)
		os.WriteFile(full, []byte("fake-cert-data-"+f), 0644)
	}

	// Create kubeconfig files
	kubeconfigs := []string{
		"admin.conf", "controller-manager.conf",
		"scheduler.conf", "super-admin.conf",
	}
	os.MkdirAll(kubeconfigDir, 0755)
	for _, f := range kubeconfigs {
		os.WriteFile(filepath.Join(kubeconfigDir, f), []byte("fake-kubeconfig-"+f), 0644)
	}

	return pkiDir, kubeconfigDir
}

func TestCreate_BackupDirCreated(t *testing.T) {
	pkiDir, kubeconfigDir := setupFakePKI(t)
	backupDir := t.TempDir()

	m := New(backupDir, pkiDir, kubeconfigDir)
	b, err := m.Create("node1")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if b.BackupPath == "" {
		t.Error("expected non-empty backup path")
	}
	if b.Node != "node1" {
		t.Errorf("expected node node1, got %s", b.Node)
	}
	if b.CreatedAt.IsZero() {
		t.Error("expected non-zero CreatedAt")
	}

	// Verify backup dir exists
	if _, err := os.Stat(b.BackupPath); err != nil {
		t.Errorf("backup path does not exist: %v", err)
	}
}

func TestCreate_PKIFilesCopied(t *testing.T) {
	pkiDir, kubeconfigDir := setupFakePKI(t)
	backupDir := t.TempDir()

	m := New(backupDir, pkiDir, kubeconfigDir)
	b, err := m.Create("node1")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Check a selection of PKI files were backed up
	toCheck := []string{
		"ca.crt", "ca.key",
		"apiserver.crt", "apiserver.key",
		"etcd/server.crt", "etcd/server.key",
	}
	for _, f := range toCheck {
		backupFile := filepath.Join(b.BackupPath, "pki", f)
		if _, err := os.Stat(backupFile); err != nil {
			t.Errorf("expected backed up file %s, not found: %v", f, err)
		}
	}
}

func TestCreate_KubeconfigFilesCopied(t *testing.T) {
	pkiDir, kubeconfigDir := setupFakePKI(t)
	backupDir := t.TempDir()

	m := New(backupDir, pkiDir, kubeconfigDir)
	b, err := m.Create("node1")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	kubeconfigs := []string{
		"admin.conf", "controller-manager.conf",
		"scheduler.conf",
	}
	for _, f := range kubeconfigs {
		backupFile := filepath.Join(b.BackupPath, "kubeconfigs", f)
		if _, err := os.Stat(backupFile); err != nil {
			t.Errorf("expected backed up kubeconfig %s, not found: %v", f, err)
		}
	}
}

func TestCreate_ContentPreserved(t *testing.T) {
	pkiDir, kubeconfigDir := setupFakePKI(t)
	backupDir := t.TempDir()

	m := New(backupDir, pkiDir, kubeconfigDir)
	b, err := m.Create("node1")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Verify content matches original
	original, _ := os.ReadFile(filepath.Join(pkiDir, "apiserver.crt"))
	backed, _ := os.ReadFile(filepath.Join(b.BackupPath, "pki", "apiserver.crt"))

	if string(original) != string(backed) {
		t.Errorf("content mismatch: original=%q backed=%q", original, backed)
	}
}

func TestCreate_MissingFileSkipped(t *testing.T) {
	pkiDir, kubeconfigDir := setupFakePKI(t)
	backupDir := t.TempDir()

	// Remove super-admin.conf — older clusters may not have it
	os.Remove(filepath.Join(kubeconfigDir, "super-admin.conf"))

	m := New(backupDir, pkiDir, kubeconfigDir)
	// Should not fail even if super-admin.conf is missing
	_, err := m.Create("node1")
	if err != nil {
		t.Fatalf("Create should not fail for missing optional files: %v", err)
	}
}

func TestCreate_MultipleNodes_Isolated(t *testing.T) {
	pkiDir, kubeconfigDir := setupFakePKI(t)
	backupDir := t.TempDir()

	m := New(backupDir, pkiDir, kubeconfigDir)
	b1, err := m.Create("node1")
	if err != nil {
		t.Fatalf("Create node1 failed: %v", err)
	}
	b2, err := m.Create("node2")
	if err != nil {
		t.Fatalf("Create node2 failed: %v", err)
	}

	// Backup paths must be different
	if b1.BackupPath == b2.BackupPath {
		t.Error("expected different backup paths for different nodes")
	}

	// Each should be under their own node directory
	if filepath.Dir(b1.BackupPath) == filepath.Dir(b2.BackupPath) {
		t.Error("expected node-isolated backup dirs")
	}
}

func TestRestore_RestoresFiles(t *testing.T) {
	pkiDir, kubeconfigDir := setupFakePKI(t)
	backupDir := t.TempDir()

	m := New(backupDir, pkiDir, kubeconfigDir)

	// Create backup
	b, err := m.Create("node1")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Simulate renewal by overwriting cert files
	os.WriteFile(filepath.Join(pkiDir, "apiserver.crt"), []byte("new-cert-data"), 0644)
	os.WriteFile(filepath.Join(kubeconfigDir, "admin.conf"), []byte("new-kubeconfig-data"), 0644)

	// Restore from backup
	if err := m.Restore(b.BackupPath); err != nil {
		t.Fatalf("Restore failed: %v", err)
	}

	// Verify original content is back
	restored, _ := os.ReadFile(filepath.Join(pkiDir, "apiserver.crt"))
	if string(restored) != "fake-cert-data-apiserver.crt" {
		t.Errorf("restore did not recover original content: got %q", restored)
	}

	restoredKC, _ := os.ReadFile(filepath.Join(kubeconfigDir, "admin.conf"))
	if string(restoredKC) != "fake-kubeconfig-admin.conf" {
		t.Errorf("restore did not recover kubeconfig: got %q", restoredKC)
	}
}

func TestCleanup_RemovesOldBackups(t *testing.T) {
	pkiDir, kubeconfigDir := setupFakePKI(t)
	backupDir := t.TempDir()

	m := New(backupDir, pkiDir, kubeconfigDir)

	// Create a backup
	b, err := m.Create("node1")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Backdate the backup directory modification time
	oldTime := time.Now().AddDate(0, 0, -10)
	os.Chtimes(b.BackupPath, oldTime, oldTime)

	// Cleanup with 5 day retention
	if err := m.Cleanup("node1", 5); err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}

	// Old backup should be gone
	if _, err := os.Stat(b.BackupPath); !os.IsNotExist(err) {
		t.Error("expected old backup to be removed")
	}
}

func TestCleanup_KeepsRecentBackups(t *testing.T) {
	pkiDir, kubeconfigDir := setupFakePKI(t)
	backupDir := t.TempDir()

	m := New(backupDir, pkiDir, kubeconfigDir)

	b, err := m.Create("node1")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Cleanup with 30 day retention — recent backup should survive
	if err := m.Cleanup("node1", 30); err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}

	if _, err := os.Stat(b.BackupPath); err != nil {
		t.Error("expected recent backup to be kept")
	}
}
