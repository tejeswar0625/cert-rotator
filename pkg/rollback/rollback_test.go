package rollback

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tejeswar0625/cert-rotator/pkg/backup"
	"github.com/tejeswar0625/cert-rotator/pkg/podrestart"
	"github.com/tejeswar0625/cert-rotator/state"
)

func setupFakePKI(t *testing.T) (pkiDir, kubeconfigDir string) {
	t.Helper()
	base := t.TempDir()
	pkiDir = filepath.Join(base, "pki")
	kubeconfigDir = filepath.Join(base, "kubernetes")

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
		os.WriteFile(full, []byte("original-"+f), 0644)
	}

	os.MkdirAll(kubeconfigDir, 0755)
	for _, f := range []string{"admin.conf", "controller-manager.conf", "scheduler.conf", "super-admin.conf"} {
		os.WriteFile(filepath.Join(kubeconfigDir, f), []byte("original-"+f), 0644)
	}

	return pkiDir, kubeconfigDir
}

func setupTest(t *testing.T) (*Manager, *state.State, string, string, string) {
	t.Helper()

	pkiDir, kubeconfigDir := setupFakePKI(t)
	backupDir := t.TempDir()
	manifestDir := t.TempDir()
	stateDir := t.TempDir()
	stateFile := filepath.Join(stateDir, "state.json")

	for _, name := range []string{"etcd", "kube-apiserver", "kube-controller-manager", "kube-scheduler"} {
		content := "apiVersion: v1\nkind: Pod\nmetadata:\n  name: " + name + "\n  annotations: {}\nspec:\n  containers:\n  - name: " + name + "\n    image: test\n"
		os.WriteFile(filepath.Join(manifestDir, name+".yaml"), []byte(content), 0644)
	}

	backupMgr := backup.New(backupDir, pkiDir, kubeconfigDir)
	restartMgr := podrestart.New(manifestDir, true)
	mgr := New(backupMgr, restartMgr, stateFile, true)

	s := state.New()

	return mgr, s, pkiDir, stateFile, backupDir
}

func TestRollbackAll_DryRun(t *testing.T) {
	mgr, s, _, stateFile, backupDir := setupTest(t)

	pkiDir, kubeconfigDir := setupFakePKI(t)
	realBackupMgr := backup.New(backupDir, pkiDir, kubeconfigDir)
	b1, err := realBackupMgr.Create("node1")
	if err != nil {
		t.Fatalf("creating backup: %v", err)
	}

	s.Nodes["node1"] = state.NodeState{
		Node:       "node1",
		BackupPath: b1.BackupPath,
		RenewedAt:  time.Now(),
	}
	s.Save(stateFile)

	results := mgr.RollbackAll([]string{"node1"}, "node2", s, 5*time.Second)

	if len(results) == 0 {
		t.Fatal("expected at least one rollback result")
	}
}

func TestRollbackAll_ReversesOrder(t *testing.T) {
	mgr, s, _, stateFile, backupDir := setupTest(t)

	pkiDir, kubeconfigDir := setupFakePKI(t)
	realBackupMgr := backup.New(backupDir, pkiDir, kubeconfigDir)

	b1, err := realBackupMgr.Create("node1")
	if err != nil {
		t.Fatalf("creating node1 backup: %v", err)
	}
	b2, err := realBackupMgr.Create("node2")
	if err != nil {
		t.Fatalf("creating node2 backup: %v", err)
	}

	s.Nodes["node1"] = state.NodeState{Node: "node1", BackupPath: b1.BackupPath, RenewedAt: time.Now()}
	s.Nodes["node2"] = state.NodeState{Node: "node2", BackupPath: b2.BackupPath, RenewedAt: time.Now()}
	s.Save(stateFile)

	results := mgr.RollbackAll([]string{"node1", "node2"}, "node3", s, 5*time.Second)

	if len(results) != 3 {
		t.Errorf("expected 3 rollback results, got %d", len(results))
	}
	if results[0].Node != "node3" {
		t.Errorf("expected node3 first, got %s", results[0].Node)
	}
	if results[1].Node != "node2" {
		t.Errorf("expected node2 second, got %s", results[1].Node)
	}
	if results[2].Node != "node1" {
		t.Errorf("expected node1 last, got %s", results[2].Node)
	}
}

func TestRollbackAll_NoBackupPath(t *testing.T) {
	mgr, s, _, stateFile, _ := setupTest(t)

	// Node with no backup path
	s.Nodes["node1"] = state.NodeState{Node: "node1", BackupPath: ""}
	s.Save(stateFile)

	results := mgr.RollbackAll([]string{}, "node1", s, 5*time.Second)

	if len(results) == 0 {
		t.Fatal("expected rollback result")
	}
	if results[0].Success {
		t.Error("expected failure when no backup path")
	}
	if results[0].Error == nil {
		t.Error("expected error when no backup path")
	}
}

func TestRollbackAll_Deduplication(t *testing.T) {
	mgr, s, _, stateFile, backupDir := setupTest(t)

	pkiDir, kubeconfigDir := setupFakePKI(t)
	realBackupMgr := backup.New(backupDir, pkiDir, kubeconfigDir)
	b1, _ := realBackupMgr.Create("node1")

	s.Nodes["node1"] = state.NodeState{Node: "node1", BackupPath: b1.BackupPath}
	s.Save(stateFile)

	results := mgr.RollbackAll([]string{"node1"}, "node1", s, 5*time.Second)

	count := 0
	for _, r := range results {
		if r.Node == "node1" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected node1 once, got %d times", count)
	}
}

func TestIsCritical_AllSuccess(t *testing.T) {
	results := []RollbackResult{
		{Node: "node1", Success: true},
		{Node: "node2", Success: true},
	}
	if IsCritical(results) {
		t.Error("expected not critical when all rollbacks succeed")
	}
}

func TestIsCritical_OneFailed(t *testing.T) {
	results := []RollbackResult{
		{Node: "node1", Success: true},
		{Node: "node2", Success: false},
	}
	if !IsCritical(results) {
		t.Error("expected critical when any rollback fails")
	}
}

func TestSummary_AllSuccess(t *testing.T) {
	results := []RollbackResult{
		{Node: "node1", Success: true, RestoredAt: time.Now()},
		{Node: "node2", Success: true, RestoredAt: time.Now()},
	}
	summary := Summary(results, "node3", "health check")

	if summary == "" {
		t.Error("expected non-empty summary")
	}
	if !strings.Contains(summary, "node3") {
		t.Error("summary should mention failed node")
	}
	if !strings.Contains(summary, "health check") {
		t.Error("summary should mention failure step")
	}
	if !strings.Contains(summary, "successfully") {
		t.Error("summary should mention successful restore")
	}
}

func TestSummary_Critical(t *testing.T) {
	results := []RollbackResult{
		{Node: "node1", Success: false, Error: os.ErrNotExist},
	}
	summary := Summary(results, "node2", "cert write")

	if !strings.Contains(summary, "CRITICAL") {
		t.Error("summary should mention CRITICAL for failed rollback")
	}
	if !strings.Contains(summary, "Manual intervention") {
		t.Error("summary should mention Manual intervention")
	}
}

func TestReverse(t *testing.T) {
	input := []string{"node1", "node2", "node3"}
	result := reverse(input)

	if result[0] != "node3" || result[1] != "node2" || result[2] != "node1" {
		t.Errorf("unexpected reverse result: %v", result)
	}
	if input[0] != "node1" {
		t.Error("reverse should not modify original slice")
	}
}

func TestReverse_Empty(t *testing.T) {
	result := reverse([]string{})
	if len(result) != 0 {
		t.Error("reverse of empty slice should be empty")
	}
}

func TestReverse_Single(t *testing.T) {
	result := reverse([]string{"node1"})
	if len(result) != 1 || result[0] != "node1" {
		t.Errorf("unexpected result for single element: %v", result)
	}
}
