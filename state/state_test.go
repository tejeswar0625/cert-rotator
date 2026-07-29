package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	s := New()
	if s.Phase != PhaseIdle {
		t.Errorf("expected IDLE phase, got %s", s.Phase)
	}
	if s.Nodes == nil {
		t.Error("expected non-nil nodes map")
	}
	if s.Critical {
		t.Error("expected critical to be false")
	}
}

func TestLoad_NoFile(t *testing.T) {
	// Loading from a non-existent path should return a fresh state
	s, err := Load("/nonexistent/path/state.json")
	if err != nil {
		t.Fatalf("expected no error for missing file, got: %v", err)
	}
	if s.Phase != PhaseIdle {
		t.Errorf("expected IDLE for fresh state, got %s", s.Phase)
	}
}

func TestSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	s := New()
	s.Phase = PhaseRenewingN1
	s.FailedNode = "node2"
	s.StartedAt = time.Now().UTC().Truncate(time.Second)

	if err := s.Save(path); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("state file not created: %v", err)
	}

	// Load it back
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if loaded.Phase != PhaseRenewingN1 {
		t.Errorf("phase mismatch: got %s want %s", loaded.Phase, PhaseRenewingN1)
	}
	if loaded.FailedNode != "node2" {
		t.Errorf("failed node mismatch: got %s want %s", loaded.FailedNode, "node2")
	}
}

func TestSetPhase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	s := New()

	phases := []Phase{
		PhaseDetecting,
		PhaseRenewingN1,
		PhaseRenewingN2,
		PhaseRenewingN3,
		PhaseRollbackN3,
		PhaseRollbackN2,
		PhaseRollbackN1,
		PhaseNotifying,
		PhaseIdle,
	}

	for _, phase := range phases {
		if err := s.SetPhase(phase, path); err != nil {
			t.Fatalf("SetPhase %s failed: %v", phase, err)
		}
		if s.Phase != phase {
			t.Errorf("expected phase %s, got %s", phase, s.Phase)
		}

		// Verify persisted correctly
		loaded, _ := Load(path)
		if loaded.Phase != phase {
			t.Errorf("persisted phase mismatch: got %s want %s", loaded.Phase, phase)
		}
	}
}

func TestSetNodeBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	s := New()
	err := s.SetNodeBackup("node1", "/var/lib/cert-rotator/backups/node1/2026-01-01", path)
	if err != nil {
		t.Fatalf("SetNodeBackup failed: %v", err)
	}

	ns, ok := s.Nodes["node1"]
	if !ok {
		t.Fatal("expected node1 in nodes map")
	}
	if ns.BackupPath != "/var/lib/cert-rotator/backups/node1/2026-01-01" {
		t.Errorf("backup path mismatch: got %s", ns.BackupPath)
	}
	if ns.Node != "node1" {
		t.Errorf("node mismatch: got %s", ns.Node)
	}

	// Verify persisted
	loaded, _ := Load(path)
	if loaded.Nodes["node1"].BackupPath == "" {
		t.Error("backup path not persisted")
	}
}

func TestSetNodeRenewed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	s := New()
	s.Nodes["node1"] = NodeState{Node: "node1"}

	if err := s.SetNodeRenewed("node1", path); err != nil {
		t.Fatalf("SetNodeRenewed failed: %v", err)
	}

	ns := s.Nodes["node1"]
	if ns.RenewedAt.IsZero() {
		t.Error("expected non-zero RenewedAt")
	}
}

func TestSetNodeRollback_Success(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	s := New()
	s.Nodes["node1"] = NodeState{Node: "node1"}

	if err := s.SetNodeRollback("node1", false, path); err != nil {
		t.Fatalf("SetNodeRollback failed: %v", err)
	}

	ns := s.Nodes["node1"]
	if ns.RolledBackAt.IsZero() {
		t.Error("expected non-zero RolledBackAt")
	}
	if ns.RollbackFailed {
		t.Error("expected RollbackFailed to be false")
	}
	if s.Critical {
		t.Error("expected Critical to be false on successful rollback")
	}
}

func TestSetNodeRollback_Failed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	s := New()
	s.Nodes["node1"] = NodeState{Node: "node1"}

	if err := s.SetNodeRollback("node1", true, path); err != nil {
		t.Fatalf("SetNodeRollback failed: %v", err)
	}

	if !s.Nodes["node1"].RollbackFailed {
		t.Error("expected RollbackFailed to be true")
	}
	if !s.Critical {
		t.Error("expected Critical to be true when rollback fails")
	}
}

func TestIsInProgress(t *testing.T) {
	s := New()

	if s.IsInProgress() {
		t.Error("expected false for IDLE state")
	}

	s.Phase = PhaseRenewingN1
	if !s.IsInProgress() {
		t.Error("expected true for RENEWING state")
	}

	s.Phase = PhaseRollbackN2
	if !s.IsInProgress() {
		t.Error("expected true for ROLLBACK state")
	}
}

func TestReset(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	s := New()
	s.Phase = PhaseRollbackN1
	s.FailedNode = "node3"
	s.FailureStep = "health check"
	s.Critical = true
	s.Nodes["node1"] = NodeState{Node: "node1", BackupPath: "/some/path"}

	if err := s.Reset(path); err != nil {
		t.Fatalf("Reset failed: %v", err)
	}

	if s.Phase != PhaseIdle {
		t.Errorf("expected IDLE after reset, got %s", s.Phase)
	}
	if s.FailedNode != "" {
		t.Error("expected empty FailedNode after reset")
	}
	if s.Critical {
		t.Error("expected Critical false after reset")
	}
	if len(s.Nodes) != 0 {
		t.Error("expected empty nodes map after reset")
	}

	// Verify reset is persisted
	loaded, _ := Load(path)
	if loaded.Phase != PhaseIdle {
		t.Error("reset not persisted")
	}
}

func TestSave_CreatesParentDir(t *testing.T) {
	dir := t.TempDir()
	// Use a nested path that doesn't exist yet
	path := filepath.Join(dir, "nested", "deep", "state.json")

	s := New()
	if err := s.Save(path); err != nil {
		t.Fatalf("Save should create parent dirs: %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Error("state file not created in nested dir")
	}
}

func TestSave_UpdatesTimestamp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	s := New()
	before := time.Now()
	s.Save(path)
	after := time.Now()

	loaded, _ := Load(path)
	if loaded.UpdatedAt.Before(before) || loaded.UpdatedAt.After(after) {
		t.Errorf("UpdatedAt not set correctly: got %v", loaded.UpdatedAt)
	}
}
