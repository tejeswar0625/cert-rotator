package podrestart

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// createFakeManifest writes a minimal static pod manifest to a temp dir
func createFakeManifest(t *testing.T, dir, name string) string {
	t.Helper()
	content := `apiVersion: v1
kind: Pod
metadata:
  name: ` + name + `
  namespace: kube-system
  annotations: {}
spec:
  containers:
  - name: ` + name + `
    image: k8s.gcr.io/` + name + `:v1.26.0
`
	path := filepath.Join(dir, name+".yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("creating fake manifest: %v", err)
	}
	return path
}

func TestRestart_InjectsAnnotation(t *testing.T) {
	dir := t.TempDir()
	createFakeManifest(t, dir, "kube-apiserver")

	m := New(dir, false)
	if err := m.Restart("kube-apiserver"); err != nil {
		t.Fatalf("Restart failed: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "kube-apiserver.yaml"))
	if err != nil {
		t.Fatalf("reading manifest: %v", err)
	}

	if !strings.Contains(string(data), "cert-rotator/restarted-at") {
		t.Error("expected restart annotation in manifest")
	}
}

func TestRestart_DryRun_NoChange(t *testing.T) {
	dir := t.TempDir()
	path := createFakeManifest(t, dir, "kube-apiserver")

	original, _ := os.ReadFile(path)

	m := New(dir, true) // dry run
	if err := m.Restart("kube-apiserver"); err != nil {
		t.Fatalf("Restart dry run failed: %v", err)
	}

	after, _ := os.ReadFile(path)
	if string(original) != string(after) {
		t.Error("dry run should not modify the manifest")
	}
}

func TestRestart_MissingManifest(t *testing.T) {
	dir := t.TempDir()
	m := New(dir, false)

	err := m.Restart("kube-apiserver")
	if err == nil {
		t.Error("expected error for missing manifest")
	}
}

func TestRestart_YmlExtension(t *testing.T) {
	dir := t.TempDir()

	// Write with .yml extension instead of .yaml
	content := `apiVersion: v1
kind: Pod
metadata:
  name: kube-scheduler
  namespace: kube-system
  annotations: {}
spec:
  containers:
  - name: kube-scheduler
    image: k8s.gcr.io/kube-scheduler:v1.26.0
`
	os.WriteFile(filepath.Join(dir, "kube-scheduler.yml"), []byte(content), 0644)

	m := New(dir, false)
	if err := m.Restart("kube-scheduler"); err != nil {
		t.Fatalf("Restart failed for .yml extension: %v", err)
	}
}

func TestRestart_AnnotationUpdatedOnSecondRestart(t *testing.T) {
	dir := t.TempDir()
	createFakeManifest(t, dir, "etcd")

	m := New(dir, false)

	// First restart
	if err := m.Restart("etcd"); err != nil {
		t.Fatalf("first Restart failed: %v", err)
	}

	data1, _ := os.ReadFile(filepath.Join(dir, "etcd.yaml"))

	// Second restart
	if err := m.Restart("etcd"); err != nil {
		t.Fatalf("second Restart failed: %v", err)
	}

	data2, _ := os.ReadFile(filepath.Join(dir, "etcd.yaml"))

	// Both should have the annotation but timestamps will differ
	if !strings.Contains(string(data1), "cert-rotator/restarted-at") {
		t.Error("first restart missing annotation")
	}
	if !strings.Contains(string(data2), "cert-rotator/restarted-at") {
		t.Error("second restart missing annotation")
	}
}

func TestInjectRestartAnnotation_ValidYAML(t *testing.T) {
	input := []byte(`apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
  namespace: kube-system
spec:
  containers:
  - name: kube-apiserver
    image: k8s.gcr.io/kube-apiserver:v1.26.0
`)
	result, err := injectRestartAnnotation(input)
	if err != nil {
		t.Fatalf("injectRestartAnnotation failed: %v", err)
	}

	if !strings.Contains(string(result), "cert-rotator/restarted-at") {
		t.Error("annotation not injected")
	}
}

func TestInjectRestartAnnotation_PreservesExistingAnnotations(t *testing.T) {
	input := []byte(`apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
  namespace: kube-system
  annotations:
    existing-annotation: "existing-value"
spec:
  containers:
  - name: kube-apiserver
    image: k8s.gcr.io/kube-apiserver:v1.26.0
`)
	result, err := injectRestartAnnotation(input)
	if err != nil {
		t.Fatalf("injectRestartAnnotation failed: %v", err)
	}

	if !strings.Contains(string(result), "existing-annotation") {
		t.Error("existing annotation was lost")
	}
	if !strings.Contains(string(result), "cert-rotator/restarted-at") {
		t.Error("new annotation not injected")
	}
}

func TestInjectRestartAnnotation_InvalidYAML(t *testing.T) {
	input := []byte(`this is not: valid: yaml: at: all: {{{`)
	_, err := injectRestartAnnotation(input)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestRestartAll_DryRun(t *testing.T) {
	dir := t.TempDir()

	// Create all static pod manifests
	for _, name := range restartOrder {
		createFakeManifest(t, dir, name)
	}

	m := New(dir, true) // dry run
	if err := m.RestartAll(); err != nil {
		t.Fatalf("RestartAll dry run failed: %v", err)
	}

	// Verify no manifests were modified
	for _, name := range restartOrder {
		data, _ := os.ReadFile(filepath.Join(dir, name+".yaml"))
		if strings.Contains(string(data), "cert-rotator/restarted-at") {
			t.Errorf("dry run should not have modified manifest for %s", name)
		}
	}
}
