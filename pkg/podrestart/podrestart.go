package podrestart

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/tejeswar0625/cert-rotator/pkg/logger"
)

var restartOrder = []string{
	"etcd",
	"kube-apiserver",
	"kube-controller-manager",
	"kube-scheduler",
}

type Manager struct {
	manifestDir string
	dryRun      bool
}

func New(manifestDir string, dryRun bool) *Manager {
	return &Manager{
		manifestDir: manifestDir,
		dryRun:      dryRun,
	}
}

func (m *Manager) RestartAll() error {
	logger.Info("podrestart", "",
		"Starting static pod restart sequence. Pods will be restarted in a specific order — etcd first, then apiserver, then controller-manager and scheduler. This order is critical: etcd must be healthy before apiserver starts.",
		slog.String("restart_order", fmt.Sprintf("%v", restartOrder)),
	)

	for _, name := range restartOrder {
		if err := m.Restart(name); err != nil {
			return fmt.Errorf("restarting %s: %w", name, err)
		}
		if !m.dryRun {
			logger.Info("podrestart", "",
				"Waiting for kubelet to detect manifest change and recreate the pod. This typically takes 5-15 seconds.",
				slog.String("pod", name),
				slog.String("wait", "10s"),
			)
			time.Sleep(10 * time.Second)
		}
	}

	logger.Info("podrestart", "",
		"All static pods restarted successfully. Proceeding to health check.",
	)
	return nil
}

func (m *Manager) Restart(name string) error {
	manifestPath := filepath.Join(m.manifestDir, name+".yaml")

	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		manifestPath = filepath.Join(m.manifestDir, name+".yml")
		if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
			return fmt.Errorf("manifest not found for %s in %s", name, m.manifestDir)
		}
	}

	if m.dryRun {
		logger.Info("podrestart", "",
			"DRY RUN — would restart static pod by updating restart annotation in manifest. No changes made.",
			slog.String("pod", name),
			slog.String("manifest", manifestPath),
		)
		return nil
	}

	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("reading manifest %s: %w", manifestPath, err)
	}

	updated, err := injectRestartAnnotation(data)
	if err != nil {
		return fmt.Errorf("injecting restart annotation into %s: %w", name, err)
	}

	info, err := os.Stat(manifestPath)
	if err != nil {
		return fmt.Errorf("statting manifest %s: %w", manifestPath, err)
	}

	if err := os.WriteFile(manifestPath, updated, info.Mode()); err != nil {
		return fmt.Errorf("writing manifest %s: %w", manifestPath, err)
	}

	logger.Info("podrestart", "",
		"Static pod restart triggered. A restart annotation has been added to the manifest file. "+
			"Kubelet watches this directory and will automatically stop and recreate the pod when it detects the change.",
		slog.String("pod", name),
		slog.String("manifest", manifestPath),
		slog.String("mechanism", "annotation update — kubelet detects manifest change and recreates pod"),
	)
	return nil
}

func injectRestartAnnotation(data []byte) ([]byte, error) {
	var manifest map[string]interface{}
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("parsing manifest: %w", err)
	}

	metadata, ok := manifest["metadata"].(map[string]interface{})
	if !ok {
		metadata = make(map[string]interface{})
		manifest["metadata"] = metadata
	}

	annotations, ok := metadata["annotations"].(map[string]interface{})
	if !ok {
		annotations = make(map[string]interface{})
		metadata["annotations"] = annotations
	}

	annotations["cert-rotator/restarted-at"] = time.Now().UTC().Format(time.RFC3339)

	updated, err := yaml.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("marshalling updated manifest: %w", err)
	}

	return updated, nil
}

func (m *Manager) WaitForReady(name string, timeout time.Duration) error {
	manifestPath := filepath.Join(m.manifestDir, name+".yaml")
	deadline := time.Now().Add(timeout)

	logger.Info("podrestart", "",
		"Waiting for static pod manifest to be ready after restart.",
		slog.String("pod", name),
		slog.String("timeout", timeout.String()),
	)

	for time.Now().Before(deadline) {
		info, err := os.Stat(manifestPath)
		if err == nil && info.Size() > 0 {
			logger.Info("podrestart", "",
				"Static pod manifest is ready.",
				slog.String("pod", name),
			)
			return nil
		}
		time.Sleep(2 * time.Second)
	}

	return fmt.Errorf("timeout waiting for manifest %s to be ready", name)
}
