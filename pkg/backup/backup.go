package backup

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/tejeswar0625/cert-rotator/pkg/logger"
)

var pkiFiles = []string{
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

var kubeconfigFiles = []string{
	"admin.conf",
	"controller-manager.conf",
	"scheduler.conf",
	"super-admin.conf",
}

type Backup struct {
	Node       string    `json:"node"`
	BackupPath string    `json:"backup_path"`
	CreatedAt  time.Time `json:"created_at"`
}

type Manager struct {
	backupDir     string
	pkiDir        string
	kubeconfigDir string
}

func New(backupDir, pkiDir, kubeconfigDir string) *Manager {
	return &Manager{
		backupDir:     backupDir,
		pkiDir:        pkiDir,
		kubeconfigDir: kubeconfigDir,
	}
}

func (m *Manager) Create(node string) (*Backup, error) {
	timestamp := time.Now().UTC().Format("2006-01-02T15-04-05Z")
	backupPath := filepath.Join(m.backupDir, node, timestamp)

	pkiBackup := filepath.Join(backupPath, "pki")
	kubeconfigBackup := filepath.Join(backupPath, "kubeconfigs")

	logger.Info("backup", node,
		"Creating cert backup before renewal. This is a file-level copy of cert and kubeconfig files only — no cluster state or etcd data is touched.",
		slog.String("backup_path", backupPath),
		slog.String("pki_source", m.pkiDir),
		slog.String("kubeconfig_source", m.kubeconfigDir),
	)

	if err := os.MkdirAll(pkiBackup, 0700); err != nil {
		return nil, fmt.Errorf("creating pki backup dir: %w", err)
	}
	if err := os.MkdirAll(kubeconfigBackup, 0700); err != nil {
		return nil, fmt.Errorf("creating kubeconfig backup dir: %w", err)
	}

	// Back up PKI files
	for _, rel := range pkiFiles {
		src := filepath.Join(m.pkiDir, rel)
		dst := filepath.Join(pkiBackup, rel)

		if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
			return nil, fmt.Errorf("creating subdir for %s: %w", rel, err)
		}

		if err := copyFile(src, dst); err != nil {
			if os.IsNotExist(err) {
				logger.Debug("backup", node,
					"Cert file not found — skipping. This is normal for optional files like super-admin.conf on older clusters.",
					slog.String("file", rel),
				)
				continue
			}
			return nil, fmt.Errorf("backing up %s: %w", rel, err)
		}

		logger.Debug("backup", node, "Backed up cert file",
			slog.String("file", rel),
		)
	}

	// Back up kubeconfig files
	for _, filename := range kubeconfigFiles {
		src := filepath.Join(m.kubeconfigDir, filename)
		dst := filepath.Join(kubeconfigBackup, filename)

		if err := copyFile(src, dst); err != nil {
			if os.IsNotExist(err) {
				logger.Debug("backup", node,
					"Kubeconfig file not found — skipping.",
					slog.String("file", filename),
				)
				continue
			}
			return nil, fmt.Errorf("backing up kubeconfig %s: %w", filename, err)
		}

		logger.Debug("backup", node, "Backed up kubeconfig file",
			slog.String("file", filename),
		)
	}

	b := &Backup{
		Node:       node,
		BackupPath: backupPath,
		CreatedAt:  time.Now().UTC(),
	}

	logger.Info("backup", node,
		"Cert backup completed successfully. If renewal fails, this backup will be used to restore the node to its previous state.",
		slog.String("backup_path", backupPath),
		slog.String("created_at", b.CreatedAt.Format(time.RFC3339)),
	)

	return b, nil
}

func (m *Manager) Restore(backupPath string) error {
	pkiBackup := filepath.Join(backupPath, "pki")
	kubeconfigBackup := filepath.Join(backupPath, "kubeconfigs")

	logger.Info("backup", "",
		"Restoring cert backup. Copying previous cert files back to their original locations on the node.",
		slog.String("backup_path", backupPath),
		slog.String("pki_destination", m.pkiDir),
		slog.String("kubeconfig_destination", m.kubeconfigDir),
	)

	// Restore PKI files
	for _, rel := range pkiFiles {
		src := filepath.Join(pkiBackup, rel)
		dst := filepath.Join(m.pkiDir, rel)

		if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
			return fmt.Errorf("creating pki subdir for restore %s: %w", rel, err)
		}

		if err := copyFile(src, dst); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("restoring %s: %w", rel, err)
		}

		logger.Debug("backup", "", "Restored cert file",
			slog.String("file", rel),
			slog.String("destination", dst),
		)
	}

	// Restore kubeconfig files
	for _, filename := range kubeconfigFiles {
		src := filepath.Join(kubeconfigBackup, filename)
		dst := filepath.Join(m.kubeconfigDir, filename)

		if err := copyFile(src, dst); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("restoring kubeconfig %s: %w", filename, err)
		}

		logger.Debug("backup", "", "Restored kubeconfig file",
			slog.String("file", filename),
			slog.String("destination", dst),
		)
	}

	logger.Info("backup", "",
		"Cert restore completed. All cert and kubeconfig files have been restored from backup. Static pods will be restarted next to pick up the restored certs.",
		slog.String("backup_path", backupPath),
	)

	return nil
}

func (m *Manager) Cleanup(node string, keepDays int) error {
	nodeBackupDir := filepath.Join(m.backupDir, node)
	entries, err := os.ReadDir(nodeBackupDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	cutoff := time.Now().AddDate(0, 0, -keepDays)
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			path := filepath.Join(nodeBackupDir, entry.Name())
			logger.Info("backup", node,
				"Removing old cert backup — older than retention period",
				slog.String("backup_path", path),
				slog.Int("keep_days", keepDays),
				slog.String("backup_age", info.ModTime().Format(time.RFC3339)),
			)
			os.RemoveAll(path)
		}
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	srcInfo, err := in.Stat()
	if err != nil {
		return err
	}

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, srcInfo.Mode())
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
