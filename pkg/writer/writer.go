package writer

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/tejeswar0625/cert-rotator/pkg/logger"
)

type Writer struct {
	pkiDir string
	dryRun bool
}

func New(pkiDir string, dryRun bool) *Writer {
	return &Writer{
		pkiDir: pkiDir,
		dryRun: dryRun,
	}
}

func (w *Writer) WriteCert(relPath string, certPEM []byte) error {
	fullPath := filepath.Join(w.pkiDir, relPath)

	if w.dryRun {
		logger.Info("writer", "", "DRY RUN — would write certificate file. No changes made to disk.",
			slog.String("path", fullPath),
			slog.Int("size_bytes", len(certPEM)),
		)
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		return fmt.Errorf("creating dir for %s: %w", fullPath, err)
	}

	if err := os.WriteFile(fullPath, certPEM, 0644); err != nil {
		return fmt.Errorf("writing cert %s: %w", fullPath, err)
	}

	logger.Info("writer", "",
		"Certificate file written successfully. Permissions set to 0644 — readable by control plane components.",
		slog.String("path", fullPath),
		slog.String("permissions", "0644"),
	)
	return nil
}

func (w *Writer) WriteKey(relPath string, keyPEM []byte) error {
	fullPath := filepath.Join(w.pkiDir, relPath)

	if w.dryRun {
		logger.Info("writer", "", "DRY RUN — would write private key file. No changes made to disk.",
			slog.String("path", fullPath),
		)
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		return fmt.Errorf("creating dir for %s: %w", fullPath, err)
	}

	if err := os.WriteFile(fullPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("writing key %s: %w", fullPath, err)
	}

	logger.Info("writer", "",
		"Private key file written successfully. Permissions set to 0600 — readable by root only. This is intentional for security.",
		slog.String("path", fullPath),
		slog.String("permissions", "0600"),
	)
	return nil
}

func (w *Writer) WriteCertKeyPair(relCertPath, relKeyPath string, certPEM, keyPEM []byte) error {
	logger.Info("writer", "",
		"Writing cert and key pair to disk.",
		slog.String("cert_path", filepath.Join(w.pkiDir, relCertPath)),
		slog.String("key_path", filepath.Join(w.pkiDir, relKeyPath)),
	)

	if err := w.WriteCert(relCertPath, certPEM); err != nil {
		return err
	}
	if err := w.WriteKey(relKeyPath, keyPEM); err != nil {
		return err
	}
	return nil
}

var CertPaths = map[string][2]string{
	"apiserver":                {"apiserver.crt", "apiserver.key"},
	"apiserver-etcd-client":    {"apiserver-etcd-client.crt", "apiserver-etcd-client.key"},
	"apiserver-kubelet-client": {"apiserver-kubelet-client.crt", "apiserver-kubelet-client.key"},
	"front-proxy-client":       {"front-proxy-client.crt", "front-proxy-client.key"},
	"etcd-server":              {"etcd/server.crt", "etcd/server.key"},
	"etcd-peer":                {"etcd/peer.crt", "etcd/peer.key"},
	"etcd-healthcheck-client":  {"etcd/healthcheck-client.crt", "etcd/healthcheck-client.key"},
}

func (w *Writer) WriteAllCerts(pairs map[string][2][]byte) error {
	logger.Info("writer", "",
		"Writing all renewed certificate and key pairs to disk.",
		slog.Int("cert_count", len(pairs)),
	)

	for certName, pems := range pairs {
		paths, ok := CertPaths[certName]
		if !ok {
			return fmt.Errorf("unknown cert name: %s", certName)
		}

		if err := w.WriteCertKeyPair(paths[0], paths[1], pems[0], pems[1]); err != nil {
			return fmt.Errorf("writing cert pair for %s: %w", certName, err)
		}
	}
	return nil
}

func (w *Writer) Verify() error {
	logger.Info("writer", "",
		"Verifying all certificate files were written correctly. Checking each file exists and is non-empty.",
	)

	for certName, paths := range CertPaths {
		for _, relPath := range paths {
			fullPath := filepath.Join(w.pkiDir, relPath)
			info, err := os.Stat(fullPath)
			if err != nil {
				return fmt.Errorf("cert file missing after write [%s]: %s: %w", certName, fullPath, err)
			}
			if info.Size() == 0 {
				return fmt.Errorf("cert file empty after write [%s]: %s", certName, fullPath)
			}

			logger.Debug("writer", "",
				"Cert file verified — exists and non-empty",
				slog.String("cert", certName),
				slog.String("path", fullPath),
				slog.Int64("size_bytes", info.Size()),
			)
		}
	}

	logger.Info("writer", "",
		"All certificate files verified successfully. Safe to proceed with static pod restart.",
	)
	return nil
}
