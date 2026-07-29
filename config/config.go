package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	BackupDir            string
	StateFile            string
	RenewalThresholdDays int
	CheckInterval        time.Duration
	PKIDir               string
	ManifestDir          string
	KubeconfigDir        string
	CAKeyPath            string
	EtcdCAKeyPath        string
	FrontProxyCAKeyPath  string
	CurrentNode          string
	SMTPEnabled          bool
	SMTPHost             string
	SMTPPort             int
	SMTPFrom             string
	SMTPTo               []string
	SlackWebhookEnabled  bool
	SlackWebhookURL      string
	DryRun               bool
}

func Load() *Config {
	return &Config{
		BackupDir:            getEnv("CERT_ROTATOR_BACKUP_DIR", "/var/lib/cert-rotator/backups"),
		StateFile:            getEnv("CERT_ROTATOR_STATE_FILE", "/var/lib/cert-rotator/state.json"),
		RenewalThresholdDays: getEnvInt("CERT_ROTATOR_THRESHOLD_DAYS", 30),
		CheckInterval:        time.Duration(getEnvInt("CERT_ROTATOR_CHECK_INTERVAL_HOURS", 24)) * time.Hour,
		PKIDir:               getEnv("CERT_ROTATOR_PKI_DIR", "/etc/kubernetes/pki"),
		ManifestDir:          getEnv("CERT_ROTATOR_MANIFEST_DIR", "/etc/kubernetes/manifests"),
		KubeconfigDir:        getEnv("CERT_ROTATOR_KUBECONFIG_DIR", "/etc/kubernetes"),
		CAKeyPath:            getEnv("CERT_ROTATOR_CA_KEY_PATH", "/etc/kubernetes/pki/ca.key"),
		EtcdCAKeyPath:        getEnv("CERT_ROTATOR_ETCD_CA_KEY_PATH", "/etc/kubernetes/pki/etcd/ca.key"),
		FrontProxyCAKeyPath:  getEnv("CERT_ROTATOR_FRONT_PROXY_CA_KEY_PATH", "/etc/kubernetes/pki/front-proxy-ca.key"),
		CurrentNode:          getEnv("NODE_NAME", ""),
		SMTPEnabled:          getEnvBool("CERT_ROTATOR_SMTP_ENABLED", false),
		SMTPHost:             getEnv("CERT_ROTATOR_SMTP_HOST", ""),
		SMTPPort:             getEnvInt("CERT_ROTATOR_SMTP_PORT", 587),
		SMTPFrom:             getEnv("CERT_ROTATOR_SMTP_FROM", ""),
		SlackWebhookEnabled:  getEnvBool("CERT_ROTATOR_SLACK_ENABLED", false),
		SlackWebhookURL:      getEnv("CERT_ROTATOR_SLACK_WEBHOOK_URL", ""),
		DryRun:               getEnvBool("CERT_ROTATOR_DRY_RUN", false),
	}
}

func Default() *Config {
	return Load()
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if val := os.Getenv(key); val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return fallback
}

func getEnvBool(key string, fallback bool) bool {
	if val := os.Getenv(key); val != "" {
		if b, err := strconv.ParseBool(val); err == nil {
			return b
		}
	}
	return fallback
}
