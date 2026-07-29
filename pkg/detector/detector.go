package detector

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/tejeswar0625/cert-rotator/pkg/logger"
)

type CertStatus string

const (
	StatusOK          CertStatus = "OK"
	StatusApproaching CertStatus = "APPROACHING"
	StatusExpired     CertStatus = "EXPIRED"
)

type CertInfo struct {
	Name         string
	Path         string
	Expiry       time.Time
	ResidualDays int
	Status       CertStatus
	Subject      string
	DNSNames     []string
	IPAddresses  []string
}

type DetectionResult struct {
	Node  string
	Certs []CertInfo
}

var certFiles = map[string]string{
	"apiserver":                "apiserver.crt",
	"apiserver-etcd-client":    "apiserver-etcd-client.crt",
	"apiserver-kubelet-client": "apiserver-kubelet-client.crt",
	"front-proxy-client":       "front-proxy-client.crt",
	"etcd-server":              "etcd/server.crt",
	"etcd-peer":                "etcd/peer.crt",
	"etcd-healthcheck-client":  "etcd/healthcheck-client.crt",
}

var kubeconfigCerts = map[string]string{
	"admin.conf":              "admin.conf",
	"controller-manager.conf": "controller-manager.conf",
	"scheduler.conf":          "scheduler.conf",
	"super-admin.conf":        "super-admin.conf",
}

type Detector struct {
	pkiDir        string
	kubeconfigDir string
	thresholdDays int
}

func New(pkiDir, kubeconfigDir string, thresholdDays int) *Detector {
	return &Detector{
		pkiDir:        pkiDir,
		kubeconfigDir: kubeconfigDir,
		thresholdDays: thresholdDays,
	}
}

func (d *Detector) Detect(node string) (*DetectionResult, error) {
	logger.Info("detector", node,
		"Starting certificate expiry detection. Reading all control plane certs from disk.",
		slog.String("pki_dir", d.pkiDir),
		slog.String("kubeconfig_dir", d.kubeconfigDir),
		slog.Int("renewal_threshold_days", d.thresholdDays),
	)

	result := &DetectionResult{Node: node}

	// Check PKI certs
	for name, relPath := range certFiles {
		fullPath := filepath.Join(d.pkiDir, relPath)
		logger.Debug("detector", node, "Reading certificate file",
			slog.String("cert", name),
			slog.String("path", fullPath),
		)

		info, err := d.parseCert(name, fullPath)
		if err != nil {
			return nil, fmt.Errorf("reading cert %s at %s: %w", name, fullPath, err)
		}
		info.Status = d.classify(info.ResidualDays)
		result.Certs = append(result.Certs, *info)
	}

	// Check kubeconfig embedded certs
	for name, filename := range kubeconfigCerts {
		fullPath := filepath.Join(d.kubeconfigDir, filename)
		logger.Debug("detector", node, "Reading kubeconfig embedded certificate",
			slog.String("cert", name),
			slog.String("path", fullPath),
		)

		info, err := d.parseKubeconfigCert(name, fullPath)
		if err != nil {
			return nil, fmt.Errorf("reading kubeconfig cert %s at %s: %w", name, fullPath, err)
		}
		if info == nil {
			// file doesn't exist — skip
			continue
		}
		info.Status = d.classify(info.ResidualDays)
		result.Certs = append(result.Certs, *info)
	}

	logger.Info("detector", node,
		"Certificate detection complete",
		slog.Int("total_certs_checked", len(result.Certs)),
		slog.Bool("needs_renewal", result.NeedsRenewal()),
		slog.Bool("urgent", result.IsUrgent()),
	)

	return result, nil
}

func (d *Detector) parseCert(name, path string) (*CertInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return d.parsePEMCert(name, path, data)
}

func (d *Detector) parsePEMCert(name, path string, data []byte) (*CertInfo, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate %s: %w", path, err)
	}

	now := time.Now()
	residual := cert.NotAfter.Sub(now)
	residualDays := int(residual.Hours() / 24)

	ips := make([]string, 0, len(cert.IPAddresses))
	for _, ip := range cert.IPAddresses {
		ips = append(ips, ip.String())
	}

	return &CertInfo{
		Name:         name,
		Path:         path,
		Expiry:       cert.NotAfter,
		ResidualDays: residualDays,
		Subject:      cert.Subject.CommonName,
		DNSNames:     cert.DNSNames,
		IPAddresses:  ips,
	}, nil
}

func (d *Detector) parseKubeconfigCert(name, path string) (*CertInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Debug("detector", "",
				"Kubeconfig file not found — skipping. This is normal for super-admin.conf on older clusters.",
				slog.String("cert", name),
				slog.String("path", path),
			)
			return nil, nil
		}
		return nil, err
	}

	// Parse using generic map to avoid YAML tag issues with hyphenated keys
	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing kubeconfig %s: %w", path, err)
	}

	certData, err := extractClientCertData(raw, path)
	if err != nil {
		return nil, err
	}
	if certData == "" {
		return nil, fmt.Errorf("no client certificate found in kubeconfig %s", path)
	}

	// Step 1: base64 decode
	decoded, err := base64.StdEncoding.DecodeString(certData)
	if err != nil {
		return nil, fmt.Errorf("decoding cert from kubeconfig %s: %w", path, err)
	}

	// Step 2: the decoded bytes may be PEM-encoded (base64 of PEM is common in kubeconfigs)
	// Try PEM decode first, fall back to treating as raw DER
	certDER := decoded
	if block, _ := pem.Decode(decoded); block != nil {
		logger.Debug("detector", "",
			"Kubeconfig cert is PEM-encoded inside base64 — decoding PEM layer",
			slog.String("path", path),
		)
		certDER = block.Bytes
	}

	// Step 3: parse the DER certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parsing cert from kubeconfig %s: %w", path, err)
	}

	now := time.Now()
	residualDays := int(cert.NotAfter.Sub(now).Hours() / 24)

	logger.Debug("detector", "",
		"Kubeconfig cert parsed successfully",
		slog.String("cert", name),
		slog.String("subject", cert.Subject.CommonName),
		slog.Int("residual_days", residualDays),
		slog.String("expiry", cert.NotAfter.Format(time.RFC3339)),
	)

	return &CertInfo{
		Name:         name,
		Path:         path,
		Expiry:       cert.NotAfter,
		ResidualDays: residualDays,
		Subject:      cert.Subject.CommonName,
	}, nil
}

// extractClientCertData navigates the kubeconfig map to find client-certificate-data
func extractClientCertData(raw map[string]interface{}, path string) (string, error) {
	usersRaw, ok := raw["users"]
	if !ok {
		return "", fmt.Errorf("no users field in kubeconfig %s", path)
	}

	users, ok := usersRaw.([]interface{})
	if !ok {
		return "", fmt.Errorf("users field is not a list in kubeconfig %s", path)
	}

	logger.Debug("detector", "",
		"Scanning kubeconfig users",
		slog.String("path", path),
		slog.Int("users_found", len(users)),
	)

	for _, u := range users {
		userMap, ok := u.(map[string]interface{})
		if !ok {
			continue
		}

		userField, ok := userMap["user"]
		if !ok {
			continue
		}

		userInfo, ok := userField.(map[string]interface{})
		if !ok {
			continue
		}

		// Try both hyphenated and camelCase variants
		for _, key := range []string{"client-certificate-data", "clientCertificateData"} {
			if val, ok := userInfo[key]; ok {
				if certStr, ok := val.(string); ok && certStr != "" {
					logger.Debug("detector", "",
						"Found client certificate data in kubeconfig",
						slog.String("path", path),
						slog.String("key", key),
					)
					return certStr, nil
				}
			}
		}
	}

	return "", nil
}

func (d *Detector) classify(residualDays int) CertStatus {
	if residualDays <= 0 {
		return StatusExpired
	}
	if residualDays <= d.thresholdDays {
		return StatusApproaching
	}
	return StatusOK
}

func (r *DetectionResult) NeedsRenewal() bool {
	for _, c := range r.Certs {
		if c.Status != StatusOK {
			return true
		}
	}
	return false
}

func (r *DetectionResult) IsUrgent() bool {
	for _, c := range r.Certs {
		if c.Status == StatusExpired {
			return true
		}
	}
	return false
}

func (r *DetectionResult) LogSummary() {
	for _, c := range r.Certs {
		switch c.Status {
		case StatusOK:
			logger.Info("detector", r.Node,
				"Certificate is healthy — no action required",
				slog.String("cert", c.Name),
				slog.String("expiry", c.Expiry.Format(time.RFC3339)),
				slog.Int("residual_days", c.ResidualDays),
				slog.String("next_action", "none"),
			)
		case StatusApproaching:
			logger.Warn("detector", r.Node,
				"Certificate is expiring soon — renewal will be triggered. "+
					"If left unrenewed, the control plane will stop working when this cert expires.",
				slog.String("cert", c.Name),
				slog.String("expiry", c.Expiry.Format(time.RFC3339)),
				slog.Int("residual_days", c.ResidualDays),
				slog.String("next_action", "renewal scheduled for this cycle"),
			)
		case StatusExpired:
			logger.Critical("detector", r.Node,
				"CERTIFICATE HAS ALREADY EXPIRED. The control plane component using this cert "+
					"may already be unreachable. Immediate renewal is being triggered.",
				fmt.Errorf("cert %s expired on %s", c.Name, c.Expiry.Format(time.RFC3339)),
				slog.String("cert", c.Name),
				slog.String("expired_at", c.Expiry.Format(time.RFC3339)),
				slog.String("next_action", "immediate renewal triggered — this cycle will not wait"),
			)
		}
	}
}

func (r *DetectionResult) Summary() []string {
	lines := make([]string, 0, len(r.Certs))
	for _, c := range r.Certs {
		lines = append(lines, fmt.Sprintf(
			"[%s] %s — expiry: %s, residual: %d days, status: %s",
			r.Node, c.Name, c.Expiry.Format(time.RFC3339), c.ResidualDays, c.Status,
		))
	}
	return lines
}
