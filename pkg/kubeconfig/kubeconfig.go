package kubeconfig

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/tejeswar0625/cert-rotator/pkg/generator"
	"github.com/tejeswar0625/cert-rotator/pkg/logger"
	"github.com/tejeswar0625/cert-rotator/pkg/signer"
)

type kubeconfigFile struct {
	APIVersion     string    `yaml:"apiVersion"`
	Kind           string    `yaml:"kind"`
	Clusters       []cluster `yaml:"clusters"`
	Users          []user    `yaml:"users"`
	Contexts       []context `yaml:"contexts"`
	CurrentContext string    `yaml:"current-context"`
}

type cluster struct {
	Name    string      `yaml:"name"`
	Cluster clusterInfo `yaml:"cluster"`
}

type clusterInfo struct {
	Server                   string `yaml:"server"`
	CertificateAuthorityData string `yaml:"certificate-authority-data"`
}

type user struct {
	Name string   `yaml:"name"`
	User userInfo `yaml:"user"`
}

type userInfo struct {
	ClientCertificateData string `yaml:"client-certificate-data"`
	ClientKeyData         string `yaml:"client-key-data"`
}

type context struct {
	Name    string      `yaml:"name"`
	Context contextInfo `yaml:"context"`
}

type contextInfo struct {
	Cluster string `yaml:"cluster"`
	User    string `yaml:"user"`
}

var kubeconfigCerts = map[string]string{
	"admin.conf":              "kubernetes-admin",
	"controller-manager.conf": "system:kube-controller-manager",
	"scheduler.conf":          "system:kube-scheduler",
	"super-admin.conf":        "kubernetes-super-admin",
}

type Manager struct {
	kubeconfigDir string
	pkiDir        string
	dryRun        bool
	gen           *generator.Generator
	sig           *signer.Signer
}

func New(kubeconfigDir, pkiDir string, dryRun bool) *Manager {
	return &Manager{
		kubeconfigDir: kubeconfigDir,
		pkiDir:        pkiDir,
		dryRun:        dryRun,
		gen:           generator.New(),
		sig:           signer.New(),
	}
}

func (m *Manager) RenewAll() error {
	logger.Info("kubeconfig", "",
		"Renewing all kubeconfig files. These files embed client certificates used by "+
			"kubectl, controller-manager, and scheduler to authenticate to the Kubernetes API server. "+
			"They must be regenerated every time the cluster CA signs new certs.",
		slog.String("kubeconfig_dir", m.kubeconfigDir),
		slog.String("files", fmt.Sprintf("%v", getKeys(kubeconfigCerts))),
	)

	for filename, commonName := range kubeconfigCerts {
		if err := m.Renew(filename, commonName); err != nil {
			return fmt.Errorf("renewing kubeconfig %s: %w", filename, err)
		}
	}

	logger.Info("kubeconfig", "",
		"All kubeconfig files renewed successfully.",
	)
	return nil
}

func (m *Manager) Renew(filename, commonName string) error {
	fullPath := filepath.Join(m.kubeconfigDir, filename)

	logger.Info("kubeconfig", "",
		"Renewing kubeconfig file. A new client certificate will be generated for this identity and embedded in the kubeconfig.",
		slog.String("file", filename),
		slog.String("identity", commonName),
		slog.String("path", fullPath),
	)

	data, err := os.ReadFile(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Warn("kubeconfig", "",
				"Kubeconfig file not found — skipping. This is expected for super-admin.conf on older clusters.",
				slog.String("file", filename),
				slog.String("path", fullPath),
			)
			return nil
		}
		return fmt.Errorf("reading %s: %w", filename, err)
	}

	var kc kubeconfigFile
	if err := yaml.Unmarshal(data, &kc); err != nil {
		return fmt.Errorf("parsing %s: %w", filename, err)
	}

	if len(kc.Users) == 0 {
		return fmt.Errorf("no users found in %s", filename)
	}

	caCertPath := filepath.Join(m.pkiDir, "ca.crt")
	caKeyPath := filepath.Join(m.pkiDir, "ca.key")

	logger.Debug("kubeconfig", "",
		"Loading cluster CA to sign new kubeconfig client certificate.",
		slog.String("ca_cert", caCertPath),
		slog.String("ca_key", caKeyPath),
	)

	caCert, err := m.gen.LoadCACert(caCertPath)
	if err != nil {
		return fmt.Errorf("loading CA cert: %w", err)
	}

	caKey, err := m.gen.LoadCAKey(caKeyPath)
	if err != nil {
		return fmt.Errorf("loading CA key: %w", err)
	}

	certPEM, keyPEM, err := m.generateClientCert(commonName, caCert, caKey)
	if err != nil {
		return fmt.Errorf("generating client cert for %s: %w", commonName, err)
	}

	if m.dryRun {
		logger.Info("kubeconfig", "",
			"DRY RUN — would regenerate kubeconfig with new embedded client certificate. No changes made.",
			slog.String("file", filename),
			slog.String("identity", commonName),
		)
		return nil
	}

	kc.Users[0].User.ClientCertificateData = base64.StdEncoding.EncodeToString(certPEM)
	kc.Users[0].User.ClientKeyData = base64.StdEncoding.EncodeToString(keyPEM)

	updated, err := yaml.Marshal(&kc)
	if err != nil {
		return fmt.Errorf("marshalling updated %s: %w", filename, err)
	}

	info, err := os.Stat(fullPath)
	if err != nil {
		return fmt.Errorf("statting %s: %w", fullPath, err)
	}

	if err := os.WriteFile(fullPath, updated, info.Mode()); err != nil {
		return fmt.Errorf("writing updated %s: %w", filename, err)
	}

	logger.Info("kubeconfig", "",
		"Kubeconfig renewed successfully. The new client certificate has been embedded and the file written to disk.",
		slog.String("file", filename),
		slog.String("identity", commonName),
		slog.String("path", fullPath),
	)
	return nil
}

func (m *Manager) generateClientCert(commonName string, caCert *x509.Certificate, caKey *rsa.PrivateKey) (certPEM, keyPEM []byte, err error) {
	logger.Debug("kubeconfig", "",
		"Generating new client certificate for kubeconfig identity.",
		slog.String("identity", commonName),
		slog.String("organization", "system:masters"),
		slog.String("key_usage", "digital_signature + key_encipherment"),
		slog.String("ext_key_usage", "client_auth only — not server auth"),
	)

	newKey, err := m.gen.GenerateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("generating key: %w", err)
	}

	template, err := buildClientCertTemplate(commonName)
	if err != nil {
		return nil, nil, err
	}

	certDER, err := m.sig.Sign(template, caCert, caKey, &newKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM = m.gen.EncodeCertPEM(certDER)
	keyPEM = m.gen.EncodeKeyPEM(newKey)

	logger.Debug("kubeconfig", "",
		"Client certificate generated successfully.",
		slog.String("identity", commonName),
	)

	return certPEM, keyPEM, nil
}

func buildClientCertTemplate(commonName string) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generating serial: %w", err)
	}

	return &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"system:masters"},
		},
		NotBefore:             time.Now().Add(-10 * time.Minute),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}, nil
}

func getKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
