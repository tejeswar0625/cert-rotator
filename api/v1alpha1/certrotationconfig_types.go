package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Last Checked",type=string,JSONPath=`.status.lastCheckedAt`
// +kubebuilder:printcolumn:name="Last Renewed",type=string,JSONPath=`.status.lastRenewedAt`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// CertRotationConfig is the schema for the certrotationconfigs API.
// One instance is created per cluster (singleton pattern). Each control plane
// node's cert-rotator pod reconciles its own entry under status.nodes.
type CertRotationConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CertRotationConfigSpec   `json:"spec,omitempty"`
	Status CertRotationConfigStatus `json:"status,omitempty"`
}

// CertRotationConfigSpec defines the desired configuration for cert rotation.
type CertRotationConfigSpec struct {
	// ThresholdDays is the number of days before expiry at which renewal is triggered.
	// +kubebuilder:default=30
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=365
	ThresholdDays int `json:"thresholdDays,omitempty"`

	// CheckIntervalHours is how often each node checks cert expiry.
	// +kubebuilder:default=24
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=168
	CheckIntervalHours int `json:"checkIntervalHours,omitempty"`

	// DryRun logs what would happen without executing any renewal.
	// Cert backups are still taken in dry run mode for validation.
	// +kubebuilder:default=false
	DryRun bool `json:"dryRun,omitempty"`

	// BackupDir is where cert backups are stored on each control plane node.
	// +kubebuilder:default="/var/lib/cert-rotator/backups"
	BackupDir string `json:"backupDir,omitempty"`

	// BackupRetentionDays is how long to keep old cert backups on disk.
	// +kubebuilder:default=30
	// +kubebuilder:validation:Minimum=1
	BackupRetentionDays int `json:"backupRetentionDays,omitempty"`

	// PKIDir is the path to the Kubernetes PKI directory on the node.
	// +kubebuilder:default="/etc/kubernetes/pki"
	PKIDir string `json:"pkiDir,omitempty"`

	// KubeconfigDir is the path to the Kubernetes config directory on the node.
	// +kubebuilder:default="/etc/kubernetes"
	KubeconfigDir string `json:"kubeconfigDir,omitempty"`

	// ManifestsDir is the path to the static pod manifests directory on the node.
	// +kubebuilder:default="/etc/kubernetes/manifests"
	ManifestsDir string `json:"manifestsDir,omitempty"`

	// HealthCheckTimeoutSeconds is the timeout for each health check probe.
	// +kubebuilder:default=30
	// +kubebuilder:validation:Minimum=5
	HealthCheckTimeoutSeconds int `json:"healthCheckTimeoutSeconds,omitempty"`

	// HealthCheckMaxAttempts is the number of times to retry health checks
	// after static pod restart before declaring renewal failed.
	// +kubebuilder:default=10
	// +kubebuilder:validation:Minimum=1
	HealthCheckMaxAttempts int `json:"healthCheckMaxAttempts,omitempty"`

	// Notifications configures SMTP and Slack webhook alerts.
	// +optional
	Notifications NotificationSpec `json:"notifications,omitempty"`
}

// NotificationSpec configures notification channels.
type NotificationSpec struct {
	// SMTP configures email notifications.
	// +optional
	SMTP SMTPSpec `json:"smtp,omitempty"`

	// Slack configures Slack webhook notifications.
	// +optional
	Slack SlackSpec `json:"slack,omitempty"`
}

// SMTPSpec configures SMTP email notifications.
type SMTPSpec struct {
	// Enabled toggles SMTP notifications.
	Enabled bool `json:"enabled,omitempty"`

	// SecretRef is the name of a Secret in the operator namespace containing
	// keys: host, port, username, password, from, to
	// +optional
	SecretRef string `json:"secretRef,omitempty"`
}

// SlackSpec configures Slack webhook notifications.
type SlackSpec struct {
	// Enabled toggles Slack notifications.
	Enabled bool `json:"enabled,omitempty"`

	// SecretRef is the name of a Secret in the operator namespace containing
	// key: webhook_url
	// +optional
	SecretRef string `json:"secretRef,omitempty"`
}

// CertRotationConfigStatus defines the observed state of cert rotation
// across all control plane nodes.
type CertRotationConfigStatus struct {
	// Phase is the overall cluster-level phase.
	// +kubebuilder:validation:Enum=Idle;Renewing;Failed
	Phase ClusterPhase `json:"phase,omitempty"`

	// LastCheckedAt is when any node last ran detection.
	// +optional
	LastCheckedAt *metav1.Time `json:"lastCheckedAt,omitempty"`

	// LastRenewedAt is when any node last successfully completed renewal.
	// +optional
	LastRenewedAt *metav1.Time `json:"lastRenewedAt,omitempty"`

	// Nodes contains per-node cert rotation state.
	// Each control plane node's pod updates its own entry here.
	// +optional
	Nodes map[string]NodeStatus `json:"nodes,omitempty"`

	// Conditions reflects the overall health of cert rotation.
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// ClusterPhase is the overall phase across all nodes.
type ClusterPhase string

const (
	ClusterPhaseIdle     ClusterPhase = "Idle"
	ClusterPhaseRenewing ClusterPhase = "Renewing"
	ClusterPhaseFailed   ClusterPhase = "Failed"
)

// NodeStatus is the per-node cert rotation state written by each DaemonSet pod.
type NodeStatus struct {
	// Node is the name of the control plane node.
	Node string `json:"node"`

	// Phase is this node's current rotation phase.
	// +kubebuilder:validation:Enum=Idle;Detecting;Renewing;RollingBack;Failed;Critical
	Phase NodePhase `json:"phase"`

	// LastCheckedAt is when this node last ran cert detection.
	// +optional
	LastCheckedAt *metav1.Time `json:"lastCheckedAt,omitempty"`

	// LastRenewedAt is when this node last successfully completed cert renewal.
	// +optional
	LastRenewedAt *metav1.Time `json:"lastRenewedAt,omitempty"`

	// BackupPath is the path of the most recent cert backup on this node.
	// Used for rollback if renewal fails.
	// +optional
	BackupPath string `json:"backupPath,omitempty"`

	// FailureReason contains the error message if phase is Failed or Critical.
	// +optional
	FailureReason string `json:"failureReason,omitempty"`

	// Certs contains per-certificate expiry information for this node.
	// +optional
	Certs []CertStatus `json:"certs,omitempty"`
}

// NodePhase is the rotation phase for a single node.
type NodePhase string

const (
	NodePhaseIdle        NodePhase = "Idle"
	NodePhaseDetecting   NodePhase = "Detecting"
	NodePhaseRenewing    NodePhase = "Renewing"
	NodePhaseRollingBack NodePhase = "RollingBack"
	NodePhaseFailed      NodePhase = "Failed"
	NodePhaseCritical    NodePhase = "Critical"
)

// CertStatus holds expiry information for a single certificate on a node.
type CertStatus struct {
	// Name is the cert identifier (e.g. "apiserver", "etcd-server").
	Name string `json:"name"`

	// ExpiryTime is when this cert expires.
	ExpiryTime metav1.Time `json:"expiryTime"`

	// ResidualDays is days remaining until expiry (negative means already expired).
	ResidualDays int `json:"residualDays"`

	// Status is the classification: OK, APPROACHING, or EXPIRED.
	// +kubebuilder:validation:Enum=OK;APPROACHING;EXPIRED
	Status string `json:"status"`
}

// Condition type constants used in status.conditions.
const (
	// ConditionCertsHealthy is true when all certs on all nodes are OK.
	ConditionCertsHealthy = "CertsHealthy"

	// ConditionRenewalInProgress is true when any node is actively renewing.
	ConditionRenewalInProgress = "RenewalInProgress"

	// ConditionCriticalFailure is true when rollback failed on any node —
	// requires manual operator intervention.
	ConditionCriticalFailure = "CriticalFailure"
)

// +kubebuilder:object:root=true

// CertRotationConfigList contains a list of CertRotationConfig.
type CertRotationConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CertRotationConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(&CertRotationConfig{}, &CertRotationConfigList{})
}
