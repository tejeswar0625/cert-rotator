package controller

import (
	"context"
	"fmt"
	"hash/fnv"
	"os"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	certrotatorv1alpha1 "github.com/tejeswar0625/cert-rotator/api/v1alpha1"

	// All existing packages — filenames match exactly what's in pkg/
	"github.com/tejeswar0625/cert-rotator/pkg/backup"
	"github.com/tejeswar0625/cert-rotator/pkg/detector"
	"github.com/tejeswar0625/cert-rotator/pkg/generator"
	"github.com/tejeswar0625/cert-rotator/pkg/healthcheck"
	"github.com/tejeswar0625/cert-rotator/pkg/notifier"
	"github.com/tejeswar0625/cert-rotator/pkg/podrestart"
	"github.com/tejeswar0625/cert-rotator/pkg/rollback"
	"github.com/tejeswar0625/cert-rotator/pkg/signer"
	"github.com/tejeswar0625/cert-rotator/pkg/writer"
)

// CertRotationConfigReconciler reconciles a CertRotationConfig object.
// Each instance runs on one control plane node (DaemonSet) and manages
// only that node's certs. Node identity comes from MY_NODE_NAME env var
// injected via the downward API.
type CertRotationConfigReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	NodeName string
}

// +kubebuilder:rbac:groups=cert-rotator.tejeswar0625.dev,resources=certrotationconfigs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=cert-rotator.tejeswar0625.dev,resources=certrotationconfigs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=cert-rotator.tejeswar0625.dev,resources=certrotationconfigs/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch

func (r *CertRotationConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx).WithValues("node", r.NodeName)

	// --- 1. Fetch the CertRotationConfig CR ---
	cfg := &certrotatorv1alpha1.CertRotationConfig{}
	if err := r.Get(ctx, req.NamespacedName, cfg); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	spec := cfg.Spec
	log.Info("Reconcile started",
		"thresholdDays", spec.ThresholdDays,
		"dryRun", spec.DryRun,
		"checkIntervalHours", spec.CheckIntervalHours,
	)

	// --- 2. Check for Critical state — do not retry until manually cleared ---
	if nodeStatus, ok := cfg.Status.Nodes[r.NodeName]; ok {
		if nodeStatus.Phase == certrotatorv1alpha1.NodePhaseCritical {
			log.Error(nil, "Node is in CRITICAL state — manual intervention required. "+
				"Delete or patch status.nodes to clear before cert-rotator will retry.",
				"failureReason", nodeStatus.FailureReason,
				"backupPath", nodeStatus.BackupPath,
			)
			return ctrl.Result{RequeueAfter: 1 * time.Hour}, nil
		}
	}

	// --- 3. Run cert detection ---
	if err := r.setNodePhase(ctx, cfg, certrotatorv1alpha1.NodePhaseDetecting, ""); err != nil {
		return ctrl.Result{}, err
	}

	// detector.New(pkiDir, kubeconfigDir, thresholdDays) — matches detector.go signature
	det := detector.New(spec.PKIDir, spec.KubeconfigDir, spec.ThresholdDays)
	detResult, err := det.Detect(r.NodeName)
	if err != nil {
		log.Error(err, "Cert detection failed")
		if patchErr := r.setNodePhase(ctx, cfg, certrotatorv1alpha1.NodePhaseFailed,
			fmt.Sprintf("cert detection failed: %v", err)); patchErr != nil {
			log.Error(patchErr, "Failed to update node phase after detection error")
		}
		return ctrl.Result{RequeueAfter: r.requeueInterval(spec)}, nil
	}
	detResult.LogSummary()

	// --- 4. Update status with current cert expiry info ---
	now := metav1.Now()
	if err := r.updateNodeCertStatus(ctx, cfg, toCertStatuses(detResult), now); err != nil {
		return ctrl.Result{}, err
	}

	// --- 5. Nothing to do — go idle and requeue ---
	if !detResult.NeedsRenewal() {
		log.Info("All certs healthy — no renewal needed",
			"certsChecked", len(detResult.Certs),
		)
		if err := r.setNodePhase(ctx, cfg, certrotatorv1alpha1.NodePhaseIdle, ""); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.updateClusterConditions(ctx, cfg); err != nil {
			log.Error(err, "Failed to update cluster conditions")
		}
		return ctrl.Result{RequeueAfter: r.requeueWithJitter(spec)}, nil
	}

	// --- 6. Renewal needed ---
	log.Info("Cert renewal triggered",
		"urgent", detResult.IsUrgent(),
		"dryRun", spec.DryRun,
	)
	if err := r.setNodePhase(ctx, cfg, certrotatorv1alpha1.NodePhaseRenewing, ""); err != nil {
		return ctrl.Result{}, err
	}

	renewErr := r.runRenewal(ctx, cfg, spec, detResult)
	if renewErr != nil {
		log.Error(renewErr, "Renewal failed — initiating rollback")
		if err := r.setNodePhase(ctx, cfg, certrotatorv1alpha1.NodePhaseRollingBack, renewErr.Error()); err != nil {
			log.Error(err, "Failed to set RollingBack phase")
		}

		rollbackErr := r.runRollback(ctx, cfg, spec, renewErr)
		if rollbackErr != nil {
			criticalMsg := fmt.Sprintf(
				"CRITICAL: renewal failed (%v) AND rollback failed (%v). Manual intervention required.",
				renewErr, rollbackErr,
			)
			log.Error(rollbackErr, criticalMsg)
			if err := r.setNodePhase(ctx, cfg, certrotatorv1alpha1.NodePhaseCritical, criticalMsg); err != nil {
				log.Error(err, "Failed to set Critical phase")
			}
			r.sendCriticalAlert(cfg, spec, criticalMsg)
			if err := r.updateClusterConditions(ctx, cfg); err != nil {
				log.Error(err, "Failed to update cluster conditions after critical failure")
			}
			// Do not requeue — operator must manually clear the Critical state
			return ctrl.Result{}, nil
		}

		// Rollback succeeded
		if err := r.setNodePhase(ctx, cfg, certrotatorv1alpha1.NodePhaseFailed, renewErr.Error()); err != nil {
			log.Error(err, "Failed to set Failed phase after rollback")
		}
		r.sendRollbackNotification(cfg, spec, renewErr)
		if err := r.updateClusterConditions(ctx, cfg); err != nil {
			log.Error(err, "Failed to update cluster conditions after rollback")
		}
		return ctrl.Result{RequeueAfter: r.requeueWithJitter(spec)}, nil
	}

	// --- 7. Renewal succeeded ---
	log.Info("Cert renewal completed successfully")
	renewedAt := metav1.Now()
	if err := r.setNodeRenewed(ctx, cfg, renewedAt); err != nil {
		return ctrl.Result{}, err
	}
	r.sendRenewalSuccess(cfg, spec)
	if err := r.updateClusterConditions(ctx, cfg); err != nil {
		log.Error(err, "Failed to update cluster conditions after renewal")
	}
	return ctrl.Result{RequeueAfter: r.requeueWithJitter(spec)}, nil
}

// runRenewal executes the full renewal pipeline for this node.
func (r *CertRotationConfigReconciler) runRenewal(
	ctx context.Context,
	cfg *certrotatorv1alpha1.CertRotationConfig,
	spec certrotatorv1alpha1.CertRotationConfigSpec,
	detResult *detector.DetectionResult,
) error {
	log := log.FromContext(ctx).WithValues("node", r.NodeName)

	// Step 1: cert backup — backup.New(backupDir, pkiDir, kubeconfigDir)
	backupMgr := backup.New(spec.BackupDir, spec.PKIDir, spec.KubeconfigDir)
	b, err := backupMgr.Create(r.NodeName)
	if err != nil {
		return fmt.Errorf("cert backup failed: %w", err)
	}
	log.Info("Cert backup created", "backupPath", b.BackupPath)

	// Persist backup path to status immediately — needed for rollback if we crash
	if err := r.setNodeBackupPath(ctx, cfg, b.BackupPath); err != nil {
		return fmt.Errorf("persisting backup path to status: %w", err)
	}

	if spec.DryRun {
		log.Info("DRY RUN — skipping cert generation, signing, writing, and pod restart")
		return nil
	}

	// Step 2: generate and sign new certs for each cert that needs renewal
	gen := generator.New()
	sg := signer.New()
	certWriter := writer.New(spec.PKIDir, false)

	for _, certInfo := range detResult.Certs {
		if certInfo.Status == detector.StatusOK {
			continue
		}

		log.Info("Renewing certificate", "cert", certInfo.Name)

		// Load existing cert to mirror its SANs and key usages exactly
		existing, err := gen.LoadExistingCert(certInfo.Path)
		if err != nil {
			return fmt.Errorf("loading existing cert %s: %w", certInfo.Name, err)
		}

		// Route to correct CA for this cert type
		caCertPath, caKeyPath := signer.CAForCert(certInfo.Name)

		caCert, err := gen.LoadCACert(caCertPath)
		if err != nil {
			return fmt.Errorf("loading CA cert for %s: %w", certInfo.Name, err)
		}

		caKey, err := gen.LoadCAKey(caKeyPath)
		if err != nil {
			return fmt.Errorf("loading CA key for %s: %w", certInfo.Name, err)
		}

		// Generate new key + cert, sign with CA
		certPEM, keyPEM, err := sg.SignWithSelfKey(existing, caCert, caKey, gen)
		if err != nil {
			return fmt.Errorf("signing cert %s: %w", certInfo.Name, err)
		}

		// Look up file paths for this cert name
		paths, ok := writer.CertPaths[certInfo.Name]
		if !ok {
			return fmt.Errorf("unknown cert name: %s — no path mapping found", certInfo.Name)
		}

		if err := certWriter.WriteCertKeyPair(paths[0], paths[1], certPEM, keyPEM); err != nil {
			return fmt.Errorf("writing renewed cert %s: %w", certInfo.Name, err)
		}

		log.Info("Certificate renewed and written", "cert", certInfo.Name)
	}

	// Step 3: restart static pods — podrestart.New(manifestsDir, dryRun)
	restartMgr := podrestart.New(spec.ManifestsDir, false)
	if err := restartMgr.RestartAll(); err != nil {
		return fmt.Errorf("static pod restart failed: %w", err)
	}

	// Step 4: health check with retry — healthcheck.New(node, timeout, dryRun)
	timeout := time.Duration(spec.HealthCheckTimeoutSeconds) * time.Second
	checker := healthcheck.New(r.NodeName, timeout, false)
	if err := checker.CheckAllWithRetry(spec.HealthCheckMaxAttempts, 15*time.Second); err != nil {
		return fmt.Errorf("health check failed after cert renewal: %w", err)
	}

	return nil
}

// runRollback restores this node from its most recent cert backup.
func (r *CertRotationConfigReconciler) runRollback(
	ctx context.Context,
	cfg *certrotatorv1alpha1.CertRotationConfig,
	spec certrotatorv1alpha1.CertRotationConfigSpec,
	originalErr error,
) error {
	log := log.FromContext(ctx).WithValues("node", r.NodeName)

	nodeStatus, ok := cfg.Status.Nodes[r.NodeName]
	if !ok || nodeStatus.BackupPath == "" {
		return fmt.Errorf("no backup path in status for node %s — cannot roll back", r.NodeName)
	}

	backupPath := nodeStatus.BackupPath
	log.Info("Starting rollback from cert backup",
		"backupPath", backupPath,
		"originalError", originalErr.Error(),
	)

	// rollback.New(backupMgr, restartMgr, stateFile, dryRun) — matches rollback.go
	backupMgr := backup.New(spec.BackupDir, spec.PKIDir, spec.KubeconfigDir)
	restartMgr := podrestart.New(spec.ManifestsDir, spec.DryRun)
	rollbackMgr := rollback.New(backupMgr, restartMgr, "", spec.DryRun)

	timeout := time.Duration(spec.HealthCheckTimeoutSeconds) * time.Second

	// RollbackAll(renewedNodes, failedNode, state, healthTimeout)
	// State is nil here — backup path comes from CR status, not state.json
	results := rollbackMgr.RollbackAll([]string{}, r.NodeName, nil, timeout)
	if rollback.IsCritical(results) {
		return fmt.Errorf("rollback failed: %s", rollback.Summary(results, r.NodeName, originalErr.Error()))
	}

	// Verify health after rollback
	checker := healthcheck.New(r.NodeName, timeout, spec.DryRun)
	if err := checker.CheckAllWithRetry(spec.HealthCheckMaxAttempts, 15*time.Second); err != nil {
		return fmt.Errorf("node unhealthy after rollback: %w", err)
	}

	log.Info("Rollback completed — node restored to previous cert state", "backupPath", backupPath)
	return nil
}

// --- Status patch helpers ---

func (r *CertRotationConfigReconciler) setNodePhase(
	ctx context.Context,
	cfg *certrotatorv1alpha1.CertRotationConfig,
	phase certrotatorv1alpha1.NodePhase,
	failureReason string,
) error {
	patch := client.MergeFrom(cfg.DeepCopy())
	r.ensureNodes(cfg)
	ns := cfg.Status.Nodes[r.NodeName]
	ns.Phase = phase
	ns.Node = r.NodeName
	if failureReason != "" {
		ns.FailureReason = failureReason
	}
	cfg.Status.Nodes[r.NodeName] = ns
	return r.Status().Patch(ctx, cfg, patch)
}

func (r *CertRotationConfigReconciler) setNodeBackupPath(
	ctx context.Context,
	cfg *certrotatorv1alpha1.CertRotationConfig,
	backupPath string,
) error {
	patch := client.MergeFrom(cfg.DeepCopy())
	r.ensureNodes(cfg)
	ns := cfg.Status.Nodes[r.NodeName]
	ns.BackupPath = backupPath
	cfg.Status.Nodes[r.NodeName] = ns
	return r.Status().Patch(ctx, cfg, patch)
}

func (r *CertRotationConfigReconciler) setNodeRenewed(
	ctx context.Context,
	cfg *certrotatorv1alpha1.CertRotationConfig,
	renewedAt metav1.Time,
) error {
	patch := client.MergeFrom(cfg.DeepCopy())
	r.ensureNodes(cfg)
	ns := cfg.Status.Nodes[r.NodeName]
	ns.Phase = certrotatorv1alpha1.NodePhaseIdle
	ns.LastRenewedAt = &renewedAt
	ns.FailureReason = ""
	cfg.Status.Nodes[r.NodeName] = ns
	cfg.Status.LastRenewedAt = &renewedAt
	return r.Status().Patch(ctx, cfg, patch)
}

func (r *CertRotationConfigReconciler) updateNodeCertStatus(
	ctx context.Context,
	cfg *certrotatorv1alpha1.CertRotationConfig,
	certs []certrotatorv1alpha1.CertStatus,
	checkedAt metav1.Time,
) error {
	patch := client.MergeFrom(cfg.DeepCopy())
	r.ensureNodes(cfg)
	ns := cfg.Status.Nodes[r.NodeName]
	ns.Certs = certs
	ns.LastCheckedAt = &checkedAt
	cfg.Status.Nodes[r.NodeName] = ns
	cfg.Status.LastCheckedAt = &checkedAt
	return r.Status().Patch(ctx, cfg, patch)
}

func (r *CertRotationConfigReconciler) updateClusterConditions(
	ctx context.Context,
	cfg *certrotatorv1alpha1.CertRotationConfig,
) error {
	patch := client.MergeFrom(cfg.DeepCopy())

	healthy := true
	renewing := false
	critical := false

	for _, ns := range cfg.Status.Nodes {
		switch ns.Phase {
		case certrotatorv1alpha1.NodePhaseCritical:
			critical = true
			healthy = false
		case certrotatorv1alpha1.NodePhaseRenewing, certrotatorv1alpha1.NodePhaseRollingBack:
			renewing = true
		case certrotatorv1alpha1.NodePhaseFailed:
			healthy = false
		}
		for _, c := range ns.Certs {
			if c.Status != "OK" {
				healthy = false
			}
		}
	}

	now := metav1.Now()

	certsHealthyStatus := metav1.ConditionTrue
	certsHealthyReason := "AllCertsValid"
	certsHealthyMsg := "All control plane certs are valid across all nodes"
	if !healthy {
		certsHealthyStatus = metav1.ConditionFalse
		certsHealthyReason = "CertsExpiring"
		certsHealthyMsg = "One or more control plane certs are expiring or expired"
	}
	meta.SetStatusCondition(&cfg.Status.Conditions, metav1.Condition{
		Type:               certrotatorv1alpha1.ConditionCertsHealthy,
		Status:             certsHealthyStatus,
		Reason:             certsHealthyReason,
		Message:            certsHealthyMsg,
		LastTransitionTime: now,
	})

	renewalStatus := metav1.ConditionFalse
	renewalReason := "NoRenewalInProgress"
	renewalMsg := "No cert renewal is currently in progress"
	if renewing {
		renewalStatus = metav1.ConditionTrue
		renewalReason = "RenewalActive"
		renewalMsg = "Cert renewal is in progress on one or more nodes"
	}
	meta.SetStatusCondition(&cfg.Status.Conditions, metav1.Condition{
		Type:               certrotatorv1alpha1.ConditionRenewalInProgress,
		Status:             renewalStatus,
		Reason:             renewalReason,
		Message:            renewalMsg,
		LastTransitionTime: now,
	})

	criticalCondStatus := metav1.ConditionFalse
	criticalReason := "NoCriticalFailure"
	criticalMsg := "No critical failures detected"
	if critical {
		criticalCondStatus = metav1.ConditionTrue
		criticalReason = "RollbackFailed"
		criticalMsg = "Cert renewal AND rollback failed on one or more nodes — manual intervention required"
		cfg.Status.Phase = certrotatorv1alpha1.ClusterPhaseFailed
	} else if renewing {
		cfg.Status.Phase = certrotatorv1alpha1.ClusterPhaseRenewing
	} else {
		cfg.Status.Phase = certrotatorv1alpha1.ClusterPhaseIdle
	}
	meta.SetStatusCondition(&cfg.Status.Conditions, metav1.Condition{
		Type:               certrotatorv1alpha1.ConditionCriticalFailure,
		Status:             criticalCondStatus,
		Reason:             criticalReason,
		Message:            criticalMsg,
		LastTransitionTime: now,
	})

	return r.Status().Patch(ctx, cfg, patch)
}

func (r *CertRotationConfigReconciler) ensureNodes(cfg *certrotatorv1alpha1.CertRotationConfig) {
	if cfg.Status.Nodes == nil {
		cfg.Status.Nodes = make(map[string]certrotatorv1alpha1.NodeStatus)
	}
	if _, ok := cfg.Status.Nodes[r.NodeName]; !ok {
		cfg.Status.Nodes[r.NodeName] = certrotatorv1alpha1.NodeStatus{
			Node:  r.NodeName,
			Phase: certrotatorv1alpha1.NodePhaseIdle,
		}
	}
}

// --- Notification helpers ---
// notifier.New(smtpConfig, slackConfig) — matches notifier.go

func (r *CertRotationConfigReconciler) sendRenewalSuccess(
	cfg *certrotatorv1alpha1.CertRotationConfig,
	spec certrotatorv1alpha1.CertRotationConfigSpec,
) {
	n := r.buildNotifier(spec)
	if n == nil {
		return
	}
	_ = n.Notify(notifier.Event{
		Type:    notifier.EventRenewalSuccess,
		Node:    r.NodeName,
		Message: fmt.Sprintf("Node %s: cert renewal completed successfully", r.NodeName),
	})
}

func (r *CertRotationConfigReconciler) sendRollbackNotification(
	cfg *certrotatorv1alpha1.CertRotationConfig,
	spec certrotatorv1alpha1.CertRotationConfigSpec,
	originalErr error,
) {
	n := r.buildNotifier(spec)
	if n == nil {
		return
	}
	nodeStatus := cfg.Status.Nodes[r.NodeName]
	_ = n.Notify(notifier.Event{
		Type:    notifier.EventRollbackSuccess,
		Node:    r.NodeName,
		Message: fmt.Sprintf("Node %s: renewal failed (%v). Certs rolled back to %s. Investigate before next attempt.", r.NodeName, originalErr, nodeStatus.BackupPath),
	})
}

func (r *CertRotationConfigReconciler) sendCriticalAlert(
	cfg *certrotatorv1alpha1.CertRotationConfig,
	spec certrotatorv1alpha1.CertRotationConfigSpec,
	criticalMsg string,
) {
	n := r.buildNotifier(spec)
	if n == nil {
		return
	}
	n.NotifyCritical(notifier.Event{
		Type:    notifier.EventCritical,
		Node:    r.NodeName,
		Message: fmt.Sprintf("CRITICAL — Node %s: %s", r.NodeName, criticalMsg),
	})
}

func (r *CertRotationConfigReconciler) buildNotifier(spec certrotatorv1alpha1.CertRotationConfigSpec) *notifier.Notifier {
	return notifier.New(
		notifier.SMTPConfig{Enabled: spec.Notifications.SMTP.Enabled},
		notifier.SlackConfig{Enabled: spec.Notifications.Slack.Enabled},
	)
}

// --- Requeue helpers ---

// requeueWithJitter returns the check interval plus a deterministic per-node
// jitter (0-119s based on node name hash). Prevents all 3 control plane pods
// from reconciling at exactly the same wall clock second after fresh install.
func (r *CertRotationConfigReconciler) requeueWithJitter(spec certrotatorv1alpha1.CertRotationConfigSpec) time.Duration {
	base := time.Duration(spec.CheckIntervalHours) * time.Hour
	h := fnv.New32a()
	h.Write([]byte(r.NodeName))
	jitter := time.Duration(h.Sum32()%120) * time.Second
	return base + jitter
}

func (r *CertRotationConfigReconciler) requeueInterval(spec certrotatorv1alpha1.CertRotationConfigSpec) time.Duration {
	return time.Duration(spec.CheckIntervalHours) * time.Hour
}

// --- Conversion helpers ---

func toCertStatuses(result *detector.DetectionResult) []certrotatorv1alpha1.CertStatus {
	statuses := make([]certrotatorv1alpha1.CertStatus, 0, len(result.Certs))
	for _, c := range result.Certs {
		statuses = append(statuses, certrotatorv1alpha1.CertStatus{
			Name:         c.Name,
			ExpiryTime:   metav1.Time{Time: c.Expiry},
			ResidualDays: c.ResidualDays,
			Status:       string(c.Status),
		})
	}
	return statuses
}

// SetupWithManager registers the reconciler with controller-runtime.
func (r *CertRotationConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.NodeName == "" {
		return fmt.Errorf("NodeName must be set — inject MY_NODE_NAME via downward API")
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&certrotatorv1alpha1.CertRotationConfig{}).
		Complete(r)
}

// NodeNameFromEnv reads MY_NODE_NAME injected via the downward API.
func NodeNameFromEnv() (string, error) {
	name := os.Getenv("MY_NODE_NAME")
	if name == "" {
		return "", fmt.Errorf("MY_NODE_NAME environment variable not set")
	}
	return name, nil
}
