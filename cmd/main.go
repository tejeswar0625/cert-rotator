package main

import (
	"flag"
	"fmt"
	"os"

	// Import all Kubernetes client auth plugins
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	certrotatorv1alpha1 "github.com/tejeswar0625/cert-rotator/api/v1alpha1"
	"github.com/tejeswar0625/cert-rotator/internal/controller"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(certrotatorv1alpha1.AddToScheme(scheme))
}

func main() {
	var metricsAddr string
	var probeAddr string
	var enableLeaderElection bool

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080",
		"The address the metrics endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081",
		"The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election. Not needed for DaemonSet deployments — each pod is independent.")

	opts := zap.Options{Development: false}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// Read node name from downward API — this identifies which control plane
	// node this pod is running on and which certs it manages
	nodeName, err := controller.NodeNameFromEnv()
	if err != nil {
		setupLog.Error(err, "Failed to get node name from environment")
		os.Exit(1)
	}
	setupLog.Info("cert-rotator operator starting", "node", nodeName)

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr,
		},
		HealthProbeBindAddress: probeAddr,
		// Leader election is intentionally disabled by default.
		// This is a DaemonSet — each pod is the sole manager of its own node.
		// Leader election would incorrectly serialize what should be parallel
		// per-node reconciliation.
		LeaderElection: enableLeaderElection,
	})
	if err != nil {
		setupLog.Error(err, "Unable to start manager")
		os.Exit(1)
	}

	if err = (&controller.CertRotationConfigReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		NodeName: nodeName,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Unable to create controller", "controller", "CertRotationConfig")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "Unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "Unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("Starting manager", "node", nodeName)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "Problem running manager")
		os.Exit(1)
	}
}

// validateEnvironment checks required environment variables and host paths
// are accessible before starting the manager. Fails fast with a clear message.
func validateEnvironment(nodeName string) error {
	requiredEnvVars := []string{
		"MY_NODE_NAME",
	}
	for _, env := range requiredEnvVars {
		if os.Getenv(env) == "" {
			return fmt.Errorf("required environment variable %s is not set", env)
		}
	}

	// Validate hostPath mounts are accessible
	// These are mounted from the node via the DaemonSet spec
	requiredPaths := []string{
		"/etc/kubernetes/pki",
		"/etc/kubernetes/manifests",
	}
	for _, path := range requiredPaths {
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("required host path %s is not accessible: %w — check hostPath mounts in DaemonSet spec", path, err)
		}
	}

	return nil
}
