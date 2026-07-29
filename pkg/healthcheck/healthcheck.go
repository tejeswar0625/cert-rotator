package healthcheck

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/tejeswar0625/cert-rotator/pkg/logger"
)

type component struct {
	name   string
	port   int
	path   string
	scheme string
}

var controlPlaneComponents = []component{
	{name: "etcd", port: 2379, path: "/health", scheme: "https"},
	{name: "kube-apiserver", port: 6443, path: "/healthz", scheme: "https"},
	{name: "kube-controller-manager", port: 10257, path: "/healthz", scheme: "https"},
	{name: "kube-scheduler", port: 10259, path: "/healthz", scheme: "https"},
}

type Checker struct {
	node    string
	timeout time.Duration
	dryRun  bool
}

func New(node string, timeout time.Duration, dryRun bool) *Checker {
	return &Checker{
		node:    node,
		timeout: timeout,
		dryRun:  dryRun,
	}
}

func (c *Checker) CheckAll() error {
	logger.Info("healthcheck", c.node,
		"Running health checks on all control plane components. "+
			"Each component is checked via TCP connection and HTTPS health endpoint.",
	)

	for _, comp := range controlPlaneComponents {
		if err := c.Check(comp); err != nil {
			return fmt.Errorf("health check failed for %s: %w", comp.name, err)
		}
	}
	return nil
}

func (c *Checker) CheckAllWithRetry(maxAttempts int, interval time.Duration) error {
	if c.dryRun {
		logger.Info("healthcheck", c.node,
			"DRY RUN — would health check all control plane components. Skipping actual checks.",
		)
		return nil
	}

	logger.Info("healthcheck", c.node,
		"Starting health check with retry. Static pods take time to restart after cert renewal — we retry to give them time to come back up.",
		slog.Int("max_attempts", maxAttempts),
		slog.String("retry_interval", interval.String()),
	)

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err := c.CheckAll()
		if err == nil {
			logger.Info("healthcheck", c.node,
				"All control plane components are healthy. Safe to proceed.",
				slog.Int("attempt", attempt),
				slog.Int("max_attempts", maxAttempts),
			)
			return nil
		}

		if attempt == maxAttempts {
			return fmt.Errorf("health check failed after %d attempts on %s: %w",
				maxAttempts, c.node, err)
		}

		logger.Warn("healthcheck", c.node,
			"Health check failed — components may still be restarting. Will retry.",
			slog.Int("attempt", attempt),
			slog.Int("max_attempts", maxAttempts),
			slog.String("error", err.Error()),
			slog.String("retry_in", interval.String()),
		)
		time.Sleep(interval)
	}

	return nil
}

func (c *Checker) Check(comp component) error {
	addr := fmt.Sprintf("%s:%d", c.node, comp.port)

	logger.Debug("healthcheck", c.node,
		"Checking component health.",
		slog.String("component", comp.name),
		slog.String("address", addr),
		slog.String("health_endpoint", fmt.Sprintf("%s://%s%s", comp.scheme, addr, comp.path)),
	)

	if err := c.tcpProbe(addr); err != nil {
		logger.Error("healthcheck", c.node,
			"TCP connection failed. The component process may not be running or the port is not open. "+
				"This could mean the static pod has not restarted yet after cert renewal.",
			err,
			slog.String("component", comp.name),
			slog.String("address", addr),
			slog.String("suggestion", "Wait a few seconds and retry — kubelet may still be recreating the pod"),
		)
		return fmt.Errorf("TCP probe failed for %s on %s: %w", comp.name, addr, err)
	}

	url := fmt.Sprintf("%s://%s%s", comp.scheme, addr, comp.path)
	if err := c.httpProbe(url); err != nil {
		logger.Error("healthcheck", c.node,
			"HTTP health check failed. The component is running but returning an unhealthy status. "+
				"This may indicate the component is still initialising with the new certificates.",
			err,
			slog.String("component", comp.name),
			slog.String("url", url),
			slog.String("suggestion", "Check component logs for certificate errors"),
		)
		return fmt.Errorf("HTTP probe failed for %s at %s: %w", comp.name, url, err)
	}

	logger.Info("healthcheck", c.node,
		"Component is healthy.",
		slog.String("component", comp.name),
		slog.String("address", addr),
	)
	return nil
}

func (c *Checker) tcpProbe(addr string) error {
	conn, err := net.DialTimeout("tcp", addr, c.timeout)
	if err != nil {
		return fmt.Errorf("cannot connect to %s: %w", addr, err)
	}
	conn.Close()
	return nil
}

func (c *Checker) httpProbe(url string) error {
	client := &http.Client{
		Timeout: c.timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec
				// TLS verification is intentionally skipped here.
				// We just rotated the certs so the new cert is what's being served.
				// We are checking liveness, not cert validity.
			},
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("HTTP GET %s failed: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unhealthy response from %s: HTTP %d", url, resp.StatusCode)
	}

	return nil
}

func (c *Checker) TCPOnlyCheck() error {
	if c.dryRun {
		logger.Info("healthcheck", c.node,
			"DRY RUN — would TCP check all components. Skipping.",
		)
		return nil
	}

	logger.Info("healthcheck", c.node,
		"Running TCP-only health check. Used when the cluster API may be down due to expired certs. "+
			"Checks if each component port is open — does not validate HTTP responses.",
	)

	for _, comp := range controlPlaneComponents {
		addr := fmt.Sprintf("%s:%d", c.node, comp.port)
		if err := c.tcpProbe(addr); err != nil {
			return fmt.Errorf("TCP check failed for %s on %s: %w", comp.name, addr, err)
		}
		logger.Info("healthcheck", c.node,
			"Component port is open.",
			slog.String("component", comp.name),
			slog.String("address", addr),
		)
	}
	return nil
}

type Result struct {
	Node       string
	Healthy    bool
	Components map[string]error
}

func (c *Checker) CheckAllDetailed() *Result {
	result := &Result{
		Node:       c.node,
		Healthy:    true,
		Components: make(map[string]error),
	}

	for _, comp := range controlPlaneComponents {
		err := c.Check(comp)
		result.Components[comp.name] = err
		if err != nil {
			result.Healthy = false
			logger.Error("healthcheck", c.node,
				"Component health check failed.",
				err,
				slog.String("component", comp.name),
			)
		}
	}

	if result.Healthy {
		logger.Info("healthcheck", c.node,
			"All components healthy.",
		)
	} else {
		logger.Error("healthcheck", c.node,
			"One or more components are unhealthy. Check component logs for details.",
			fmt.Errorf("unhealthy components detected on node %s", c.node),
		)
	}

	return result
}
