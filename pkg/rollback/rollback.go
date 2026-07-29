package rollback

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/tejeswar0625/cert-rotator/pkg/backup"
	"github.com/tejeswar0625/cert-rotator/pkg/healthcheck"
	"github.com/tejeswar0625/cert-rotator/pkg/logger"
	"github.com/tejeswar0625/cert-rotator/pkg/podrestart"
	"github.com/tejeswar0625/cert-rotator/state"
)

type RollbackResult struct {
	Node       string
	Success    bool
	Error      error
	RestoredAt time.Time
}

type Manager struct {
	backupMgr  *backup.Manager
	restartMgr *podrestart.Manager
	stateFile  string
	dryRun     bool
}

func New(
	backupMgr *backup.Manager,
	restartMgr *podrestart.Manager,
	stateFile string,
	dryRun bool,
) *Manager {
	return &Manager{
		backupMgr:  backupMgr,
		restartMgr: restartMgr,
		stateFile:  stateFile,
		dryRun:     dryRun,
	}
}

func (m *Manager) RollbackAll(
	renewedNodes []string,
	failedNode string,
	s *state.State,
	healthTimeout time.Duration,
) []RollbackResult {
	nodesToRollback := append([]string{failedNode}, reverse(renewedNodes)...)

	seen := make(map[string]bool)
	unique := make([]string, 0)
	for _, n := range nodesToRollback {
		if !seen[n] {
			seen[n] = true
			unique = append(unique, n)
		}
	}

	logger.Info("rollback", "",
		"Starting full cluster rollback. All nodes that were renewed will be restored to their previous cert state in reverse order. "+
			"This ensures the entire cluster is on the same cert version — no mixed states.",
		slog.String("failed_node", failedNode),
		slog.String("nodes_to_rollback", fmt.Sprintf("%v", unique)),
		slog.String("reason", "cert renewal or health check failed — reverting to safe state"),
	)

	results := make([]RollbackResult, 0)

	for _, node := range unique {
		logger.Info("rollback", node,
			"Rolling back node. Restoring cert backup, restarting static pods with old certs, and verifying health.",
		)

		result := m.rollbackNode(node, s, healthTimeout)
		results = append(results, result)

		failed := result.Error != nil
		if err := s.SetNodeRollback(node, failed, m.stateFile); err != nil {
			logger.Warn("rollback", node,
				"Could not update state file after rollback. State may be inconsistent on restart.",
				slog.String("error", err.Error()),
			)
		}

		if result.Error != nil {
			logger.Critical("rollback", node,
				"ROLLBACK FAILED on this node. The node may be in an inconsistent cert state. "+
					"Manual intervention is required. Check the backup path in state.json to restore manually.",
				result.Error,
				slog.String("backup_path", s.Nodes[node].BackupPath),
				slog.String("manual_restore", fmt.Sprintf("Copy files from %s back to /etc/kubernetes/pki/", s.Nodes[node].BackupPath)),
			)
		} else {
			logger.Info("rollback", node,
				"Node rolled back successfully. Previous certs restored and components are healthy.",
				slog.String("restored_at", result.RestoredAt.Format(time.RFC3339)),
			)
		}
	}

	return results
}

func (m *Manager) rollbackNode(node string, s *state.State, healthTimeout time.Duration) RollbackResult {
	result := RollbackResult{Node: node}

	nodeState, ok := s.Nodes[node]
	if !ok || nodeState.BackupPath == "" {
		result.Error = fmt.Errorf("no cert backup path found for node %s in state — cannot restore without a backup", node)
		logger.Error("rollback", node,
			"Cannot roll back — no cert backup path found in state.json. "+
				"This means the backup was not created before renewal started, or state.json was lost.",
			result.Error,
		)
		return result
	}

	if m.dryRun {
		logger.Info("rollback", node,
			"DRY RUN — would restore cert backup and restart static pods. No changes made.",
			slog.String("backup_path", nodeState.BackupPath),
		)
		result.Success = true
		result.RestoredAt = time.Now()
		return result
	}

	logger.Info("rollback", node,
		"Restoring cert backup files to /etc/kubernetes/pki/ and kubeconfig files.",
		slog.String("backup_path", nodeState.BackupPath),
	)

	if err := m.backupMgr.Restore(nodeState.BackupPath); err != nil {
		result.Error = fmt.Errorf("restoring cert backup for node %s: %w", node, err)
		logger.Error("rollback", node,
			"Failed to restore cert backup files. The node cert files may be in a partially written state.",
			result.Error,
			slog.String("backup_path", nodeState.BackupPath),
		)
		return result
	}

	logger.Info("rollback", node,
		"Cert backup restored. Restarting static pods so they pick up the restored certs.",
	)

	if err := m.restartMgr.RestartAll(); err != nil {
		result.Error = fmt.Errorf("restarting pods during rollback for node %s: %w", node, err)
		logger.Error("rollback", node,
			"Failed to restart static pods during rollback. Certs have been restored but pods may still be using new certs. Manual pod restart may be required.",
			result.Error,
		)
		return result
	}

	logger.Info("rollback", node,
		"Static pods restarted with restored certs. Running health check to confirm node is back to healthy state.",
	)

	checker := healthcheck.New(node, healthTimeout, m.dryRun)
	if err := checker.CheckAllWithRetry(10, 15*time.Second); err != nil {
		result.Error = fmt.Errorf("health check failed after rollback for node %s: %w", node, err)
		logger.Error("rollback", node,
			"Health check failed after rollback. The node may not have recovered correctly. "+
				"Check component logs and verify cert files manually.",
			result.Error,
			slog.String("backup_path", nodeState.BackupPath),
		)
		return result
	}

	result.Success = true
	result.RestoredAt = time.Now()
	return result
}

func IsCritical(results []RollbackResult) bool {
	for _, r := range results {
		if !r.Success {
			return true
		}
	}
	return false
}

func Summary(results []RollbackResult, failedNode, failureStep string) string {
	summary := fmt.Sprintf("Cert rotation failed on node %s at step: %s\n\n", failedNode, failureStep)
	summary += "Rollback results:\n"

	for _, r := range results {
		if r.Success {
			summary += fmt.Sprintf("  ✓ %s — rolled back successfully at %s\n",
				r.Node, r.RestoredAt.Format(time.RFC3339))
		} else {
			summary += fmt.Sprintf("  ✗ %s — ROLLBACK FAILED: %v\n", r.Node, r.Error)
		}
	}

	if IsCritical(results) {
		summary += "\nCRITICAL: One or more nodes failed to roll back.\n"
		summary += "Manual intervention required immediately.\n"
		summary += "Check cert backup paths in /var/lib/cert-rotator/state.json\n"
	} else {
		summary += "\nAll nodes restored to previous certs successfully.\n"
		summary += "Please investigate the failed node before the next renewal attempt.\n"
	}

	return summary
}

func reverse(nodes []string) []string {
	cp := make([]string, len(nodes))
	copy(cp, nodes)
	for i, j := 0, len(cp)-1; i < j; i, j = i+1, j-1 {
		cp[i], cp[j] = cp[j], cp[i]
	}
	return cp
}
