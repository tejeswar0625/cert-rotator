package state

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/tejeswar0625/cert-rotator/pkg/logger"
)

type Phase string

const (
	PhaseIdle       Phase = "IDLE"
	PhaseDetecting  Phase = "DETECTING"
	PhaseRenewingN1 Phase = "RENEWING_N1"
	PhaseRenewingN2 Phase = "RENEWING_N2"
	PhaseRenewingN3 Phase = "RENEWING_N3"
	PhaseRollbackN3 Phase = "ROLLBACK_N3"
	PhaseRollbackN2 Phase = "ROLLBACK_N2"
	PhaseRollbackN1 Phase = "ROLLBACK_N1"
	PhaseNotifying  Phase = "NOTIFYING"
)

type NodeState struct {
	Node           string    `json:"node"`
	BackupPath     string    `json:"backup_path"`
	RenewedAt      time.Time `json:"renewed_at,omitempty"`
	RolledBackAt   time.Time `json:"rolled_back_at,omitempty"`
	RenewalFailed  bool      `json:"renewal_failed"`
	RollbackFailed bool      `json:"rollback_failed"`
}

type State struct {
	Phase       Phase                `json:"phase"`
	StartedAt   time.Time            `json:"started_at"`
	UpdatedAt   time.Time            `json:"updated_at"`
	Nodes       map[string]NodeState `json:"nodes"`
	FailedNode  string               `json:"failed_node,omitempty"`
	FailureStep string               `json:"failure_step,omitempty"`
	Critical    bool                 `json:"critical"`
}

func New() *State {
	return &State{
		Phase: PhaseIdle,
		Nodes: make(map[string]NodeState),
	}
}

func Load(path string) (*State, error) {
	logger.Debug("state", "",
		"Loading state from disk. If an in-progress operation is found, cert-rotator will resume from where it left off.",
		slog.String("path", path),
	)

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Info("state", "",
				"No existing state file found. Starting fresh with IDLE state. This is normal on first run.",
				slog.String("path", path),
			)
			return New(), nil
		}
		return nil, err
	}

	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}

	logger.Info("state", "",
		"State loaded from disk.",
		slog.String("path", path),
		slog.String("phase", string(s.Phase)),
		slog.String("failed_node", s.FailedNode),
		slog.Bool("critical", s.Critical),
	)

	return &s, nil
}

func (s *State) Save(path string) error {
	s.UpdatedAt = time.Now()

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return err
	}

	logger.Debug("state", "",
		"State saved to disk.",
		slog.String("path", path),
		slog.String("phase", string(s.Phase)),
	)

	return nil
}

func (s *State) SetPhase(phase Phase, path string) error {
	logger.Info("state", "",
		"State transition.",
		slog.String("from", string(s.Phase)),
		slog.String("to", string(phase)),
		slog.String("explanation", phaseExplanation(phase)),
	)
	s.Phase = phase
	return s.Save(path)
}

func (s *State) SetNodeBackup(node, backupPath, statePath string) error {
	logger.Info("state", node,
		"Recording cert backup path in state. This path will be used to restore the node if renewal fails.",
		slog.String("backup_path", backupPath),
	)
	ns := s.Nodes[node]
	ns.Node = node
	ns.BackupPath = backupPath
	s.Nodes[node] = ns
	return s.Save(statePath)
}

func (s *State) SetNodeRenewed(node, statePath string) error {
	logger.Info("state", node,
		"Recording node as successfully renewed.",
	)
	ns := s.Nodes[node]
	ns.RenewedAt = time.Now()
	s.Nodes[node] = ns
	return s.Save(statePath)
}

func (s *State) SetNodeRollback(node string, failed bool, statePath string) error {
	ns := s.Nodes[node]
	ns.RolledBackAt = time.Now()
	ns.RollbackFailed = failed
	s.Nodes[node] = ns
	if failed {
		s.Critical = true
		logger.Critical("state", node,
			"Rollback failed on this node. Marking state as CRITICAL. "+
				"cert-rotator will fire unconditional alerts and will not re-enter the renewal loop until state is manually cleared.",
			fmt.Errorf("rollback failed on node %s", node),
		)
	} else {
		logger.Info("state", node,
			"Node rollback recorded as successful.",
			slog.String("rolled_back_at", ns.RolledBackAt.Format(time.RFC3339)),
		)
	}
	return s.Save(statePath)
}

func (s *State) IsInProgress() bool {
	return s.Phase != PhaseIdle
}

func (s *State) Reset(path string) error {
	logger.Info("state", "",
		"Resetting state to IDLE. All node state and failure information cleared.",
		slog.String("previous_phase", string(s.Phase)),
		slog.String("previous_failed_node", s.FailedNode),
	)
	s.Phase = PhaseIdle
	s.Nodes = make(map[string]NodeState)
	s.FailedNode = ""
	s.FailureStep = ""
	s.Critical = false
	s.StartedAt = time.Time{}
	return s.Save(path)
}

func phaseExplanation(phase Phase) string {
	switch phase {
	case PhaseIdle:
		return "No operation in progress. Waiting for next check interval."
	case PhaseDetecting:
		return "Checking certificate expiry on all control plane nodes."
	case PhaseRenewingN1:
		return "Renewing certificates on node 1."
	case PhaseRenewingN2:
		return "Renewing certificates on node 2."
	case PhaseRenewingN3:
		return "Renewing certificates on node 3."
	case PhaseRollbackN1:
		return "Rolling back node 1 to previous cert state."
	case PhaseRollbackN2:
		return "Rolling back node 2 to previous cert state."
	case PhaseRollbackN3:
		return "Rolling back node 3 to previous cert state."
	case PhaseNotifying:
		return "Sending notifications for completed operation."
	default:
		return "Unknown phase."
	}
}
