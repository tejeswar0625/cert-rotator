package notifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"github.com/tejeswar0625/cert-rotator/pkg/logger"
)

type EventType string

const (
	EventRenewalSuccess  EventType = "RENEWAL_SUCCESS"
	EventRenewalFailure  EventType = "RENEWAL_FAILURE"
	EventRollbackSuccess EventType = "ROLLBACK_SUCCESS"
	EventRollbackFailure EventType = "ROLLBACK_FAILURE"
	EventCertExpiring    EventType = "CERT_EXPIRING"
	EventCertExpired     EventType = "CERT_EXPIRED"
	EventCritical        EventType = "CRITICAL"
)

type Event struct {
	Type      EventType
	Node      string
	Timestamp time.Time
	Message   string
	Details   string
}

type SMTPConfig struct {
	Enabled  bool
	Host     string
	Port     int
	From     string
	To       []string
	Username string
	Password string
}

type SlackConfig struct {
	Enabled    bool
	WebhookURL string
}

type Notifier struct {
	smtp  SMTPConfig
	slack SlackConfig
}

func New(smtp SMTPConfig, slack SlackConfig) *Notifier {
	return &Notifier{
		smtp:  smtp,
		slack: slack,
	}
}

func (n *Notifier) Notify(event Event) error {
	event.Timestamp = time.Now().UTC()

	logger.Info("notifier", event.Node,
		"Sending notification for cert-rotator event.",
		slog.String("event_type", string(event.Type)),
		slog.Bool("smtp_enabled", n.smtp.Enabled),
		slog.Bool("slack_enabled", n.slack.Enabled),
		slog.String("message", event.Message),
	)

	var errs []string

	if n.smtp.Enabled {
		if err := n.sendSMTP(event); err != nil {
			errs = append(errs, fmt.Sprintf("SMTP: %v", err))
			logger.Error("notifier", event.Node,
				"Failed to send SMTP notification. Check SMTP configuration.",
				err,
				slog.String("smtp_host", n.smtp.Host),
			)
		}
	}

	if n.slack.Enabled {
		if err := n.sendSlack(event); err != nil {
			errs = append(errs, fmt.Sprintf("Slack: %v", err))
			logger.Error("notifier", event.Node,
				"Failed to send Slack notification. Check webhook URL configuration.",
				err,
			)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("notification errors: %s", strings.Join(errs, "; "))
	}

	return nil
}

func (n *Notifier) NotifyCritical(event Event) {
	event.Type = EventCritical
	event.Timestamp = time.Now().UTC()

	logger.Critical("notifier", event.Node,
		"CRITICAL ALERT — firing unconditionally via all channels regardless of notification config. "+
			"A rollback has failed and the node may be in an inconsistent cert state. Manual intervention required immediately.",
		fmt.Errorf("%s", event.Message),
		slog.String("details", event.Details),
	)

	// Fire SMTP unconditionally
	if err := n.sendSMTP(event); err != nil {
		logger.Error("notifier", event.Node,
			"CRITICAL: Failed to send SMTP alert. Check SMTP config immediately — the operator may not receive this alert.",
			err,
		)
	}

	// Fire Slack unconditionally
	if err := n.sendSlack(event); err != nil {
		logger.Error("notifier", event.Node,
			"CRITICAL: Failed to send Slack alert. Check webhook URL immediately — the operator may not receive this alert.",
			err,
		)
	}
}

func (n *Notifier) sendSMTP(event Event) error {
	if n.smtp.Host == "" || len(n.smtp.To) == 0 {
		return fmt.Errorf("SMTP not configured: missing host or recipients")
	}

	subject := formatSubject(event)
	body := formatBody(event)

	msg := []byte(fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s",
		n.smtp.From,
		strings.Join(n.smtp.To, ", "),
		subject,
		body,
	))

	addr := fmt.Sprintf("%s:%d", n.smtp.Host, n.smtp.Port)

	var auth smtp.Auth
	if n.smtp.Username != "" && n.smtp.Password != "" {
		auth = smtp.PlainAuth("", n.smtp.Username, n.smtp.Password, n.smtp.Host)
	}

	if err := smtp.SendMail(addr, auth, n.smtp.From, n.smtp.To, msg); err != nil {
		return fmt.Errorf("sending email: %w", err)
	}

	logger.Info("notifier", event.Node,
		"SMTP notification sent successfully.",
		slog.String("subject", subject),
		slog.String("to", strings.Join(n.smtp.To, ", ")),
	)
	return nil
}

func (n *Notifier) sendSlack(event Event) error {
	if n.slack.WebhookURL == "" {
		return fmt.Errorf("Slack webhook URL not configured")
	}

	payload := map[string]interface{}{
		"text": formatSlackMessage(event),
		"attachments": []map[string]interface{}{
			{
				"color":  slackColor(event.Type),
				"text":   event.Details,
				"footer": fmt.Sprintf("cert-rotator | %s", event.Timestamp.Format(time.RFC3339)),
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshalling slack payload: %w", err)
	}

	resp, err := http.Post(n.slack.WebhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("sending slack webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack webhook returned HTTP %d", resp.StatusCode)
	}

	logger.Info("notifier", event.Node,
		"Slack notification sent successfully.",
		slog.String("event_type", string(event.Type)),
	)
	return nil
}

func formatSubject(event Event) string {
	switch event.Type {
	case EventCritical:
		return fmt.Sprintf("[CRITICAL] cert-rotator: rollback failed on %s — manual intervention required", event.Node)
	case EventRenewalFailure:
		return fmt.Sprintf("[FAILURE] cert-rotator: renewal failed on %s", event.Node)
	case EventRollbackSuccess:
		return fmt.Sprintf("[ROLLBACK] cert-rotator: all nodes restored after failure on %s", event.Node)
	case EventRollbackFailure:
		return fmt.Sprintf("[CRITICAL] cert-rotator: rollback failed on %s — manual intervention required", event.Node)
	case EventRenewalSuccess:
		return "[SUCCESS] cert-rotator: control plane certs renewed successfully"
	case EventCertExpiring:
		return fmt.Sprintf("[WARNING] cert-rotator: control plane certs expiring soon on %s", event.Node)
	case EventCertExpired:
		return fmt.Sprintf("[URGENT] cert-rotator: control plane certs already expired on %s — immediate renewal triggered", event.Node)
	default:
		return fmt.Sprintf("[INFO] cert-rotator: %s", event.Type)
	}
}

func formatBody(event Event) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Event:     %s\n", event.Type))
	sb.WriteString(fmt.Sprintf("Node:      %s\n", event.Node))
	sb.WriteString(fmt.Sprintf("Timestamp: %s\n", event.Timestamp.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Message:   %s\n", event.Message))
	if event.Details != "" {
		sb.WriteString("\n--- Details ---\n")
		sb.WriteString(event.Details)
	}
	sb.WriteString("\n\n-- cert-rotator")
	return sb.String()
}

func formatSlackMessage(event Event) string {
	icon := slackIcon(event.Type)
	return fmt.Sprintf("%s *cert-rotator* | `%s` | Node: `%s`\n%s",
		icon, event.Type, event.Node, event.Message)
}

func slackColor(eventType EventType) string {
	switch eventType {
	case EventRenewalSuccess, EventRollbackSuccess:
		return "good"
	case EventCertExpiring:
		return "warning"
	case EventRenewalFailure, EventRollbackFailure, EventCritical, EventCertExpired:
		return "danger"
	default:
		return "#439FE0"
	}
}

func slackIcon(eventType EventType) string {
	switch eventType {
	case EventRenewalSuccess:
		return ":white_check_mark:"
	case EventRollbackSuccess:
		return ":arrows_counterclockwise:"
	case EventCertExpiring:
		return ":warning:"
	case EventCritical, EventRollbackFailure:
		return ":rotating_light:"
	case EventRenewalFailure:
		return ":x:"
	case EventCertExpired:
		return ":skull:"
	default:
		return ":information_source:"
	}
}
