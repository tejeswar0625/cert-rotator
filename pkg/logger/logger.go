package logger

import (
	"log/slog"
	"os"
)

var log *slog.Logger

func init() {
	log = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.MessageKey {
				a.Key = "message"
			}
			return a
		},
	}))

	// Set as default logger
	slog.SetDefault(log)
}

// Info logs a normal operational message
func Info(component, node, msg string, args ...any) {
	fields := buildFields(component, node, args...)
	log.Info(msg, fields...)
}

// Debug logs detailed internal steps
func Debug(component, node, msg string, args ...any) {
	fields := buildFields(component, node, args...)
	log.Debug(msg, fields...)
}

// Warn logs unexpected but non-fatal conditions
func Warn(component, node, msg string, args ...any) {
	fields := buildFields(component, node, args...)
	log.Warn(msg, fields...)
}

// Error logs failures and actions taken in response
func Error(component, node, msg string, err error, args ...any) {
	fields := buildFields(component, node, args...)
	if err != nil {
		fields = append(fields, slog.String("error", err.Error()))
	}
	log.Error(msg, fields...)
}

// Critical logs P0 conditions — rollback failures, unrecoverable states
func Critical(component, node, msg string, err error, args ...any) {
	fields := buildFields(component, node, args...)
	fields = append(fields, slog.String("severity", "CRITICAL"))
	if err != nil {
		fields = append(fields, slog.String("error", err.Error()))
	}
	log.Error(msg, fields...)
}

// CertInfo logs cert-specific information
func CertInfo(component, node, certName, msg string, args ...any) {
	fields := []any{
		slog.String("component", component),
		slog.String("node", node),
		slog.String("cert", certName),
	}
	fields = append(fields, args...)
	log.Info(msg, fields...)
}

// Phase logs state machine transitions
func Phase(from, to, node string) {
	log.Info("State transition",
		slog.String("component", "orchestrator"),
		slog.String("node", node),
		slog.String("from", string(from)),
		slog.String("to", string(to)),
	)
}

func buildFields(component, node string, args ...any) []any {
	fields := []any{
		slog.String("component", component),
	}
	if node != "" {
		fields = append(fields, slog.String("node", node))
	}
	fields = append(fields, args...)
	return fields
}
