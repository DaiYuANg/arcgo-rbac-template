package httpapi

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/arcgolabs/dbx"
	columnx "github.com/arcgolabs/dbx/column"
	"github.com/arcgolabs/dbx/querydsl"
	schemax "github.com/arcgolabs/dbx/schema"
)

type authAuditSink interface {
	Write(authAuditRecord)
}

type authAuditRecord struct {
	Event    string
	UserID   string
	Username string
	ClientIP string
	Success  bool
	Reason   string
}

type noopAuthAuditSink struct{}

func (noopAuthAuditSink) Write(authAuditRecord) {}

type dbAuthAuditSink struct {
	core   *dbx.DB
	logger *slog.Logger
}

func newAuthAuditSink(core *dbx.DB, logger *slog.Logger) authAuditSink {
	if core == nil {
		return noopAuthAuditSink{}
	}
	return &dbAuthAuditSink{core: core, logger: logger}
}

func (s *dbAuthAuditSink) Write(rec authAuditRecord) {
	if s == nil || s.core == nil {
		return
	}
	insert := querydsl.InsertInto(AuthAuditLogs).Values(
		AuthAuditLogs.ID.Set(newAuthAuditID()),
		AuthAuditLogs.Event.Set(rec.Event),
		AuthAuditLogs.UserID.Set(strings.TrimSpace(rec.UserID)),
		AuthAuditLogs.Username.Set(strings.TrimSpace(rec.Username)),
		AuthAuditLogs.ClientIP.Set(strings.TrimSpace(rec.ClientIP)),
		AuthAuditLogs.Success.Set(rec.Success),
		AuthAuditLogs.Reason.Set(strings.TrimSpace(rec.Reason)),
		AuthAuditLogs.CreatedAt.Set(time.Now().UnixMilli()),
	)
	if _, err := dbx.Exec(context.Background(), s.core, insert); err != nil {
		logger := s.logger
		if logger == nil {
			logger = slog.Default()
		}
		logger.Warn("auth_audit_persist_failed", "error", err)
	}
}

func newAuthAuditID() string {
	token, err := randomToken(16)
	if err != nil {
		return fmt.Sprintf("audit-%d", time.Now().UnixNano())
	}
	return "audit-" + token
}

type authAuditLog struct {
	ID        string `dbx:"id"`
	Event     string `dbx:"event"`
	UserID    string `dbx:"user_id"`
	Username  string `dbx:"username"`
	ClientIP  string `dbx:"client_ip"`
	Success   bool   `dbx:"success"`
	Reason    string `dbx:"reason"`
	CreatedAt int64  `dbx:"created_at"`
}

type authAuditLogSchema struct {
	schemax.Schema[authAuditLog]
	ID        columnx.Column[authAuditLog, string] `dbx:"id,pk"`
	Event     columnx.Column[authAuditLog, string] `dbx:"event"`
	UserID    columnx.Column[authAuditLog, string] `dbx:"user_id"`
	Username  columnx.Column[authAuditLog, string] `dbx:"username"`
	ClientIP  columnx.Column[authAuditLog, string] `dbx:"client_ip"`
	Success   columnx.Column[authAuditLog, bool]   `dbx:"success"`
	Reason    columnx.Column[authAuditLog, string] `dbx:"reason"`
	CreatedAt columnx.Column[authAuditLog, int64]  `dbx:"created_at"`
}

var AuthAuditLogs = schemax.MustSchema("auth_audit_logs", authAuditLogSchema{})
