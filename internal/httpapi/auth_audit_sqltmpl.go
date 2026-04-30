package httpapi

import (
	"embed"
	"errors"
	"fmt"
	"sync"

	"github.com/arcgolabs/dbx"
	"github.com/arcgolabs/dbx/sqlstmt"
	"github.com/arcgolabs/dbx/sqltmpl"
)

//go:embed sql/auth_audit/*.sql
var authAuditSQLFS embed.FS

var authAuditRegistryCache sync.Map

type auditListQueryParams struct {
	Event        string
	UserID       string
	UsernameLike string
	ClientIPLike string
	From         *int64
	To           *int64
	Limit        int64
	Offset       int64
}

func toAuditListQueryParams(in normalizedAuditListInput) auditListQueryParams {
	params := auditListQueryParams{
		Event:  in.Event,
		UserID: in.UserID,
		Limit:  in.PageSize,
		Offset: (in.Page - 1) * in.PageSize,
	}
	if in.Username != "" {
		params.UsernameLike = "%" + in.Username + "%"
	}
	if in.ClientIP != "" {
		params.ClientIPLike = "%" + in.ClientIP + "%"
	}
	if in.From > 0 {
		params.From = &in.From
	}
	if in.To > 0 {
		params.To = &in.To
	}
	return params
}

func authAuditCountStatement(core *dbx.DB) (sqlstmt.Source, error) {
	registry, err := authAuditRegistry(core)
	if err != nil {
		return nil, err
	}
	return registry.Statement("sql/auth_audit/count.sql")
}

func authAuditListStatement(core *dbx.DB) (sqlstmt.Source, error) {
	registry, err := authAuditRegistry(core)
	if err != nil {
		return nil, err
	}
	return registry.Statement("sql/auth_audit/list.sql")
}

func authAuditRegistry(core *dbx.DB) (*sqltmpl.Registry, error) {
	if core == nil || core.Dialect() == nil {
		return nil, errors.New("db core not ready")
	}
	dialectName := core.Dialect().Name()
	if v, ok := authAuditRegistryCache.Load(dialectName); ok {
		return v.(*sqltmpl.Registry), nil
	}
	registry := sqltmpl.NewRegistry(authAuditSQLFS, core.Dialect())
	if _, err := registry.PreloadAll(); err != nil {
		return nil, fmt.Errorf("preload auth audit sql templates: %w", err)
	}
	actual, _ := authAuditRegistryCache.LoadOrStore(dialectName, registry)
	return actual.(*sqltmpl.Registry), nil
}
