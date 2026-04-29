package httpapi

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/arcgolabs/authx"
	authjwt "github.com/arcgolabs/authx/jwt"
	collectionlist "github.com/arcgolabs/collectionx/list"
	"github.com/arcgolabs/dbx/mapper"
	"github.com/arcgolabs/dbx/sqlexec"
	"github.com/arcgolabs/dbx/sqlstmt"
	"github.com/arcgolabs/httpx"
	"github.com/golang-jwt/jwt/v5"
)

type auditLogsListInput struct {
	Authorization string `header:"Authorization"`
	Page          int64  `query:"page"`
	PageSize      int64  `query:"pageSize"`
	Event         string `query:"event"`
	UserID        string `query:"userId"`
	Username      string `query:"username"`
	ClientIP      string `query:"clientIp"`
	From          int64  `query:"from"`
	To            int64  `query:"to"`
}

type normalizedAuditListInput struct {
	Page     int64
	PageSize int64
	Event    string
	UserID   string
	Username string
	ClientIP string
	From     int64
	To       int64
}

func (e *AuthEndpoint) ListAuditLogs(ctx context.Context, in *auditLogsListInput) (*PageResponse[AuthAuditLogDTO], error) {
	if e.engine == nil {
		return nil, httpx.NewError(500, "auth_engine_missing")
	}
	if e.core == nil || e.core.SQLDB() == nil || e.core.Dialect() == nil {
		return &PageResponse[AuthAuditLogDTO]{Body: PagePayload[AuthAuditLogDTO]{Items: []AuthAuditLogDTO{}, Total: 0, Page: 1, PageSize: 20}}, nil
	}
	if _, err := e.authorizeAndEnforce(ctx, in.Authorization, "users:read", "/users"); err != nil {
		return nil, err
	}
	return e.listAuditLogs(ctx, normalizeAuditListInput(in))
}

func normalizeAuditListInput(in *auditLogsListInput) normalizedAuditListInput {
	if in == nil {
		return normalizedAuditListInput{Page: 1, PageSize: 20}
	}
	page := in.Page
	if page <= 0 {
		page = 1
	}
	pageSize := in.PageSize
	if pageSize <= 0 {
		pageSize = 20
	}
	pageSize = min(pageSize, 200)

	from := in.From
	to := in.To
	if from > 0 && to > 0 && to < from {
		from, to = to, from
	}
	return normalizedAuditListInput{
		Page:     page,
		PageSize: pageSize,
		Event:    strings.TrimSpace(in.Event),
		UserID:   strings.TrimSpace(in.UserID),
		Username: strings.TrimSpace(in.Username),
		ClientIP: strings.TrimSpace(in.ClientIP),
		From:     from,
		To:       to,
	}
}

func (e *AuthEndpoint) listAuditLogs(ctx context.Context, in normalizedAuditListInput) (*PageResponse[AuthAuditLogDTO], error) {
	countStmt := e.newAuditCountStatement()
	total, err := sqlexec.ScalarTyped[normalizedAuditListInput, int64](ctx, e.core, countStmt, in)
	if err != nil {
		return nil, httpx.NewError(500, "unknown", fmt.Errorf("count auth audits: %w", err))
	}

	listStmt := e.newAuditListStatement()
	rows, err := sqlexec.ListTyped[normalizedAuditListInput, authAuditLogRow](ctx, e.core, listStmt, in, mapper.MustStructMapper[authAuditLogRow]())
	if err != nil {
		return nil, httpx.NewError(500, "unknown", fmt.Errorf("query auth audits: %w", err))
	}
	items := make([]AuthAuditLogDTO, 0, in.PageSize)
	rows.Range(func(_ int, row authAuditLogRow) bool {
		items = append(items, row.toDTO())
		return true
	})

	return &PageResponse[AuthAuditLogDTO]{
		Body: PagePayload[AuthAuditLogDTO]{
			Items:    items,
			Total:    total,
			Page:     in.Page,
			PageSize: in.PageSize,
		},
	}, nil
}

func (e *AuthEndpoint) buildAuditWhere(in normalizedAuditListInput) (string, []any) {
	clauses := make([]string, 0, 6)
	args := make([]any, 0, 6)
	add := func(column string, op string, value any) {
		args = append(args, value)
		clauses = append(clauses, column+" "+op+" "+e.core.Dialect().BindVar(len(args)))
	}

	if in.Event != "" {
		add("event", "=", in.Event)
	}
	if in.UserID != "" {
		add("user_id", "=", in.UserID)
	}
	if in.Username != "" {
		add("username", "LIKE", "%"+in.Username+"%")
	}
	if in.ClientIP != "" {
		add("client_ip", "LIKE", "%"+in.ClientIP+"%")
	}
	if in.From > 0 {
		add("created_at", ">=", in.From)
	}
	if in.To > 0 {
		add("created_at", "<=", in.To)
	}
	if len(clauses) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

func (e *AuthEndpoint) newAuditCountStatement() sqlstmt.TypedSource[normalizedAuditListInput] {
	return sqlstmt.For[normalizedAuditListInput](sqlstmt.New("auth_audit_count", func(params any) (sqlstmt.Bound, error) {
		in, err := assertAuditParams(params)
		if err != nil {
			return sqlstmt.Bound{}, err
		}
		whereSQL, args := e.buildAuditWhere(in)
		return sqlstmt.Bound{
			Name: "auth_audit_count",
			SQL:  "SELECT COUNT(1) FROM auth_audit_logs" + whereSQL,
			Args: collectionlist.NewList(args...),
		}, nil
	}))
}

func (e *AuthEndpoint) newAuditListStatement() sqlstmt.TypedSource[normalizedAuditListInput] {
	return sqlstmt.For[normalizedAuditListInput](sqlstmt.New("auth_audit_list", func(params any) (sqlstmt.Bound, error) {
		in, err := assertAuditParams(params)
		if err != nil {
			return sqlstmt.Bound{}, err
		}
		whereSQL, args := e.buildAuditWhere(in)
		limitBind := e.core.Dialect().BindVar(len(args) + 1)
		offsetBind := e.core.Dialect().BindVar(len(args) + 2)
		sql := `SELECT event, user_id, username, client_ip, success, reason, created_at
		FROM auth_audit_logs` + whereSQL + ` ORDER BY created_at DESC LIMIT ` + limitBind + ` OFFSET ` + offsetBind
		bindArgs := append(cloneAny(args), in.PageSize, (in.Page-1)*in.PageSize)
		return sqlstmt.Bound{
			Name: "auth_audit_list",
			SQL:  sql,
			Args: collectionlist.NewList(bindArgs...),
		}, nil
	}))
}

func assertAuditParams(params any) (normalizedAuditListInput, error) {
	in, ok := params.(normalizedAuditListInput)
	if !ok {
		return normalizedAuditListInput{}, errors.New("invalid audit query params")
	}
	return in, nil
}

func cloneAny(xs []any) []any {
	out := make([]any, len(xs))
	copy(out, xs)
	return out
}

func (e *AuthEndpoint) authorizeAndEnforce(ctx context.Context, authorization, action, resource string) (authx.Principal, error) {
	bearer, err := parseBearerToken(authorization)
	if err != nil {
		return authx.Principal{}, httpx.NewError(401, "unauthorized")
	}
	res, err := e.engine.Check(ctx, authjwt.NewTokenCredential(bearer))
	if err != nil || res.Principal == nil {
		return authx.Principal{}, httpx.NewError(401, "unauthorized")
	}
	p, ok := res.Principal.(authx.Principal)
	if !ok || strings.TrimSpace(p.ID) == "" {
		return authx.Principal{}, httpx.NewError(401, "unauthorized")
	}
	if strings.TrimSpace(action) == "" {
		return p, nil
	}
	decision, err := e.engine.Can(ctx, authx.AuthorizationModel{
		Principal: p,
		Action:    action,
		Resource:  resource,
	})
	if err != nil {
		return authx.Principal{}, httpx.NewError(500, "unknown", err)
	}
	if !decision.Allowed {
		return authx.Principal{}, httpx.NewError(403, "forbidden")
	}
	return p, nil
}

func (e *AuthEndpoint) parseRefreshClaims(rawRefresh string) (authjwt.Claims, error) {
	claims := authjwt.Claims{}
	_, err := jwt.ParseWithClaims(rawRefresh, &claims, func(token *jwt.Token) (any, error) {
		return []byte(e.cfg.Auth.JWTSecret), nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}))
	if err != nil {
		return authjwt.Claims{}, fmt.Errorf("parse refresh token: %w", err)
	}
	return claims, nil
}

type authAuditLogRow struct {
	Event     string `dbx:"event"`
	UserID    string `dbx:"user_id"`
	Username  string `dbx:"username"`
	ClientIP  string `dbx:"client_ip"`
	Success   bool   `dbx:"success"`
	Reason    string `dbx:"reason"`
	CreatedAt int64  `dbx:"created_at"`
}

func (r authAuditLogRow) toDTO() AuthAuditLogDTO {
	return AuthAuditLogDTO{
		Event:            r.Event,
		UserID:           r.UserID,
		Username:         r.Username,
		ClientIP:         r.ClientIP,
		Success:          r.Success,
		Reason:           r.Reason,
		CreatedAt:        r.CreatedAt,
		CreatedAtRFC3339: unixMilliToRFC3339(r.CreatedAt),
	}
}
