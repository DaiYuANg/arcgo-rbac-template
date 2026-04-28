package httpapi

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/arcgolabs/arcgo-rbac-template/internal/authctx"
	"github.com/arcgolabs/authx"
	"github.com/DaiYuANg/arcgo/kvx"
	"github.com/arcgolabs/dbx"
	"github.com/arcgolabs/httpx"
	"github.com/danielgtaylor/huma/v2"
)

type MeEndpoint struct {
	engine *authx.Engine
	core   *dbx.DB
	cache  kvx.KV
	cachePrefix string
	cacheTTL    time.Duration
}

func (e *MeEndpoint) FiberBinding() FiberBinding {
	return FiberBinding{
		Prefix:  "/api/me",
		Handler: requireAuthFiber(e.engine),
	}
}

func (e *MeEndpoint) EndpointSpec() httpx.EndpointSpec {
	return httpx.EndpointSpec{
		Prefix:        "/api/me",
		Tags:          httpx.Tags("me"),
		SummaryPrefix: "Me",
		Description:   "Current principal endpoints",
	}
}

func (e *MeEndpoint) Register(registrar httpx.Registrar) {
	g := registrar.Scope()
	httpx.MustGroupGet(g, "", e.Get, func(op *huma.Operation) {
		op.Summary = "Get current principal"
	})
}

func (e *MeEndpoint) Get(ctx context.Context, _ *struct{}) (*MeResponse, error) {
	p, err := authctx.MustCurrent(ctx)
	if err != nil {
		return nil, err
	}
	uid := strings.TrimSpace(p.ID)

	// Optional cache: avoids recomputing role->permission joins.
	if e.cache != nil {
		key := strings.TrimSpace(e.cachePrefix) + "me:" + uid
		if raw, err := e.cache.Get(ctx, key); err == nil && len(raw) > 0 {
			var cached MeResponse
			if jsonErr := jsonUnmarshal(raw, &cached); jsonErr == nil && cached.ID != "" {
				return &cached, nil
			}
		}
	}

	name := uid
	email := ""
	if e.core != nil {
		row := e.core.SQLDB().QueryRowContext(ctx, fmt.Sprintf("SELECT name, email FROM iam_users WHERE id=%s", bind(e.core, 1)), uid)
		if err := row.Scan(&name, &email); err != nil && err != sql.ErrNoRows {
			return nil, httpx.NewError(500, "unknown", err)
		}
	}

	roleRefs := []RoleRef{}
	roleIDs := []string{}
	if e.core != nil {
		rows, err := e.core.SQLDB().QueryContext(ctx, fmt.Sprintf("SELECT role_id FROM iam_user_roles WHERE user_id=%s", bind(e.core, 1)), uid)
		if err == nil {
			for rows.Next() {
				var rid string
				if err := rows.Scan(&rid); err != nil {
					closeRows(rows)
					return nil, httpx.NewError(500, "unknown", err)
				}
				if strings.TrimSpace(rid) != "" {
					roleIDs = append(roleIDs, strings.TrimSpace(rid))
				}
			}
			if err := rows.Err(); err != nil {
				closeRows(rows)
				return nil, httpx.NewError(500, "unknown", err)
			}
			if err := rows.Close(); err != nil {
				return nil, httpx.NewError(500, "unknown", err)
			}
		}
	}
	// Fallback: use roles embedded in token if DB roles missing.
	if len(roleIDs) == 0 && p.Roles != nil {
		roleIDs = append(roleIDs, p.Roles.Values()...)
	}

	if e.core != nil && len(roleIDs) > 0 {
		for _, rid := range roleIDs {
			rid = strings.TrimSpace(rid)
			if rid == "" {
				continue
			}
			row := e.core.SQLDB().QueryRowContext(ctx, fmt.Sprintf("SELECT name FROM iam_roles WHERE id=%s", bind(e.core, 1)), rid)
			rname := rid
			if err := row.Scan(&rname); err != nil && err != sql.ErrNoRows {
				return nil, httpx.NewError(500, "unknown", err)
			}
			roleRefs = append(roleRefs, RoleRef{ID: rid, Name: rname})
		}
	} else {
		for _, rid := range roleIDs {
			rid = strings.TrimSpace(rid)
			if rid == "" {
				continue
			}
			roleRefs = append(roleRefs, RoleRef{ID: rid, Name: rid})
		}
	}

	// admin/管理员 => full access.
	for _, rr := range roleRefs {
		if rr.Name == "admin" || rr.Name == "管理员" {
			return &MeResponse{
				ID:    uid,
				Name:  name,
				Email: email,
				Roles: roleRefs,
				Permissions: []string{
					"users:read", "users:write",
					"roles:read", "roles:write",
					"permissions:read", "permissions:write",
					"permission-groups:read", "permission-groups:write",
				},
			}, nil
		}
	}

	perms := []string{}
	seen := map[string]bool{}
	if e.core != nil && len(roleIDs) > 0 {
		for _, rid := range roleIDs {
			rid = strings.TrimSpace(rid)
			if rid == "" {
				continue
			}
			// role -> groups
			grows, err := e.core.SQLDB().QueryContext(ctx, fmt.Sprintf("SELECT group_id FROM iam_role_permission_groups WHERE role_id=%s", bind(e.core, 1)), rid)
			if err != nil {
				continue
			}
			var gids []string
			for grows.Next() {
				var gid string
				if err := grows.Scan(&gid); err != nil {
					closeRows(grows)
					return nil, httpx.NewError(500, "unknown", err)
				}
				if strings.TrimSpace(gid) != "" {
					gids = append(gids, strings.TrimSpace(gid))
				}
			}
			if err := grows.Err(); err != nil {
				closeRows(grows)
				return nil, httpx.NewError(500, "unknown", err)
			}
			if err := grows.Close(); err != nil {
				return nil, httpx.NewError(500, "unknown", err)
			}
			for _, gid := range gids {
				// group -> perm ids
				prows, err := e.core.SQLDB().QueryContext(ctx, fmt.Sprintf("SELECT perm_id FROM iam_permission_group_permissions WHERE group_id=%s", bind(e.core, 1)), gid)
				if err != nil {
					continue
				}
				var pids []string
				for prows.Next() {
					var pid string
					if err := prows.Scan(&pid); err != nil {
						closeRows(prows)
						return nil, httpx.NewError(500, "unknown", err)
					}
					if strings.TrimSpace(pid) != "" {
						pids = append(pids, strings.TrimSpace(pid))
					}
				}
				if err := prows.Err(); err != nil {
					closeRows(prows)
					return nil, httpx.NewError(500, "unknown", err)
				}
				if err := prows.Close(); err != nil {
					return nil, httpx.NewError(500, "unknown", err)
				}
				for _, pid := range pids {
					row := e.core.SQLDB().QueryRowContext(ctx, fmt.Sprintf("SELECT code FROM iam_permissions WHERE id=%s", bind(e.core, 1)), pid)
					var code string
					if err := row.Scan(&code); err == nil {
						code = strings.TrimSpace(code)
						if code != "" && !seen[code] {
							seen[code] = true
							perms = append(perms, code)
						}
					}
				}
			}
		}
	}

	resp := &MeResponse{
		ID:          uid,
		Name:        name,
		Email:       email,
		Roles:       roleRefs,
		Permissions: perms,
	}

	if e.cache != nil {
		if bytes, err := jsonMarshal(resp); err == nil {
			ttl := e.cacheTTL
			if ttl <= 0 {
				ttl = 30 * time.Second
			}
			key := strings.TrimSpace(e.cachePrefix) + "me:" + uid
			if err := e.cache.Set(ctx, key, bytes, ttl); err != nil {
				slog.Default().Error("me cache set failed", "error", err)
			}
		}
	}
	return resp, nil
}

