package httpapi

import (
	"context"
	"log/slog"
	"time"

	"github.com/arcgolabs/dbx"
	"github.com/arcgolabs/httpx"
	"github.com/danielgtaylor/huma/v2"
)

type DashboardEndpoint struct {
	core *dbx.DB
}

func (e *DashboardEndpoint) EndpointSpec() httpx.EndpointSpec {
	return httpx.EndpointSpec{
		Prefix:        "/api/dashboard",
		Tags:          httpx.Tags("dashboard"),
		SummaryPrefix: "Dashboard",
		Description:   "Dashboard endpoints",
	}
}

func (e *DashboardEndpoint) Register(registrar httpx.Registrar) {
	g := registrar.Scope()
	httpx.MustGroupGet(g, "/stats", e.Stats, func(op *huma.Operation) {
		op.Summary = "Stats"
	})
}

func (e *DashboardEndpoint) Stats(ctx context.Context, _ *struct{}) (*JSONBody[DashboardStatsResponse], error) {
	out := &DashboardStatsResponse{}
	if e.core == nil {
		// still return shape; frontend treats this endpoint as optional.
		return wrapJSON(out), nil
	}

	var totalUsers int64
	if err := e.core.SQLDB().QueryRowContext(ctx, "SELECT COUNT(1) FROM iam_users").Scan(&totalUsers); err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	var totalRoles int64
	if err := e.core.SQLDB().QueryRowContext(ctx, "SELECT COUNT(1) FROM iam_roles").Scan(&totalRoles); err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	var totalPerms int64
	if err := e.core.SQLDB().QueryRowContext(ctx, "SELECT COUNT(1) FROM iam_permissions").Scan(&totalPerms); err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	var totalGroups int64
	if err := e.core.SQLDB().QueryRowContext(ctx, "SELECT COUNT(1) FROM iam_permission_groups").Scan(&totalGroups); err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}

	out.StatCards = append(out.StatCards,
		struct {
			Key      string `json:"key"`
			Value    int64  `json:"value"`
			LabelKey string `json:"labelKey"`
		}{Key: "totalUsers", Value: totalUsers, LabelKey: "dashboard.totalUsers"},
		struct {
			Key      string `json:"key"`
			Value    int64  `json:"value"`
			LabelKey string `json:"labelKey"`
		}{Key: "totalRoles", Value: totalRoles, LabelKey: "dashboard.totalRoles"},
		struct {
			Key      string `json:"key"`
			Value    int64  `json:"value"`
			LabelKey string `json:"labelKey"`
		}{Key: "totalPermissions", Value: totalPerms, LabelKey: "dashboard.totalPermissions"},
		struct {
			Key      string `json:"key"`
			Value    int64  `json:"value"`
			LabelKey string `json:"labelKey"`
		}{Key: "totalPermissionGroups", Value: totalGroups, LabelKey: "dashboard.totalPermissionGroups"},
	)

	// User activity: last 6 months (placeholder).
	now := time.Now().UTC()
	for i := 5; i >= 0; i-- {
		month := now.AddDate(0, -i, 0).Format("2006-01")
		out.UserActivity = append(out.UserActivity, struct {
			Month  string `json:"month"`
			Users  int64  `json:"users"`
			Logins int64  `json:"logins"`
		}{Month: month, Users: totalUsers, Logins: 0})
	}

	// Role distribution: count users per role (top 6).
	rows, err := e.core.SQLDB().QueryContext(ctx,
		`SELECT r.name, COUNT(ur.user_id) AS c
		 FROM iam_roles r
		 LEFT JOIN iam_user_roles ur ON ur.role_id = r.id
		 GROUP BY r.id, r.name
		 ORDER BY c DESC`)
	if err == nil {
		defer func() {
			if closeErr := rows.Close(); closeErr != nil {
				slog.Default().Error("dashboard rows close failed", "error", closeErr)
			}
		}()
		colors := []string{"var(--chart-1)", "var(--chart-2)", "var(--chart-3)", "var(--chart-4)", "var(--chart-5)", "var(--chart-6)"}
		colorIdx := 0
		for rows.Next() {
			var name string
			var c int64
			if scanErr := rows.Scan(&name, &c); scanErr != nil {
				continue
			}
			color := colors[colorIdx%len(colors)]
			colorIdx++
			out.RoleDistribution = append(out.RoleDistribution, struct {
				Name  string `json:"name"`
				Value int64  `json:"value"`
				Color string `json:"color"`
			}{Name: name, Value: c, Color: color})
			if len(out.RoleDistribution) >= 6 {
				break
			}
		}
	}

	// Permission groups summary: count permissions per group (by mapping table).
	grows, err := e.core.SQLDB().QueryContext(ctx,
		`SELECT g.name, COUNT(m.perm_id) AS c
		 FROM iam_permission_groups g
		 LEFT JOIN iam_permission_group_permissions m ON m.group_id = g.id
		 GROUP BY g.id, g.name
		 ORDER BY c DESC, g.name ASC`)
	if err == nil {
		defer func() {
			if closeErr := grows.Close(); closeErr != nil {
				slog.Default().Error("dashboard grows close failed", "error", closeErr)
			}
		}()
		for grows.Next() {
			var name string
			var c int64
			if scanErr := grows.Scan(&name, &c); scanErr != nil {
				continue
			}
			out.PermissionGroups = append(out.PermissionGroups, struct {
				Name  string `json:"name"`
				Count int64  `json:"count"`
			}{Name: name, Count: c})
		}
	}

	// Ensure non-nil slices for frontend.
	if out.StatCards == nil {
		out.StatCards = []struct {
			Key      string `json:"key"`
			Value    int64  `json:"value"`
			LabelKey string `json:"labelKey"`
		}{}
	}
	if out.UserActivity == nil {
		out.UserActivity = []struct {
			Month  string `json:"month"`
			Users  int64  `json:"users"`
			Logins int64  `json:"logins"`
		}{}
	}
	if out.RoleDistribution == nil {
		out.RoleDistribution = []struct {
			Name  string `json:"name"`
			Value int64  `json:"value"`
			Color string `json:"color"`
		}{}
	}
	if out.PermissionGroups == nil {
		out.PermissionGroups = []struct {
			Name  string `json:"name"`
			Count int64  `json:"count"`
		}{}
	}

	return wrapJSON(out), nil
}
