package httpapi

import (
	"context"
	"fmt"
	"time"

	"github.com/arcgolabs/arcgo-rbac-template/internal/db/iamrepo"
	collectionlist "github.com/arcgolabs/collectionx/list"
	"github.com/arcgolabs/dbx"
	"github.com/arcgolabs/dbx/mapper"
	"github.com/arcgolabs/dbx/querydsl"
	"github.com/arcgolabs/httpx"
	"github.com/danielgtaylor/huma/v2"
)

type DashboardEndpoint struct {
	core *dbx.DB
}

type dashboardCountRow struct {
	Total int64 `dbx:"total"`
}

type dashboardRoleDistributionRow struct {
	Name  string `dbx:"name"`
	Value int64  `dbx:"value"`
}

type dashboardPermissionGroupRow struct {
	Name  string `dbx:"name"`
	Count int64  `dbx:"count"`
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

	totalUsers, err := e.countTable(ctx, iamrepo.Users)
	if err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	totalRoles, err := e.countTable(ctx, iamrepo.Roles)
	if err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	totalPerms, err := e.countTable(ctx, iamrepo.Permissions)
	if err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	totalGroups, err := e.countTable(ctx, iamrepo.PermissionGroups)
	if err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}

	out.StatCards = append(out.StatCards,
		DashboardStatCard{Key: "totalUsers", Value: totalUsers, LabelKey: "dashboard.totalUsers"},
		DashboardStatCard{Key: "totalRoles", Value: totalRoles, LabelKey: "dashboard.totalRoles"},
		DashboardStatCard{Key: "totalPermissions", Value: totalPerms, LabelKey: "dashboard.totalPermissions"},
		DashboardStatCard{Key: "totalPermissionGroups", Value: totalGroups, LabelKey: "dashboard.totalPermissionGroups"},
	)

	// User activity: last 6 months (placeholder).
	now := time.Now().UTC()
	for i := 5; i >= 0; i-- {
		month := now.AddDate(0, -i, 0).Format("2006-01")
		out.UserActivity = append(out.UserActivity, DashboardUserActivityPoint{Month: month, Users: totalUsers, Logins: 0})
	}

	// Role distribution: count users per role (top 6).
	roleRows, err := e.listRoleDistribution(ctx)
	if err == nil {
		colors := []string{"var(--chart-1)", "var(--chart-2)", "var(--chart-3)", "var(--chart-4)", "var(--chart-5)", "var(--chart-6)"}
		roleRows.Range(func(i int, row dashboardRoleDistributionRow) bool {
			out.RoleDistribution = append(out.RoleDistribution, DashboardRoleDistributionItem{
				Name:  row.Name,
				Value: row.Value,
				Color: colors[i%len(colors)],
			})
			return true
		})
	}

	// Permission groups summary: count permissions per group (by mapping table).
	groupRows, err := e.listPermissionGroups(ctx)
	if err == nil {
		groupRows.Range(func(_ int, row dashboardPermissionGroupRow) bool {
			out.PermissionGroups = append(out.PermissionGroups, DashboardPermissionGroupSummary(row))
			return true
		})
	}

	// Ensure non-nil slices for frontend.
	if out.StatCards == nil {
		out.StatCards = []DashboardStatCard{}
	}
	if out.UserActivity == nil {
		out.UserActivity = []DashboardUserActivityPoint{}
	}
	if out.RoleDistribution == nil {
		out.RoleDistribution = []DashboardRoleDistributionItem{}
	}
	if out.PermissionGroups == nil {
		out.PermissionGroups = []DashboardPermissionGroupSummary{}
	}

	return wrapJSON(out), nil
}

func (e *DashboardEndpoint) countTable(ctx context.Context, source querydsl.TableSource) (int64, error) {
	q := querydsl.Select(querydsl.CountAll().As("total")).From(source)
	items, err := dbx.QueryAll[dashboardCountRow](ctx, e.core, q, mapper.MustStructMapper[dashboardCountRow]())
	if err != nil {
		return 0, fmt.Errorf("dashboard count query: %w", err)
	}
	if items == nil || items.Len() == 0 {
		return 0, nil
	}
	first, _ := items.Get(0)
	return first.Total, nil
}

func (e *DashboardEndpoint) listRoleDistribution(ctx context.Context) (*collectionlist.List[dashboardRoleDistributionRow], error) {
	userCount := querydsl.Count(iamrepo.UserRoles.UserID)
	q := querydsl.
		Select(
			iamrepo.Roles.Name.As("name"),
			userCount.As("value"),
		).
		From(iamrepo.Roles).
		LeftJoin(iamrepo.UserRoles).On(iamrepo.UserRoles.RoleID.EqColumn(iamrepo.Roles.ID)).
		GroupBy(iamrepo.Roles.ID, iamrepo.Roles.Name).
		OrderBy(userCount.Desc()).
		Limit(6)
	items, err := dbx.QueryAll[dashboardRoleDistributionRow](ctx, e.core, q, mapper.MustStructMapper[dashboardRoleDistributionRow]())
	if err != nil {
		return nil, fmt.Errorf("dashboard role distribution query: %w", err)
	}
	return items, nil
}

func (e *DashboardEndpoint) listPermissionGroups(ctx context.Context) (*collectionlist.List[dashboardPermissionGroupRow], error) {
	permCount := querydsl.Count(iamrepo.PermissionGroupPermissions.PermID)
	q := querydsl.
		Select(
			iamrepo.PermissionGroups.Name.As("name"),
			permCount.As("count"),
		).
		From(iamrepo.PermissionGroups).
		LeftJoin(iamrepo.PermissionGroupPermissions).On(
		iamrepo.PermissionGroupPermissions.GroupID.EqColumn(iamrepo.PermissionGroups.ID),
	).
		GroupBy(iamrepo.PermissionGroups.ID, iamrepo.PermissionGroups.Name).
		OrderBy(permCount.Desc(), iamrepo.PermissionGroups.Name.Asc())
	items, err := dbx.QueryAll[dashboardPermissionGroupRow](ctx, e.core, q, mapper.MustStructMapper[dashboardPermissionGroupRow]())
	if err != nil {
		return nil, fmt.Errorf("dashboard permission group query: %w", err)
	}
	return items, nil
}
