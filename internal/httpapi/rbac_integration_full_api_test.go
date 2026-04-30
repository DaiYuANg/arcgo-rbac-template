//nolint:testpackage // Integration tests need unexported endpoint/test setup helpers.
package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/arcgolabs/arcgo-rbac-template/internal/config"
	"github.com/arcgolabs/arcgo-rbac-template/internal/db/iamrepo"
	iamservice "github.com/arcgolabs/arcgo-rbac-template/internal/iam/application/service"
	"github.com/arcgolabs/arcgo-rbac-template/internal/testutil"
	"github.com/arcgolabs/httpx"
	adapter "github.com/arcgolabs/httpx/adapter"
	adapterfiber "github.com/arcgolabs/httpx/adapter/fiber"
	"github.com/gofiber/fiber/v2"
)

func setupFullRBACApp(t *testing.T, grantAllReadPermissions bool) (*fiber.App, func()) {
	t.Helper()

	core, _, cleanupDB := testutil.MustMigratingDB(t)
	testutil.SeedReaderUserAlice(t, core.SQLDB(), "integration-secret")
	if grantAllReadPermissions {
		grantRolePermissions(t, core.SQLDB(), testutil.TestRoleReader,
			"users:read",
			"roles:read",
			"permissions:read",
			"permission-groups:read",
		)
	}

	cfg := config.Config{Auth: testutil.DefaultIntegrationAuth()}
	userRepo := iamrepo.NewUserRepo(core)
	roleRepo := iamrepo.NewRoleRepo(core)
	groupRepo := iamrepo.NewPermissionGroupRepo(core)
	permRepo := iamrepo.NewPermissionRepo(core)

	eng := testutil.MustAuthEngine(t, cfg, core, userRepo, roleRepo)
	meSvc := iamservice.NewMeService(userRepo, roleRepo, groupRepo, permRepo)
	usersSvc := iamservice.NewUsersService(userRepo)
	rolesSvc := iamservice.NewRolesService(roleRepo)
	permsSvc := iamservice.NewPermissionsService(permRepo)
	groupSvc := iamservice.NewPermissionGroupsService(groupRepo)

	authLogger := slog.New(slog.DiscardHandler)
	authEp := &AuthEndpoint{
		cfg:       cfg,
		engine:    eng,
		cache:     nil,
		core:      core,
		logger:    authLogger,
		auditSink: newAuthAuditSink(core, authLogger),
	}
	meEp := &MeEndpoint{engine: eng, svc: meSvc, cache: nil, cachePrefix: "", cacheTTL: time.Minute}
	usersEp := &UsersResource{engine: eng, svc: usersSvc, cacheTTL: time.Minute}
	rolesEp := &RolesResource{engine: eng, svc: rolesSvc}
	permsEp := &PermissionsResource{engine: eng, svc: permsSvc}
	groupsEp := &PermissionGroupsResource{engine: eng, svc: groupSvc}
	healthEp := &HealthEndpoint{}
	dashboardEp := &DashboardEndpoint{core: core}

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	ad := adapterfiber.New(app, adapter.HumaOptions{
		Title:       "rbac-full-test",
		Version:     "0.0.1",
		Description: "integration",
		DocsPath:    "/docs",
		OpenAPIPath: "/openapi.json",
	})

	srv := httpx.New(
		httpx.WithAdapter(ad),
		httpx.WithLogger(slog.New(slog.DiscardHandler)),
		httpx.WithValidation(),
	)

	RegisterFiberBindings(app, meEp, usersEp, rolesEp, permsEp, groupsEp)
	srv.Register(authEp)
	srv.Register(healthEp)
	srv.Register(dashboardEp)
	srv.Register(meEp)
	srv.Register(usersEp)
	srv.Register(rolesEp)
	srv.Register(permsEp)
	srv.Register(groupsEp)

	return app, cleanupDB
}

func grantRolePermissions(t *testing.T, sqlDB *sql.DB, roleID string, permissions ...string) {
	t.Helper()

	ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
	ctx := context.Background()
	tx, err := sqlDB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() {
		if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
			t.Fatalf("rollback: %v", rbErr)
		}
	}()

	for _, code := range permissions {
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO iam_permissions (id, name, code, created_at) VALUES (?, ?, ?, ?)`,
			code, code, code, ts,
		); err != nil {
			t.Fatalf("insert permission %q: %v", code, err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO iam_role_permissions (role_id, perm_id) VALUES (?, ?)`,
			roleID, code,
		); err != nil {
			t.Fatalf("grant permission %q to role %q: %v", code, roleID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		t.Fatalf("commit tx: %v", err)
	}
}

func loginReaderToken(t *testing.T, app *fiber.App) string {
	t.Helper()

	loginBody := map[string]string{
		"username": testutil.TestUserAlice,
		"password": "integration-secret",
	}
	loginRes := testutil.FiberDoJSONDetailed(t, app, "POST", "/api/auth/login", loginBody, nil)
	if loginRes.StatusCode != http.StatusOK {
		t.Fatalf("login status %d body %s", loginRes.StatusCode, string(loginRes.Body))
	}
	var token struct {
		AccessToken string `json:"accessToken"`
	}
	if err := json.Unmarshal(loginRes.Body, &token); err != nil {
		t.Fatalf("login json: %v", err)
	}
	if token.AccessToken == "" {
		t.Fatalf("missing access token")
	}
	return token.AccessToken
}

func TestIntegration_FullAPI_ReadEndpointMatrix(t *testing.T) {
	t.Parallel()

	app, cleanup := setupFullRBACApp(t, true)
	defer cleanup()
	token := loginReaderToken(t, app)
	authHeader := map[string]string{"Authorization": "Bearer " + token}

	cases := []struct {
		name    string
		method  string
		path    string
		headers map[string]string
	}{
		{name: "health", method: "GET", path: "/api/health"},
		{name: "dashboard", method: "GET", path: "/api/dashboard/stats"},
		{name: "me", method: "GET", path: "/api/me", headers: authHeader},
		{name: "users list", method: "GET", path: "/api/users?page=1&pageSize=10", headers: authHeader},
		{name: "roles list", method: "GET", path: "/api/roles?page=1&pageSize=10", headers: authHeader},
		{name: "permissions list", method: "GET", path: "/api/permissions?page=1&pageSize=10", headers: authHeader},
		{name: "permission groups list", method: "GET", path: "/api/permission-groups?page=1&pageSize=10", headers: authHeader},
		{name: "audit logs", method: "GET", path: "/api/auth/audit-logs?page=1&pageSize=10", headers: authHeader},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := testutil.FiberDoJSONDetailed(t, app, tc.method, tc.path, nil, tc.headers)
			if res.StatusCode != http.StatusOK {
				t.Fatalf("%s %s => %d body=%s", tc.method, tc.path, res.StatusCode, string(res.Body))
			}
		})
	}
}

func TestIntegration_FullAPI_ProtectedEndpointsRequireAuth(t *testing.T) {
	t.Parallel()

	app, cleanup := setupFullRBACApp(t, true)
	defer cleanup()

	cases := []struct {
		name   string
		method string
		path   string
		body   any
	}{
		{name: "me", method: "GET", path: "/api/me"},
		{name: "users list", method: "GET", path: "/api/users?page=1&pageSize=10"},
		{name: "roles list", method: "GET", path: "/api/roles?page=1&pageSize=10"},
		{name: "permissions list", method: "GET", path: "/api/permissions?page=1&pageSize=10"},
		{name: "permission groups list", method: "GET", path: "/api/permission-groups?page=1&pageSize=10"},
		{name: "audit logs", method: "GET", path: "/api/auth/audit-logs?page=1&pageSize=10"},
		{name: "logout all", method: "POST", path: "/api/auth/logout-all", body: map[string]any{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := testutil.FiberDoJSONDetailed(t, app, tc.method, tc.path, tc.body, nil)
			if res.StatusCode != http.StatusUnauthorized {
				t.Fatalf("%s %s => %d body=%s", tc.method, tc.path, res.StatusCode, string(res.Body))
			}
		})
	}
}

func TestIntegration_FullAPI_WritePermissionDeniedMatrix(t *testing.T) {
	t.Parallel()

	app, cleanup := setupFullRBACApp(t, true)
	defer cleanup()
	token := loginReaderToken(t, app)
	authHeader := map[string]string{"Authorization": "Bearer " + token}

	cases := []struct {
		name   string
		method string
		path   string
		body   any
	}{
		{name: "users create", method: "POST", path: "/api/users", body: map[string]any{"id": "u-test", "email": "u@test.local", "name": "U Test"}},
		{name: "users update", method: "PUT", path: "/api/users/u-test", body: map[string]any{"id": "u-test", "email": "u2@test.local", "name": "U Test 2", "roleIds": []string{}}},
		{name: "users delete", method: "DELETE", path: "/api/users/u-test"},

		{name: "roles create", method: "POST", path: "/api/roles", body: map[string]any{"id": "r-test", "name": "R Test"}},
		{name: "roles update", method: "PUT", path: "/api/roles/r-test", body: map[string]any{"id": "r-test", "name": "R Test 2", "description": "desc", "permissionGroupIds": []string{}}},
		{name: "roles delete", method: "DELETE", path: "/api/roles/r-test"},

		{name: "permissions create", method: "POST", path: "/api/permissions", body: map[string]any{"id": "p-test", "name": "P Test", "code": "p:test"}},
		{name: "permissions update", method: "PUT", path: "/api/permissions/p-test", body: map[string]any{"id": "p-test", "name": "P Test 2", "code": "p:test:2"}},
		{name: "permissions delete", method: "DELETE", path: "/api/permissions/p-test"},

		{name: "permission groups create", method: "POST", path: "/api/permission-groups", body: map[string]any{"id": "g-test", "name": "G Test"}},
		{name: "permission groups update", method: "PUT", path: "/api/permission-groups/g-test", body: map[string]any{"id": "g-test", "name": "G Test 2", "description": "desc"}},
		{name: "permission groups delete", method: "DELETE", path: "/api/permission-groups/g-test"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := testutil.FiberDoJSONDetailed(t, app, tc.method, tc.path, tc.body, authHeader)
			if res.StatusCode != http.StatusForbidden {
				t.Fatalf("%s %s => %d body=%s", tc.method, tc.path, res.StatusCode, string(res.Body))
			}
		})
	}
}
