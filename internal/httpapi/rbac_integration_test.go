//nolint:testpackage // Integration tests need unexported endpoint/test setup helpers.
package httpapi

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/arcgolabs/arcgo-rbac-template/internal/config"
	iamservice "github.com/arcgolabs/arcgo-rbac-template/internal/iam/application/service"
	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/infra/dbxrepo"
	"github.com/arcgolabs/arcgo-rbac-template/internal/testutil"
	"github.com/arcgolabs/httpx"
	adapter "github.com/arcgolabs/httpx/adapter"
	adapterfiber "github.com/arcgolabs/httpx/adapter/fiber"
	"github.com/gofiber/fiber/v2"
)

func setupRBACApp(t *testing.T, seedAlice, seedDenied bool, mutateCfg func(*config.Config)) (*fiber.App, func()) {
	t.Helper()
	core, dia, cleanupDB := testutil.MustMigratingDB(t)
	if seedAlice {
		testutil.SeedReaderUserAlice(t, core.SQLDB(), "integration-secret")
	}
	if seedDenied {
		testutil.SeedDeniedUser(t, core.SQLDB(), "bob", "bob-secret")
	}

	cfg := config.Config{Auth: testutil.DefaultIntegrationAuth()}
	if mutateCfg != nil {
		mutateCfg(&cfg)
	}
	userRepo := dbxrepo.NewUserRepo(core, dia)
	roleRepo := dbxrepo.NewRoleRepo(core, dia)
	groupRepo := dbxrepo.NewPermissionGroupRepo(core, dia)
	permRepo := dbxrepo.NewPermissionRepo(core)

	eng := testutil.MustAuthEngine(t, cfg, core, userRepo, roleRepo)
	meSvc := iamservice.NewMeService(userRepo, roleRepo, groupRepo, permRepo)
	usersSvc := iamservice.NewUsersService(userRepo)

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

	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
	})
	ad := adapterfiber.New(app, adapter.HumaOptions{
		Title:       "rbac-test",
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

	RegisterFiberBindings(app, meEp, usersEp)
	srv.Register(authEp)
	srv.Register(meEp)
	srv.Register(usersEp)

	return app, cleanupDB
}

func TestIntegration_LoginMeAndListUsers(t *testing.T) {
	t.Parallel()
	app, cleanup := setupRBACApp(t, true, false, nil)
	defer cleanup()

	loginBody := map[string]string{
		"username": testutil.TestUserAlice,
		"password": "integration-secret",
	}
	resLogin := testutil.FiberDoJSONDetailed(t, app, "POST", "/api/auth/login", loginBody, nil)
	if resLogin.StatusCode != http.StatusOK {
		t.Fatalf("login status %d body %s", resLogin.StatusCode, string(resLogin.Body))
	}
	var tok struct {
		AccessToken string `json:"accessToken"`
	}
	if err := json.Unmarshal(resLogin.Body, &tok); err != nil {
		t.Fatalf("login json: %v", err)
	}
	if tok.AccessToken == "" {
		t.Fatalf("missing access token: %s", resLogin.Body)
	}

	h := map[string]string{"Authorization": "Bearer " + tok.AccessToken}
	statusMe, bodyMe := testutil.FiberDoJSON(t, app, "GET", "/api/me", nil, h)
	if statusMe != http.StatusOK {
		t.Fatalf("me %d: %s", statusMe, bodyMe)
	}
	var me MeResponse
	if err := json.Unmarshal(bodyMe, &me); err != nil {
		t.Fatalf("me json: %v", err)
	}
	if me.ID != testutil.TestUserAlice {
		t.Fatalf("me id: got %q", me.ID)
	}

	statusList, bodyList := testutil.FiberDoJSON(t, app, "GET", "/api/users?page=1&pageSize=10", nil, h)
	if statusList != http.StatusOK {
		t.Fatalf("users list %d: %s", statusList, bodyList)
	}
}

func TestIntegration_DeniedWithoutUsersRead(t *testing.T) {
	t.Parallel()
	app, cleanup := setupRBACApp(t, false, true, nil)
	defer cleanup()

	loginBody := map[string]string{
		"username": "bob",
		"password": "bob-secret",
	}
	resLogin := testutil.FiberDoJSONDetailed(t, app, "POST", "/api/auth/login", loginBody, nil)
	if resLogin.StatusCode != http.StatusOK {
		t.Fatalf("login status %d", resLogin.StatusCode)
	}
	var tok struct {
		AccessToken string `json:"accessToken"`
	}
	if err := json.Unmarshal(resLogin.Body, &tok); err != nil {
		t.Fatalf("login json: %v", err)
	}
	h := map[string]string{"Authorization": "Bearer " + tok.AccessToken}
	status, body := testutil.FiberDoJSON(t, app, "GET", "/api/users?page=1&pageSize=10", nil, h)
	if status != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", status, body)
	}
}

func TestIntegration_RefreshRotatesSession(t *testing.T) {
	t.Parallel()
	app, cleanup := setupRBACApp(t, true, false, nil)
	defer cleanup()

	loginBody := map[string]string{
		"username": testutil.TestUserAlice,
		"password": "integration-secret",
	}
	resLogin := testutil.FiberDoJSONDetailed(t, app, "POST", "/api/auth/login", loginBody, nil)
	if resLogin.StatusCode != http.StatusOK {
		t.Fatalf("login: %d %s", resLogin.StatusCode, resLogin.Body)
	}
	refresh := extractCookie(resLogin.Header.Get("Set-Cookie"), "refreshToken")
	if refresh == "" {
		t.Fatalf("missing refresh cookie from %v", resLogin.Header.Values("Set-Cookie"))
	}

	refRes := testutil.FiberRequest(t, app, "POST", "/api/auth/refresh",
		strings.NewReader("{}"), map[string]string{
			"Cookie": "refreshToken=" + refresh,
		})
	if refRes.StatusCode != http.StatusOK {
		t.Fatalf("refresh %d: %s", refRes.StatusCode, refRes.Body)
	}
	var outTok struct {
		AccessToken string `json:"accessToken"`
	}
	if err := json.Unmarshal(refRes.Body, &outTok); err != nil {
		t.Fatalf("refresh json: %v", err)
	}
	if outTok.AccessToken == "" {
		t.Fatalf("missing new access token")
	}
}

func TestIntegration_LogoutRevokesRefreshToken(t *testing.T) {
	t.Parallel()
	app, cleanup := setupRBACApp(t, true, false, nil)
	defer cleanup()

	loginBody := map[string]string{
		"username": testutil.TestUserAlice,
		"password": "integration-secret",
	}
	resLogin := testutil.FiberDoJSONDetailed(t, app, "POST", "/api/auth/login", loginBody, nil)
	if resLogin.StatusCode != http.StatusOK {
		t.Fatalf("login status %d body %s", resLogin.StatusCode, string(resLogin.Body))
	}
	refresh := extractCookie(resLogin.Header.Get("Set-Cookie"), "refreshToken")
	if refresh == "" {
		t.Fatalf("missing refresh cookie from %v", resLogin.Header.Values("Set-Cookie"))
	}

	logoutRes := testutil.FiberRequest(t, app, "POST", "/api/auth/logout",
		strings.NewReader("{}"), map[string]string{
			"Cookie": "refreshToken=" + refresh,
		})
	if logoutRes.StatusCode != http.StatusOK {
		t.Fatalf("logout %d: %s", logoutRes.StatusCode, logoutRes.Body)
	}

	refreshRes := testutil.FiberRequest(t, app, "POST", "/api/auth/refresh",
		strings.NewReader("{}"), map[string]string{
			"Cookie": "refreshToken=" + refresh,
		})
	if refreshRes.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 after logout, got %d: %s", refreshRes.StatusCode, refreshRes.Body)
	}
}

func TestIntegration_LoginRateLimit(t *testing.T) {
	t.Parallel()
	app, cleanup := setupRBACApp(t, true, false, func(cfg *config.Config) {
		cfg.Auth.LoginRateLimit = 1
		cfg.Auth.LoginRateWindow = time.Hour
	})
	defer cleanup()

	badLogin := map[string]string{
		"username": testutil.TestUserAlice,
		"password": "wrong-password",
	}
	first := testutil.FiberDoJSONDetailed(t, app, "POST", "/api/auth/login", badLogin, nil)
	if first.StatusCode != http.StatusUnauthorized {
		t.Fatalf("first login status %d body %s", first.StatusCode, string(first.Body))
	}

	second := testutil.FiberDoJSONDetailed(t, app, "POST", "/api/auth/login", badLogin, nil)
	if second.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on second login, got %d body %s", second.StatusCode, string(second.Body))
	}
}

func extractCookie(rawCookie, key string) string {
	rawCookie = strings.TrimSpace(rawCookie)
	if rawCookie == "" || strings.TrimSpace(key) == "" {
		return ""
	}
	for part := range strings.SplitSeq(rawCookie, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		if strings.TrimSpace(kv[0]) == key {
			return strings.TrimSpace(kv[1])
		}
	}
	return ""
}
