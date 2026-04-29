//nolint:testpackage // Integration tests need unexported endpoint/test setup helpers.
package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/arcgolabs/arcgo-rbac-template/internal/testutil"
)

func TestIntegration_LogoutAllRevokesRefreshToken(t *testing.T) {
	t.Parallel()
	app, cleanup := setupRBACApp(t, true, false, nil)
	defer cleanup()

	loginBody := map[string]string{
		"username": testutil.TestUserAlice,
		"password": "integration-secret",
	}
	loginRes := testutil.FiberDoJSONDetailed(t, app, "POST", "/api/auth/login", loginBody, nil)
	if loginRes.StatusCode != http.StatusOK {
		t.Fatalf("login status %d body %s", loginRes.StatusCode, string(loginRes.Body))
	}

	var tok struct {
		AccessToken string `json:"accessToken"`
	}
	if err := json.Unmarshal(loginRes.Body, &tok); err != nil {
		t.Fatalf("login json: %v", err)
	}
	if tok.AccessToken == "" {
		t.Fatalf("missing access token")
	}
	refresh := extractCookie(loginRes.Header.Get("Set-Cookie"), "refreshToken")
	if refresh == "" {
		t.Fatalf("missing refresh cookie")
	}

	logoutAllRes := testutil.FiberRequest(t, app, "POST", "/api/auth/logout-all",
		strings.NewReader("{}"), map[string]string{
			"Authorization": "Bearer " + tok.AccessToken,
		})
	if logoutAllRes.StatusCode != http.StatusOK {
		t.Fatalf("logout-all status %d body %s", logoutAllRes.StatusCode, logoutAllRes.Body)
	}

	refreshRes := testutil.FiberRequest(t, app, "POST", "/api/auth/refresh",
		strings.NewReader("{}"), map[string]string{
			"Cookie": "refreshToken=" + refresh,
		})
	if refreshRes.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 after logout-all, got %d: %s", refreshRes.StatusCode, refreshRes.Body)
	}
}

func TestIntegration_ListAuditLogs(t *testing.T) {
	t.Parallel()
	app, cleanup := setupRBACApp(t, true, false, nil)
	defer cleanup()

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

	listRes := testutil.FiberRequest(t, app, "GET", "/api/auth/audit-logs?page=1&pageSize=20", nil, map[string]string{
		"Authorization": "Bearer " + token.AccessToken,
	})
	if listRes.StatusCode != http.StatusOK {
		t.Fatalf("audit logs status %d body %s", listRes.StatusCode, string(listRes.Body))
	}
	var page struct {
		Items []struct {
			Event   string `json:"event"`
			Success bool   `json:"success"`
		} `json:"items"`
		Total int64 `json:"total"`
	}
	if err := json.Unmarshal(listRes.Body, &page); err != nil {
		t.Fatalf("audit logs json: %v", err)
	}
	if page.Total < 1 || len(page.Items) < 1 {
		t.Fatalf("expected at least one audit log, got total=%d items=%d body=%s", page.Total, len(page.Items), string(listRes.Body))
	}
}
