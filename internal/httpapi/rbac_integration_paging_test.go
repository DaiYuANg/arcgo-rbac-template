//nolint:testpackage // Integration tests need unexported setup helpers.
package httpapi

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/arcgolabs/arcgo-rbac-template/internal/testutil"
)

func TestIntegration_UsersList_ReturnsPagingMetadata(t *testing.T) {
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

	headers := map[string]string{"Authorization": "Bearer " + tok.AccessToken}
	listRes := testutil.FiberDoJSONDetailed(t, app, "GET", "/api/users?page=1&pageSize=1", nil, headers)
	if listRes.StatusCode != http.StatusOK {
		t.Fatalf("users list %d: %s", listRes.StatusCode, string(listRes.Body))
	}
	var page struct {
		Items    []UserDTO `json:"items"`
		Total    int64     `json:"total"`
		Page     int64     `json:"page"`
		PageSize int64     `json:"pageSize"`
	}
	if err := json.Unmarshal(listRes.Body, &page); err != nil {
		t.Fatalf("users list json: %v", err)
	}
	if page.Page != 1 || page.PageSize != 1 {
		t.Fatalf("paging metadata mismatch: page=%d size=%d", page.Page, page.PageSize)
	}
	if page.Total < 1 {
		t.Fatalf("expected total >= 1, got %d", page.Total)
	}
	if len(page.Items) > 1 {
		t.Fatalf("expected at most 1 item, got %d", len(page.Items))
	}
}
