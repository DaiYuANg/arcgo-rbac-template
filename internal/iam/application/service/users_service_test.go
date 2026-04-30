package service_test

import (
	"context"
	"testing"

	"github.com/arcgolabs/arcgo-rbac-template/internal/db/iamrepo"
	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/application/service"
	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/domain"
	"github.com/arcgolabs/arcgo-rbac-template/internal/testutil"
)

func TestUsersService_Get_ReturnsRoles(t *testing.T) {
	t.Parallel()
	core, _, cleanup := testutil.MustMigratingDB(t)
	defer cleanup()
	testutil.SeedReaderUserAlice(t, core.SQLDB(), "pw")

	svc := service.NewUsersService(iamrepo.NewUserRepo(core))

	u, roles, err := svc.Get(context.Background(), domain.UserID(testutil.TestUserAlice))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if u.Name != testutil.TestUserAliceName {
		t.Fatalf("name: got %q", u.Name)
	}
	var found bool
	for _, rid := range roles {
		if string(rid) == testutil.TestRoleReader {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected role %q in %+v", testutil.TestRoleReader, roles)
	}
}
