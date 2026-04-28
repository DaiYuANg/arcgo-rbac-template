package service_test

import (
	"context"
	"testing"

	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/application/service"
	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/domain"
	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/infra/dbxrepo"
	"github.com/arcgolabs/arcgo-rbac-template/internal/testutil"
)

func TestMeService_GetMe_ResolvesProfileAndRoles(t *testing.T) {
	t.Parallel()
	core, dia, cleanup := testutil.MustMigratingDB(t)
	defer cleanup()
	testutil.SeedReaderUserAlice(t, core.SQLDB(), "pw")

	ur := dbxrepo.NewUserRepo(core, dia)
	rr := dbxrepo.NewRoleRepo(core, dia)
	gr := dbxrepo.NewPermissionGroupRepo(core, dia)
	pr := dbxrepo.NewPermissionRepo(core)
	svc := service.NewMeService(ur, rr, gr, pr)

	info, err := svc.GetMe(
		context.Background(),
		domain.UserID(testutil.TestUserAlice),
		[]domain.RoleID{domain.RoleID(testutil.TestRoleReader)},
	)
	if err != nil {
		t.Fatalf("GetMe: %v", err)
	}
	if info.Name != testutil.TestUserAliceName {
		t.Fatalf("name: got %q", info.Name)
	}
	if info.Email != testutil.TestUserAliceEmail {
		t.Fatalf("email: got %q", info.Email)
	}
	if len(info.Roles) == 0 {
		t.Fatalf("expected at least one role")
	}
	if info.Roles[0].Name != "reader" {
		t.Fatalf("role name: got %q", info.Roles[0].Name)
	}
}
