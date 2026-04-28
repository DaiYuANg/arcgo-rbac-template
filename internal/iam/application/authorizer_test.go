package application_test

import (
	"context"
	"testing"

	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/application"
	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/domain"
	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/infra/dbxrepo"
	"github.com/arcgolabs/arcgo-rbac-template/internal/testutil"
)

func TestAuthorizer_AllowsWhenRoleGrantsPermission(t *testing.T) {
	t.Parallel()
	core, dia, cleanup := testutil.MustMigratingDB(t)
	defer cleanup()
	testutil.SeedReaderUserAlice(t, core.SQLDB(), "pw")

	ur := dbxrepo.NewUserRepo(core, dia)
	rr := dbxrepo.NewRoleRepo(core, dia)
	a := application.NewAuthorizer(ur, rr)

	dec, err := a.Can(
		context.Background(),
		domain.UserID(testutil.TestUserAlice),
		[]string{testutil.TestRoleReader},
		domain.PermissionID(testutil.TestPermUsersRead),
		"/users",
	)
	if err != nil {
		t.Fatalf("Can: %v", err)
	}
	if !dec.Allowed {
		t.Fatalf("expected allowed, got %+v", dec)
	}
}

func TestAuthorizer_DeniesWithoutPermission(t *testing.T) {
	t.Parallel()
	core, dia, cleanup := testutil.MustMigratingDB(t)
	defer cleanup()
	testutil.SeedReaderUserAlice(t, core.SQLDB(), "pw")

	ur := dbxrepo.NewUserRepo(core, dia)
	rr := dbxrepo.NewRoleRepo(core, dia)
	a := application.NewAuthorizer(ur, rr)

	dec, err := a.Can(
		context.Background(),
		domain.UserID(testutil.TestUserAlice),
		[]string{testutil.TestRoleReader},
		domain.PermissionID("users:write"),
		"/users",
	)
	if err != nil {
		t.Fatalf("Can: %v", err)
	}
	if dec.Allowed {
		t.Fatalf("expected denied, got %+v", dec)
	}
}

func TestAuthorizer_DeniesUnknownUser(t *testing.T) {
	t.Parallel()
	core, dia, cleanup := testutil.MustMigratingDB(t)
	defer cleanup()

	ur := dbxrepo.NewUserRepo(core, dia)
	rr := dbxrepo.NewRoleRepo(core, dia)
	a := application.NewAuthorizer(ur, rr)

	dec, err := a.Can(
		context.Background(),
		domain.UserID("ghost"),
		nil,
		domain.PermissionID(testutil.TestPermUsersRead),
		"/users",
	)
	if err != nil {
		t.Fatalf("Can: %v", err)
	}
	if dec.Allowed {
		t.Fatalf("expected denied, got %+v", dec)
	}
}
