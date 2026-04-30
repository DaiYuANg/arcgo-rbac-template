//nolint:testpackage // Tests validate unexported request DTO normalization.
package httpapi

import (
	"context"
	"testing"

	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/domain"
)

type usersServiceStub struct {
	lastListQuery domain.UsersListQuery
	listPage      domain.Page[domain.User]
}

func (s *usersServiceStub) List(_ context.Context, q domain.UsersListQuery) (domain.Page[domain.User], error) {
	s.lastListQuery = q
	return s.listPage, nil
}

func (s *usersServiceStub) Get(context.Context, domain.UserID) (domain.User, []domain.RoleID, error) {
	return domain.User{}, nil, nil
}

func (s *usersServiceStub) Create(context.Context, domain.User, []domain.RoleID) (domain.User, []domain.RoleID, error) {
	return domain.User{}, nil, nil
}

func (s *usersServiceStub) Update(context.Context, domain.User, []domain.RoleID) (domain.User, []domain.RoleID, error) {
	return domain.User{}, nil, nil
}

func (s *usersServiceStub) Delete(context.Context, domain.UserID) error {
	return nil
}

//nolint:cyclop,gocognit,gocyclo // Single-flow endpoint contract assertion test.
func TestUsersResourceList_MapsPageAndNormalizesQuery(t *testing.T) {
	t.Parallel()

	stub := &usersServiceStub{
		listPage: domain.Page[domain.User]{
			Items: []domain.User{
				{
					ID:        domain.UserID("u1"),
					Email:     "alice@example.com",
					Name:      "Alice",
					CreatedAt: 1710000000000,
				},
			},
			Total:    10,
			Page:     2,
			PageSize: 1,
		},
	}
	resource := &UsersResource{svc: stub}

	out, err := resource.List(context.Background(), &usersListInput{
		Page:      2,
		PageSize:  1,
		Q:         "  alice  ",
		Sort:      "  name ",
		Order:     " DESC ",
		NameLike:  " alice ",
		EmailLike: " example.com ",
	})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if stub.lastListQuery.Order != domain.SortDesc {
		t.Fatalf("order: got %q", stub.lastListQuery.Order)
	}
	if stub.lastListQuery.Q != "alice" || stub.lastListQuery.Sort != "name" {
		t.Fatalf("query normalization failed: %+v", stub.lastListQuery)
	}
	if stub.lastListQuery.NameLike != "alice" || stub.lastListQuery.EmailLike != "example.com" {
		t.Fatalf("like normalization failed: %+v", stub.lastListQuery)
	}
	if out == nil {
		t.Fatalf("expected non-nil output")
	}
	if out.Body.Total != 10 || out.Body.Page != 2 || out.Body.PageSize != 1 {
		t.Fatalf("page payload mismatch: %+v", out.Body)
	}
	if len(out.Body.Items) != 1 || out.Body.Items[0].ID != "u1" {
		t.Fatalf("items mismatch: %+v", out.Body.Items)
	}
}
