//nolint:testpackage // Tests validate unexported paging helpers directly.
package iamrepo

import (
	"testing"

	collectionlist "github.com/arcgolabs/collectionx/list"
	"github.com/arcgolabs/dbx/paging"
	"github.com/arcgolabs/dbx/querydsl"
)

func TestListOrderBy_DefaultSortKeyUsesID(t *testing.T) {
	t.Parallel()

	var calledKey string
	var calledDesc bool
	orders := map[string]func(bool) querydsl.Order{
		"id": func(desc bool) querydsl.Order {
			calledKey = "id"
			calledDesc = desc
			if desc {
				return Users.ID.Desc()
			}
			return Users.ID.Asc()
		},
	}

	order, err := listOrderBy("", true, orders)
	if err != nil {
		t.Fatalf("listOrderBy: %v", err)
	}
	if order == nil {
		t.Fatalf("expected non-nil order")
	}
	if calledKey != "id" {
		t.Fatalf("expected default sort key id, got %q", calledKey)
	}
	if !calledDesc {
		t.Fatalf("expected desc=true passed to order function")
	}
}

func TestListOrderBy_InvalidSortKeyReturnsError(t *testing.T) {
	t.Parallel()

	orders := map[string]func(bool) querydsl.Order{
		"id": func(bool) querydsl.Order { return nil },
	}

	if _, err := listOrderBy("unknown", false, orders); err == nil {
		t.Fatalf("expected error for invalid sort key")
	}
}

func TestToDomainPage_MapsItemsAndPagingMetadata(t *testing.T) {
	t.Parallel()

	sourceItems := collectionlist.NewList(
		User{ID: "u1", Email: "alice@example.com", Name: "Alice", CreatedAt: 1},
		User{ID: "u2", Email: "bob@example.com", Name: "Bob", CreatedAt: 2},
	)
	result := paging.NewResult[User](sourceItems, 5, paging.Request{Page: 2, PageSize: 2})

	page := toDomainPage[User, string](result, func(u User) string { return u.ID })
	if page.Total != 5 {
		t.Fatalf("total: got %d", page.Total)
	}
	if page.Page != 2 || page.PageSize != 2 {
		t.Fatalf("page meta: got page=%d size=%d", page.Page, page.PageSize)
	}
	if len(page.Items) != 2 || page.Items[0] != "u1" || page.Items[1] != "u2" {
		t.Fatalf("items: got %#v", page.Items)
	}
}

func TestToDomainPage_HandlesNilItems(t *testing.T) {
	t.Parallel()

	result := paging.NewResult[User](nil, 0, paging.Request{Page: 1, PageSize: 20})
	page := toDomainPage[User, string](result, func(u User) string { return u.ID })
	if page.Items == nil {
		t.Fatalf("expected non-nil items slice")
	}
	if len(page.Items) != 0 {
		t.Fatalf("expected empty items, got %d", len(page.Items))
	}
}
