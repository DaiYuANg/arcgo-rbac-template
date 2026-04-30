package iamrepo

import (
	"context"
	"fmt"
	"strings"

	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/domain"
	"github.com/arcgolabs/dbx"
	"github.com/arcgolabs/dbx/mapper"
	"github.com/arcgolabs/dbx/querydsl"
)

func listOrderBy(sortKey string, desc bool, orders map[string]func(bool) querydsl.Order) (querydsl.Order, error) {
	var none querydsl.Order
	sortKey = strings.TrimSpace(sortKey)
	if sortKey == "" {
		sortKey = "id"
	}
	fn, ok := orders[sortKey]
	if !ok {
		return none, fmt.Errorf("invalid sort field: %s", sortKey)
	}
	return fn(desc), nil
}

func queryOne[Row any](ctx context.Context, core *dbx.DB, q querydsl.Builder, wrap string) (Row, error) {
	var zero Row
	items, err := dbx.QueryAll[Row](ctx, core, q, mapper.MustStructMapper[Row]())
	if err != nil {
		return zero, fmt.Errorf("%s: %w", wrap, err)
	}
	if items == nil || items.Len() == 0 {
		return zero, domain.ErrNotFound
	}
	row, _ := items.Get(0)
	return row, nil
}
