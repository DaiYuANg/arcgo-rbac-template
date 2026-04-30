package iamrepo

import (
	"context"
	"fmt"
	"strings"

	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/domain"
	"github.com/arcgolabs/dbx"
	"github.com/arcgolabs/dbx/mapper"
	"github.com/arcgolabs/dbx/paging"
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

func toDomainPage[E any, R any](result paging.Result[E], mapItem func(E) R) domain.Page[R] {
	mapped := paging.MapResult[E, R](result, func(_ int, item E) R {
		return mapItem(item)
	})
	size := 0
	if mapped.Items != nil {
		size = mapped.Items.Len()
	}
	items := make([]R, 0, size)
	if mapped.Items != nil {
		mapped.Items.Range(func(_ int, item R) bool {
			items = append(items, item)
			return true
		})
	}
	return domain.Page[R]{
		Items:    items,
		Total:    mapped.Total,
		Page:     int64(mapped.Page),
		PageSize: int64(mapped.PageSize),
	}
}
