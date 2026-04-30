package iamrepo

import (
	"context"
	"fmt"

	"github.com/arcgolabs/dbx"
	"github.com/arcgolabs/dbx/mapper"
	"github.com/arcgolabs/dbx/querydsl"
)

func predicatesAnd(predicates []querydsl.Predicate) querydsl.Predicate {
	items := querydsl.CompactPredicates(predicates)
	if items.Len() == 0 {
		return nil
	}
	return querydsl.AndList(items)
}

type oneStringRow struct {
	Value string `dbx:"value"`
}

func queryStringColumn(ctx context.Context, core *dbx.DB, query querydsl.Builder) ([]string, error) {
	if core == nil {
		return nil, dbx.ErrNilDB
	}
	items, err := dbx.QueryAll[oneStringRow](ctx, core, query, mapper.MustStructMapper[oneStringRow]())
	if err != nil {
		return nil, fmt.Errorf("db query all: %w", err)
	}
	out := make([]string, 0, items.Len())
	if items != nil {
		items.Range(func(_ int, r oneStringRow) bool {
			out = append(out, r.Value)
			return true
		})
	}
	return out, nil
}
