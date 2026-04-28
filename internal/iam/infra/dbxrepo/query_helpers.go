package dbxrepo

import (
	"context"
	"fmt"

	"github.com/arcgolabs/dbx"
	"github.com/arcgolabs/dbx/mapper"
	"github.com/arcgolabs/dbx/querydsl"
)

// predicatesAnd folds filters with AND; an empty slice means no filter (match every row).
func predicatesAnd(predicates []querydsl.Predicate) querydsl.Predicate {
	if len(predicates) == 0 {
		return querydsl.Compare(querydsl.Value(1), querydsl.OpEq, 1)
	}
	return querydsl.And(predicates...)
}

type oneStringRow struct {
	Value string `dbx:"value"`
}

func queryStringColumn(ctx context.Context, core *dbx.DB, query querydsl.Builder) ([]string, error) {
	if core == nil {
		return nil, dbx.ErrNilDB
	}
	items, err := dbx.QueryAll(ctx, core, query, mapper.MustStructMapper[oneStringRow]())
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
