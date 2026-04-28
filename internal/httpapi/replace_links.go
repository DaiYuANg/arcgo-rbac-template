package httpapi

import (
	"context"
	"fmt"
	"strings"

	"github.com/arcgolabs/dbx"
	"github.com/arcgolabs/dbx/querydsl"
	"github.com/arcgolabs/httpx"
)

func replaceLinks(
	ctx context.Context,
	core *dbx.DB,
	deleteQuery querydsl.Builder,
	mkInsert func(id string) querydsl.Builder,
	ids []string,
	deleteErrMsg string,
	insertErrMsg string,
) error {
	if core == nil {
		return httpx.NewError(500, "db_missing")
	}
	if ids == nil {
		return nil
	}
	if _, err := dbx.Exec(ctx, core, deleteQuery); err != nil {
		return httpx.NewError(500, "unknown", fmt.Errorf("%s: %w", deleteErrMsg, err))
	}
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, err := dbx.Exec(ctx, core, mkInsert(id)); err != nil {
			return httpx.NewError(500, "unknown", fmt.Errorf("%s: %w", insertErrMsg, err))
		}
	}
	return nil
}

