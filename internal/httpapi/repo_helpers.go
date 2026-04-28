package httpapi

import (
	"context"

	"github.com/arcgolabs/authx"
	"github.com/arcgolabs/dbx"
	"github.com/arcgolabs/dbx/repository"
	"github.com/arcgolabs/httpx"
)

func nowAndEnforce(ctx context.Context, core *dbx.DB, engine *authx.Engine, action, resource string) (int64, error) {
	if core == nil {
		return 0, httpx.NewError(500, "db_missing")
	}
	if err := enforce(ctx, engine, action, resource); err != nil {
		return 0, err
	}
	return nowUnixMilli(), nil
}

func repoCreate[E any, S repository.EntitySchema[E]](ctx context.Context, core *dbx.DB, schema S, entity *E) error {
	r := repository.New[E](core, schema)
	return r.Create(ctx, entity)
}

