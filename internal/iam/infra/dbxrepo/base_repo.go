// Package dbxrepo provides dbx-backed repository implementations for IAM.
package dbxrepo

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/arcgolabs/arcgo-rbac-template/internal/db"
	"github.com/arcgolabs/dbx"
	"github.com/arcgolabs/dbx/repository"
)

type baseRepo[E any, S repository.EntitySchema[E]] struct {
	core    *dbx.DB
	dialect db.Dialect
	repo    *repository.Base[E, S]
}

func newBaseRepo[E any, S repository.EntitySchema[E]](core *dbx.DB, dialect db.Dialect, schema S) baseRepo[E, S] {
	return baseRepo[E, S]{
		core:    core,
		dialect: dialect,
		repo:    repository.New[E](core, schema),
	}
}

func ensureStringID[E any, S repository.EntitySchema[E]](
	ctx context.Context,
	repo *repository.Base[E, S],
	rawID string,
	kind string,
	mk func(id string) *E,
) error {
	id := strings.TrimSpace(rawID)
	if id == "" {
		return fmt.Errorf("%s id is empty", kind)
	}
	if err := repo.Upsert(ctx, mk(id), "id"); err != nil {
		return fmt.Errorf("%s upsert: %w", kind, err)
	}
	return nil
}

func inTx(ctx context.Context, core *dbx.DB, fn func(tx *dbx.Tx) error) (err error) {
	if core == nil {
		return dbx.ErrNilDB
	}
	tx, err := core.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if err == nil {
			return
		}
		if rollbackErr := tx.RollbackContext(ctx); rollbackErr != nil {
			err = errors.Join(err, fmt.Errorf("rollback tx: %w", rollbackErr))
		}
	}()

	if err = fn(tx); err != nil {
		return err
	}
	if err = tx.CommitContext(ctx); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}
