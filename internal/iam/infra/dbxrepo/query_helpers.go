package dbxrepo

import (
	"context"
	"database/sql"
	"errors"

	"github.com/arcgolabs/arcgo-rbac-template/internal/db"
	"github.com/arcgolabs/dbx"
)

func queryStringColumn(ctx context.Context, core *dbx.DB, dialect db.Dialect, sqlDefault, sqlPostgres, arg string) ([]string, error) {
	q := sqlDefault
	if dialect == db.DialectPostgres {
		q = sqlPostgres
	}
	rows, err := core.SQLDB().QueryContext(ctx, q, arg)
	if err != nil {
		return nil, err
	}
	out := []string{}
	for rows.Next() {
		var v sql.NullString
		if err := rows.Scan(&v); err != nil {
			closeErr := rows.Close()
			return nil, errors.Join(err, closeErr)
		}
		if v.Valid {
			out = append(out, v.String)
		}
	}
	if err := rows.Err(); err != nil {
		closeErr := rows.Close()
		return nil, errors.Join(err, closeErr)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	return out, nil
}

