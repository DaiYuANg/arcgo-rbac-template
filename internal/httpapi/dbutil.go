package httpapi

import (
	"database/sql"
	"fmt"
	"log/slog"
	"strings"

	"github.com/arcgolabs/dbx"
)

func bind(core *dbx.DB, index int) string {
	if core == nil || core.Dialect() == nil {
		return "?"
	}
	return core.Dialect().BindVar(index)
}

func orderBy(sort, order string, allowed map[string]string) (string, error) {
	sort = strings.TrimSpace(sort)
	order = strings.ToLower(strings.TrimSpace(order))
	if sort == "" {
		return "", nil
	}
	col, ok := allowed[sort]
	if !ok {
		return "", fmt.Errorf("invalid sort field: %s", sort)
	}
	if order == "" {
		order = "asc"
	}
	if order != "asc" && order != "desc" {
		return "", fmt.Errorf("invalid order: %s", order)
	}
	return " ORDER BY " + col + " " + order, nil
}

func closeRows(rows *sql.Rows) {
	if rows == nil {
		return
	}
	if err := rows.Close(); err != nil {
		slog.Default().Error("rows close failed", "error", err)
	}
}

