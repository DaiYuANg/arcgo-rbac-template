package httpapi

import "github.com/arcgolabs/dbx"

func bind(core *dbx.DB, index int) string {
	if core == nil || core.Dialect() == nil {
		return "?"
	}
	return core.Dialect().BindVar(index)
}
