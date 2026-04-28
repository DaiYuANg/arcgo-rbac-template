// Package migrations embeds SQL migration files used by cmd/migrate.
package migrations

import (
	"embed"
	"io/fs"
)

// FS contains embedded SQL migration files.
//
//go:embed *.sql
var embedded embed.FS

// Filesystem returns the embedded filesystem and root directory used by dbx/migrate.
func Filesystem() (fs.FS, string) {
	return embedded, "."
}
