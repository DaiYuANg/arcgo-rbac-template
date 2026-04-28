package testutil

import (
	"context"
	"database/sql"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	TestRoleReader     = "r-read"
	TestPermUsersRead  = "users:read"
	TestUserAlice      = "alice"
	TestUserAliceEmail = "alice@example.test"
	TestUserAliceName  = "Alice Tester"
)

// SeedReaderUserAlice creates IAM rows + auth_users for DB password login where principal ID is the username.
// Permission IDs match HTTP action strings (users:read) so IAM authorizer aligns with routers.
func SeedReaderUserAlice(tb testing.TB, sqlDB *sql.DB, plainPassword string) {
	tb.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(plainPassword), bcrypt.MinCost)
	if err != nil {
		tb.Fatalf("bcrypt: %v", err)
	}
	ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
	ctx := context.Background()
	tx, err := sqlDB.BeginTx(ctx, nil)
	if err != nil {
		tb.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	exec := func(query string, args ...any) {
		tb.Helper()
		_, execErr := tx.ExecContext(ctx, query, args...)
		if execErr != nil {
			tb.Fatalf("exec %s: %v", query, execErr)
		}
	}

	exec(`INSERT INTO iam_users (id, email, name, created_at) VALUES (?, ?, ?, ?)`,
		TestUserAlice, TestUserAliceEmail, TestUserAliceName, ts)
	exec(`INSERT INTO iam_roles (id, name, description, created_at) VALUES (?, ?, ?, ?)`,
		TestRoleReader, "reader", "test role", ts)
	exec(`INSERT INTO iam_permissions (id, name, code, created_at) VALUES (?, ?, ?, ?)`,
		TestPermUsersRead, TestPermUsersRead, TestPermUsersRead, ts)

	exec(`INSERT INTO iam_role_permissions (role_id, perm_id) VALUES (?, ?)`, TestRoleReader, TestPermUsersRead)
	exec(`INSERT INTO iam_user_roles (user_id, role_id) VALUES (?, ?)`, TestUserAlice, TestRoleReader)

	exec(`INSERT INTO auth_users (username, password_hash, roles) VALUES (?, ?, ?)`,
		TestUserAlice, string(hash), TestRoleReader)

	if err := tx.Commit(); err != nil {
		tb.Fatalf("commit: %v", err)
	}
}

// SeedUserNoPerm inserts a second user authenticated in auth_users without users:read.
func SeedDeniedUser(tb testing.TB, sqlDB *sql.DB, username, plainPassword string) {
	tb.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(plainPassword), bcrypt.MinCost)
	if err != nil {
		tb.Fatalf("bcrypt: %v", err)
	}
	ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
	ctx := context.Background()

	tx, err := sqlDB.BeginTx(ctx, nil)
	if err != nil {
		tb.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	exec := func(query string, args ...any) {
		tb.Helper()
		_, execErr := tx.ExecContext(ctx, query, args...)
		if execErr != nil {
			tb.Fatalf("exec: %v", execErr)
		}
	}

	exec(`INSERT INTO iam_users (id, email, name, created_at) VALUES (?, ?, ?, ?)`,
		username, username+"@example.test", "Denied", ts)
	exec(`INSERT INTO auth_users (username, password_hash, roles) VALUES (?, ?, ?)`, username, string(hash), "")

	if err := tx.Commit(); err != nil {
		tb.Fatalf("commit: %v", err)
	}
}
