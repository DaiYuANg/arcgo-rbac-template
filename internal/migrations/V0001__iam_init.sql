-- IAM/RBAC base schema.
-- Applied by `go run ./cmd/migrate` via `github.com/arcgolabs/dbx/migrate`.

CREATE TABLE iam_users (
  id VARCHAR(255) PRIMARY KEY
);

CREATE TABLE iam_roles (
  id VARCHAR(255) PRIMARY KEY
);

CREATE TABLE iam_permissions (
  id VARCHAR(255) PRIMARY KEY
);

CREATE TABLE iam_permission_groups (
  id VARCHAR(255) PRIMARY KEY
);

CREATE TABLE iam_user_roles (
  user_id VARCHAR(255) NOT NULL,
  role_id VARCHAR(255) NOT NULL,
  PRIMARY KEY (user_id, role_id)
);

CREATE TABLE iam_role_permissions (
  role_id VARCHAR(255) NOT NULL,
  perm_id VARCHAR(255) NOT NULL,
  PRIMARY KEY (role_id, perm_id)
);

CREATE TABLE iam_user_permissions (
  user_id VARCHAR(255) NOT NULL,
  perm_id VARCHAR(255) NOT NULL,
  PRIMARY KEY (user_id, perm_id)
);

CREATE TABLE iam_permission_group_permissions (
  group_id VARCHAR(255) NOT NULL,
  perm_id VARCHAR(255) NOT NULL,
  PRIMARY KEY (group_id, perm_id)
);

CREATE INDEX idx_iam_user_roles_user ON iam_user_roles (user_id);
CREATE INDEX idx_iam_user_roles_role ON iam_user_roles (role_id);
CREATE INDEX idx_iam_role_perms_role ON iam_role_permissions (role_id);
CREATE INDEX idx_iam_role_perms_perm ON iam_role_permissions (perm_id);
CREATE INDEX idx_iam_user_perms_user ON iam_user_permissions (user_id);
CREATE INDEX idx_iam_user_perms_perm ON iam_user_permissions (perm_id);
CREATE INDEX idx_iam_pg_perms_group ON iam_permission_group_permissions (group_id);
CREATE INDEX idx_iam_pg_perms_perm ON iam_permission_group_permissions (perm_id);

