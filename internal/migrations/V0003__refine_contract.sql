-- Destructive reset to match `refine-rbac-template` backend contract.
-- This migration intentionally drops and recreates IAM tables (no forward-compat guarantee).

DROP TABLE IF EXISTS iam_permission_group_permissions;
DROP TABLE IF EXISTS iam_role_permission_groups;
DROP TABLE IF EXISTS iam_role_permissions;
DROP TABLE IF EXISTS iam_user_permissions;
DROP TABLE IF EXISTS iam_user_roles;
DROP TABLE IF EXISTS iam_permissions;
DROP TABLE IF EXISTS iam_permission_groups;
DROP TABLE IF EXISTS iam_roles;
DROP TABLE IF EXISTS iam_users;

-- Core resources
CREATE TABLE iam_users (
  id VARCHAR(255) PRIMARY KEY,
  email VARCHAR(255) NOT NULL,
  name VARCHAR(255) NOT NULL,
  created_at BIGINT NOT NULL
);
CREATE INDEX idx_iam_users_email ON iam_users (email);

CREATE TABLE iam_roles (
  id VARCHAR(255) PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  description VARCHAR(1024) NOT NULL,
  created_at BIGINT NOT NULL
);
CREATE INDEX idx_iam_roles_name ON iam_roles (name);

CREATE TABLE iam_permission_groups (
  id VARCHAR(255) PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  description VARCHAR(1024) NOT NULL,
  created_at BIGINT NOT NULL
);
CREATE INDEX idx_iam_permission_groups_name ON iam_permission_groups (name);

CREATE TABLE iam_permissions (
  id VARCHAR(255) PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  code VARCHAR(255) NOT NULL,
  created_at BIGINT NOT NULL
);
CREATE INDEX idx_iam_permissions_code ON iam_permissions (code);
CREATE INDEX idx_iam_permissions_name ON iam_permissions (name);

-- Relations (Refine assignment rules)

-- User -> Roles
CREATE TABLE iam_user_roles (
  user_id VARCHAR(255) NOT NULL,
  role_id VARCHAR(255) NOT NULL,
  PRIMARY KEY (user_id, role_id)
);
CREATE INDEX idx_iam_user_roles_user ON iam_user_roles (user_id);
CREATE INDEX idx_iam_user_roles_role ON iam_user_roles (role_id);

-- Role -> Permission Groups
CREATE TABLE iam_role_permission_groups (
  role_id VARCHAR(255) NOT NULL,
  group_id VARCHAR(255) NOT NULL,
  PRIMARY KEY (role_id, group_id)
);
CREATE INDEX idx_iam_rpg_role ON iam_role_permission_groups (role_id);
CREATE INDEX idx_iam_rpg_group ON iam_role_permission_groups (group_id);

-- Permission Group -> Permissions
-- NOTE: The frontend treats permission.groupId as 0..1. We enforce it at write time by
-- deleting any existing mapping for perm_id before inserting a new one.
CREATE TABLE iam_permission_group_permissions (
  group_id VARCHAR(255) NOT NULL,
  perm_id VARCHAR(255) NOT NULL,
  PRIMARY KEY (group_id, perm_id)
);
CREATE INDEX idx_iam_pg_perms_group ON iam_permission_group_permissions (group_id);
CREATE INDEX idx_iam_pg_perms_perm ON iam_permission_group_permissions (perm_id);

