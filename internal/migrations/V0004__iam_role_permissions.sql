-- Direct Role -> Permission mappings used by IAM authorizer (`RoleRepo.ListPermissions`).
-- V0003 migrated the IAM contract but dropped this junction table without replacement.

CREATE TABLE iam_role_permissions (
  role_id VARCHAR(255) NOT NULL,
  perm_id VARCHAR(255) NOT NULL,
  PRIMARY KEY (role_id, perm_id)
);
CREATE INDEX idx_iam_role_perms_role ON iam_role_permissions (role_id);
CREATE INDEX idx_iam_role_perms_perm ON iam_role_permissions (perm_id);
