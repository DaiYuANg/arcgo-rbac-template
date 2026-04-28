-- Direct User -> Permission junction (dropped in V0003, used by authorizer + user repo).
CREATE TABLE iam_user_permissions (
  user_id VARCHAR(255) NOT NULL,
  perm_id VARCHAR(255) NOT NULL,
  PRIMARY KEY (user_id, perm_id)
);
CREATE INDEX idx_iam_user_perms_user ON iam_user_permissions (user_id);
CREATE INDEX idx_iam_user_perms_perm ON iam_user_permissions (perm_id);
