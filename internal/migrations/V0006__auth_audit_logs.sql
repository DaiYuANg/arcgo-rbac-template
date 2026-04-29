-- Structured auth audit logs for security and compliance analysis.
CREATE TABLE auth_audit_logs (
  id VARCHAR(255) PRIMARY KEY,
  event VARCHAR(128) NOT NULL,
  user_id VARCHAR(255) NOT NULL,
  username VARCHAR(255) NOT NULL,
  client_ip VARCHAR(255) NOT NULL,
  success BOOLEAN NOT NULL,
  reason VARCHAR(255) NOT NULL,
  created_at BIGINT NOT NULL
);

CREATE INDEX idx_auth_audit_logs_created_at ON auth_audit_logs (created_at);
CREATE INDEX idx_auth_audit_logs_event ON auth_audit_logs (event);
CREATE INDEX idx_auth_audit_logs_user_id ON auth_audit_logs (user_id);
