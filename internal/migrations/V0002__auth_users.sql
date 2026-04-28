-- Username/password users for DB-backed login source.

CREATE TABLE auth_users (
  username VARCHAR(255) PRIMARY KEY,
  password_hash VARCHAR(255) NOT NULL,
  roles VARCHAR(1024) NOT NULL
);

CREATE INDEX idx_auth_users_username ON auth_users (username);

