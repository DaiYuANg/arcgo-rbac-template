# arcgo-rbac-template

一个最小可运行的 Go **RBAC 模板**（JWT 鉴权 + RBAC 授权 + 可插拔存储），基于 `arcgolabs` 组件栈：

- `authx`：鉴权/授权抽象（本项目用 `authx/jwt` 做 JWT provider）
- `httpx`：HTTP 组织层（本项目用 `httpx/adapter/fiber`，底层是 Fiber）
- `dix`：依赖注入 + 生命周期（启动/停止 hooks）
- `dbx`：数据库连接与方言（本项目对 SQLite/MySQL/Postgres 统一支持）
- `configx`：配置加载（默认 `.env` / env / defaults，可扩展文件配置）

## 运行

```bash
go run ./cmd/server
```

默认监听 `:8080`。

## Dotenv

默认会加载 `.env` / `.env.local`（可选，不存在也不会报错）。可以从 `.env.example` 复制一份：

```bash
copy .env.example .env
```

## 迁移（推荐独立进程）

```bash
go run ./cmd/migrate
```

迁移 SQL 使用 `embed` 打包在二进制里（见 `internal/migrations`），因此运行时不依赖工作目录下是否存在 `migrations/` 文件夹。

### 环境变量

- `HTTP_ADDR`: 监听地址，默认 `:8080`
- `DB_DRIVER`: `sqlite` / `mysql` / `postgres`（默认 `sqlite`）
- `DB_DSN`: 数据库连接串
- `JWT_SECRET`: JWT HMAC secret。默认 `dev-secret-change-me`（仅开发）
- `ALLOW_INSECURE_DEV`: 默认 `true`；设为 `false` 时必须提供 `JWT_SECRET`
- `ACCESS_TOKEN_TTL`: 默认 `30m`（Go duration 格式，如 `15m` / `1h`）
- `REFRESH_TOKEN_TTL`: refresh token（cookie）有效期，默认 `168h`
- `AUTH_SOURCES`: 登录认证来源（逗号分隔），默认 `root,db`
- `AUTH_ROOT_USERNAME`: root 登录用户名，默认 `root`
- `AUTH_ROOT_PASSWORD`: root 登录密码，默认 `root`
- `AUTH_LOGIN_RATE_LIMIT`: 登录接口限流次数，默认 `20`
- `AUTH_LOGIN_RATE_WINDOW`: 登录接口限流窗口，默认 `1m`
- `AUTH_REFRESH_RATE_LIMIT`: 刷新接口限流次数，默认 `60`
- `AUTH_REFRESH_RATE_WINDOW`: 刷新接口限流窗口，默认 `1m`
- `KV_ENABLED`: 是否启用分布式缓存（Valkey/Redis），默认 `false`
- `KV_DRIVER`: `valkey`（默认）或 `redis`
- `KV_ADDR`: 默认 `127.0.0.1:6379`
- `KV_PREFIX`: key 前缀，默认 `arcgo:`
- `KV_DEFAULT_TTL`: 默认缓存 TTL，默认 `30s`
- `BOOTSTRAP_ADMIN_USER_ID`: 默认 `admin`（会被自动授予 `admin` 角色）

#### DB_DSN 示例

- SQLite in-memory（测试/本地临时使用）：

```bash
set DB_DRIVER=sqlite
set DB_DSN=file::memory:?cache=shared
```

- SQLite（默认会自动给一个可用的 DSN）：

```bash
set DB_DRIVER=sqlite
set DB_DSN=file:rbac.db?_pragma=busy_timeout(5000)
```

- MySQL / MariaDB：

```bash
set DB_DRIVER=mysql
set DB_DSN=user:pass@tcp(127.0.0.1:3306)/rbac?parseTime=true
```

- Postgres：

```bash
set DB_DRIVER=postgres
set DB_DSN=postgres://user:pass@localhost:5432/rbac?sslmode=disable
```

## RBAC 规则（示例）

内置了两个角色：

- `admin`: `admin:panel`、`user:read`
- `viewer`: `user:read`

并且把 `BOOTSTRAP_ADMIN_USER_ID`（默认 `admin`）在启动时 bootstrap 绑定为 `admin` 角色。

## 快速验证（curl）

### 1) 登录换 token（推荐）

默认启用 `root` 登录源（`root/root`），会作为超级管理员（带 `admin` 角色）：

```bash
curl -s -X POST http://localhost:8080/api/auth/login ^
  -H "Content-Type: application/json" ^
  -d "{\"username\":\"root\",\"password\":\"root\"}"
```

把返回的 `access_token` 复制出来。

#### Refresh token（可选，KVX 开启时推荐）

当 `KV_ENABLED=true` 时，服务会把 refresh token 存到 Valkey/Redis（kvx）里，并通过 `Set-Cookie` 下发 httpOnly `refreshToken`。
前端在遇到 401 时可调用：

```bash
curl -i -X POST http://localhost:8080/api/auth/refresh ^
  -H "Cookie: refreshToken=<REFRESH_TOKEN_FROM_COOKIE>"
```

登出并撤销当前 refresh token：

```bash
curl -i -X POST http://localhost:8080/api/auth/logout ^
  -H "Cookie: refreshToken=<REFRESH_TOKEN_FROM_COOKIE>"
```

登出当前用户的全部会话（需要 access token）：

```bash
curl -i -X POST http://localhost:8080/api/auth/logout-all ^
  -H "Authorization: Bearer <TOKEN>"
```

### 2) 访问需要登录的接口

```bash
curl -s http://localhost:8080/api/me -H "Authorization: Bearer <TOKEN>"
```

### 3) 访问需要权限的接口

管理员面板（需要 `admin:panel`）：

```bash
curl -s http://localhost:8080/admin/panel -H "Authorization: Bearer <TOKEN>"
```

用户列表（需要 `user:read`）：

```bash
curl -s http://localhost:8080/api/users?page=1&pageSize=10 -H "Authorization: Bearer <TOKEN>"
```

### 4) 试试非管理员

```bash
curl -s -X POST http://localhost:8080/api/auth/login ^
  -H "Content-Type: application/json" ^
  -d "{\"username\":\"alice\",\"password\":\"<PASSWORD>\"}"
```

用这个 token 访问：

- `GET /users`：允许（viewer 有 `user:read`）
- `GET /admin/panel`：拒绝（403）

## 目录结构

- `cmd/server`: 服务入口
- `internal/config`: 配置加载（configx）
- `internal/logger`: 日志模块（logx + dix lifecycle）
- `internal/db`: dbx 连接与迁移
- `internal/httpapi`: httpx typed routes
- `internal/iam`: IAM（DDD：domain/application/infra(dbxrepo)）
- `internal/authz`: authx Authorizer（基于 IAM application）

## 审计日志

认证相关行为会在日志中输出 `auth_audit`，同时会写入 `auth_audit_logs` 表（由迁移创建）：

- `event`：行为类型（如 `login` / `refresh` / `logout` / `logout-all`）
- `user_id` / `username` / `client_ip`
- `success` / `reason`
- `created_at`（毫秒时间戳）

可通过接口查询审计日志（需要已登录且具备 `users:read`）：

```bash
curl -s "http://localhost:8080/api/auth/audit-logs?page=1&pageSize=20" ^
  -H "Authorization: Bearer <TOKEN>"
```

## 下一步怎么接入 arcgolabs 的库

当前模板已经直接使用 `configx/logx/httpx/authx/dbx/dix`，RBAC 业务模型与持久化在 `internal/iam`（DDD 风格）。

