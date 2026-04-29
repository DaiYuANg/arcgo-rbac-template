// Package httpapi implements HTTP endpoints using httpx (Fiber adapter).
package httpapi

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/DaiYuANg/arcgo/kvx"
	"github.com/arcgolabs/arcgo-rbac-template/internal/authn"
	"github.com/arcgolabs/arcgo-rbac-template/internal/config"
	"github.com/arcgolabs/authx"
	authjwt "github.com/arcgolabs/authx/jwt"
	"github.com/arcgolabs/dbx"
	"github.com/arcgolabs/httpx"
	"github.com/danielgtaylor/huma/v2"
	"github.com/golang-jwt/jwt/v5"
)

type AuthEndpoint struct {
	cfg         config.Config
	engine      *authx.Engine
	cache       kvx.KV
	cachePrefix string
	core        *dbx.DB
	logger      *slog.Logger
	auditSink   authAuditSink

	runtimeOnce sync.Once
	limiter     *authRateLimiter
	revocations *refreshRevocations
}

func (e *AuthEndpoint) EndpointSpec() httpx.EndpointSpec {
	return httpx.EndpointSpec{
		Prefix:        "/api/auth",
		Tags:          httpx.Tags("auth"),
		SummaryPrefix: "Auth",
		Description:   "Auth endpoints",
	}
}

func (e *AuthEndpoint) Register(registrar httpx.Registrar) {
	g := registrar.Scope()
	httpx.MustGroupGet(g, "/audit-logs", e.ListAuditLogs, func(op *huma.Operation) {
		op.Summary = "List auth audit logs"
	})
	httpx.MustGroupPost(g, "/login", e.Login, func(op *huma.Operation) {
		op.Summary = "Login"
	})
	httpx.MustGroupPost(g, "/refresh", e.Refresh, func(op *huma.Operation) {
		op.Summary = "Refresh access token"
	})
	httpx.MustGroupPost(g, "/logout", e.Logout, func(op *huma.Operation) {
		op.Summary = "Logout and revoke refresh token"
	})
	httpx.MustGroupPost(g, "/logout-all", e.LogoutAll, func(op *huma.Operation) {
		op.Summary = "Logout all sessions for current user"
	})
}

// tokenWithCookieOutput follows Huma: only the field named Body is serialized as JSON
// (flat shape from TokenResponse at the wire — not {"body":{...}}).
type tokenWithCookieOutput struct {
	Body      TokenResponse `doc:"JWT access token payload"`
	SetCookie string        `header:"Set-Cookie"`
}

// loginHTTPInput is the Huma request shape: HTTP JSON body binds to field `Body`.
// Without a literal `Body` field, huma skips parsing the POST body entirely.
// Raw JSON is unmarshaled directly into LoginRequest (flat {"username","password"}).
type loginHTTPInput struct {
	Body          LoginRequest
	XForwardedFor string `header:"X-Forwarded-For"`
	XRealIP       string `header:"X-Real-IP"`
}

func (e *AuthEndpoint) Login(ctx context.Context, in *loginHTTPInput) (*tokenWithCookieOutput, error) {
	e.ensureRuntime()
	if e.engine == nil {
		return nil, httpx.NewError(500, "auth_engine_missing")
	}
	clientIP := normalizeClientIP(in.XForwardedFor, in.XRealIP)
	username := strings.TrimSpace(in.Body.Username)
	password := in.Body.Password

	loginKey := "login:" + clientIP + ":" + strings.ToLower(username)
	if allow, retryAfter := e.limiter.allow(loginKey, e.loginRateLimit(), e.loginRateWindow()); !allow {
		e.audit("login_rate_limited", "", username, clientIP, false, "too_many_requests")
		return nil, httpx.NewError(429, "too_many_requests", fmt.Errorf("retry after %s", retryAfter.Truncate(time.Second)))
	}

	result, err := e.engine.Check(ctx, authn.PasswordCredential{Username: username, Password: password})
	if err != nil || result.Principal == nil {
		e.audit("login", "", username, clientIP, false, "unauthenticated")
		return nil, httpx.NewError(401, "unauthenticated", err)
	}

	p, ok := result.Principal.(authx.Principal)
	if !ok || strings.TrimSpace(p.ID) == "" {
		e.audit("login", "", username, clientIP, false, "invalid_principal")
		return nil, httpx.NewError(401, "unauthenticated")
	}

	roles := []string(nil)
	if p.Roles != nil {
		roles = p.Roles.Values()
	}
	if roles == nil {
		roles = []string{}
	}
	raw, err := e.signAccessToken(p.ID, roles)
	if err != nil {
		e.audit("login", p.ID, username, clientIP, false, "token_sign_failed")
		return nil, httpx.NewError(500, "token_sign_failed", err)
	}

	var refresh string
	if e.cache != nil {
		opaque, serr := e.issueOpaqueRefresh(ctx, p.ID, roles)
		if serr != nil {
			e.audit("login", p.ID, username, clientIP, false, "refresh_issue_failed")
			return nil, httpx.NewError(500, "token_sign_failed", serr)
		}
		refresh = opaque
	} else {
		var serr error
		refresh, serr = e.signRefreshToken(p.ID, roles)
		if serr != nil {
			e.audit("login", p.ID, username, clientIP, false, "refresh_sign_failed")
			return nil, httpx.NewError(500, "token_sign_failed", serr)
		}
	}
	e.audit("login", p.ID, username, clientIP, true, "")

	return &tokenWithCookieOutput{
		Body:      TokenResponse{AccessToken: raw},
		SetCookie: buildRefreshCookie(refresh, !e.cfg.Auth.AllowInsecureDev, int(e.cfg.Auth.RefreshTokenTTL.Seconds())),
	}, nil
}

type refreshInput struct {
	Cookie        string `header:"Cookie"`
	XForwardedFor string `header:"X-Forwarded-For"`
	XRealIP       string `header:"X-Real-IP"`
}

func (e *AuthEndpoint) Refresh(ctx context.Context, in *refreshInput) (*tokenWithCookieOutput, error) {
	e.ensureRuntime()
	clientIP := normalizeClientIP(in.XForwardedFor, in.XRealIP)
	if err := e.checkRefreshRate(clientIP); err != nil {
		return nil, err
	}
	rawRefresh := strings.TrimSpace(cookieValue(in.Cookie, "refreshToken"))
	if rawRefresh == "" {
		e.audit("refresh", "", "", clientIP, false, "missing_refresh_cookie")
		return nil, httpx.NewError(401, "unauthorized")
	}
	if e.cache != nil {
		return e.refreshWithOpaqueToken(ctx, rawRefresh, clientIP)
	}
	return e.refreshWithJWTToken(rawRefresh, clientIP)
}

func (e *AuthEndpoint) checkRefreshRate(clientIP string) error {
	refreshKey := "refresh:" + clientIP
	if allow, retryAfter := e.limiter.allow(refreshKey, e.refreshRateLimit(), e.refreshRateWindow()); !allow {
		e.audit("refresh_rate_limited", "", "", clientIP, false, "too_many_requests")
		return httpx.NewError(429, "too_many_requests", fmt.Errorf("retry after %s", retryAfter.Truncate(time.Second)))
	}
	return nil
}

func (e *AuthEndpoint) refreshWithOpaqueToken(ctx context.Context, rawRefresh, clientIP string) (*tokenWithCookieOutput, error) {
	session, err := e.consumeOpaqueRefresh(ctx, rawRefresh)
	if err != nil {
		e.audit("refresh", "", "", clientIP, false, "unauthorized")
		return nil, httpx.NewError(401, "unauthorized", err)
	}
	access, err := e.signAccessToken(session.Subject, session.Roles)
	if err != nil {
		e.audit("refresh", session.Subject, "", clientIP, false, "token_sign_failed")
		return nil, httpx.NewError(500, "token_sign_failed", err)
	}
	newRefresh, err := e.issueOpaqueRefresh(ctx, session.Subject, session.Roles)
	if err != nil {
		e.audit("refresh", session.Subject, "", clientIP, false, "refresh_issue_failed")
		return nil, httpx.NewError(500, "token_sign_failed", err)
	}
	e.audit("refresh", session.Subject, "", clientIP, true, "")
	return &tokenWithCookieOutput{
		Body:      TokenResponse{AccessToken: access},
		SetCookie: buildRefreshCookie(newRefresh, !e.cfg.Auth.AllowInsecureDev, int(e.cfg.Auth.RefreshTokenTTL.Seconds())),
	}, nil
}

func (e *AuthEndpoint) refreshWithJWTToken(rawRefresh, clientIP string) (*tokenWithCookieOutput, error) {
	claims, err := e.parseRefreshClaims(rawRefresh)
	if err != nil {
		e.audit("refresh", "", "", clientIP, false, "unauthorized")
		return nil, httpx.NewError(401, "unauthorized", err)
	}
	sub := strings.TrimSpace(claims.Subject)
	if e.revocations.isRevoked(rawRefresh) {
		e.audit("refresh", sub, "", clientIP, false, "token_revoked")
		return nil, httpx.NewError(401, "unauthorized")
	}
	if sub == "" {
		e.audit("refresh", "", "", clientIP, false, "unauthorized")
		return nil, httpx.NewError(401, "unauthorized")
	}
	if e.subjectRevokedByClaims(sub, &claims) {
		e.audit("refresh", sub, "", clientIP, false, "subject_revoked")
		return nil, httpx.NewError(401, "unauthorized")
	}
	return e.issueJWTRefreshPair(rawRefresh, sub, claims, clientIP)
}

func (e *AuthEndpoint) signAccessToken(subject string, roles []string) (string, error) {
	now := time.Now()
	claims := authjwt.Claims{
		Roles: roles,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			Issuer:    e.cfg.Auth.Issuer,
			Audience:  jwt.ClaimStrings{e.cfg.Auth.Audience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(-5 * time.Second)),
			ExpiresAt: jwt.NewNumericDate(now.Add(e.cfg.Auth.AccessTokenTTL)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	raw, err := tok.SignedString([]byte(e.cfg.Auth.JWTSecret))
	if err != nil {
		return "", fmt.Errorf("sign access token: %w", err)
	}
	return raw, nil
}

func (e *AuthEndpoint) signRefreshToken(subject string, roles []string) (string, error) {
	ttl := e.cfg.Auth.RefreshTokenTTL
	if ttl <= 0 {
		ttl = 7 * 24 * time.Hour
	}
	now := time.Now()
	claims := authjwt.Claims{
		Roles: roles,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			Issuer:    e.cfg.Auth.Issuer,
			Audience:  jwt.ClaimStrings{e.cfg.Auth.Audience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(-5 * time.Second)),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	raw, err := tok.SignedString([]byte(e.cfg.Auth.JWTSecret))
	if err != nil {
		return "", fmt.Errorf("sign refresh token: %w", err)
	}
	return raw, nil
}
