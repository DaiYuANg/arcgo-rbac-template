// Package httpapi implements HTTP endpoints using httpx (Fiber adapter).
package httpapi

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/arcgolabs/arcgo-rbac-template/internal/authn"
	"github.com/arcgolabs/arcgo-rbac-template/internal/config"
	"github.com/arcgolabs/authx"
	"github.com/DaiYuANg/arcgo/kvx"
	authjwt "github.com/arcgolabs/authx/jwt"
	"github.com/arcgolabs/httpx"
	"github.com/danielgtaylor/huma/v2"
	"github.com/golang-jwt/jwt/v5"
)

type AuthEndpoint struct {
	cfg    config.Config
	engine *authx.Engine
	cache  kvx.KV
	cachePrefix string
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
	httpx.MustGroupPost(g, "/login", e.Login, func(op *huma.Operation) {
		op.Summary = "Login"
	})
	httpx.MustGroupPost(g, "/refresh", e.Refresh, func(op *huma.Operation) {
		op.Summary = "Refresh access token"
	})
}

type loginInput struct {
	Body LoginRequest `json:"body" validate:"required"`
}

type tokenWithCookieOutput struct {
	AccessToken string `json:"accessToken"`
	SetCookie   string `header:"Set-Cookie"`
}

func (e *AuthEndpoint) Login(ctx context.Context, in *loginInput) (*tokenWithCookieOutput, error) {
	if e.engine == nil {
		return nil, httpx.NewError(500, "auth_engine_missing")
	}
	username := strings.TrimSpace(in.Body.Username)
	password := in.Body.Password

	result, err := e.engine.Check(ctx, authn.PasswordCredential{Username: username, Password: password})
	if err != nil || result.Principal == nil {
		return nil, httpx.NewError(401, "unauthenticated", err)
	}

	p, ok := result.Principal.(authx.Principal)
	if !ok || strings.TrimSpace(p.ID) == "" {
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
		return nil, httpx.NewError(500, "token_sign_failed", err)
	}

	var refresh string
	if e.cache != nil {
		opaque, serr := e.issueOpaqueRefresh(ctx, p.ID, roles)
		if serr != nil {
			return nil, httpx.NewError(500, "token_sign_failed", serr)
		}
		refresh = opaque
	} else {
		var serr error
		refresh, serr = e.signRefreshToken(p.ID, roles)
		if serr != nil {
			return nil, httpx.NewError(500, "token_sign_failed", serr)
		}
	}

	return &tokenWithCookieOutput{
		AccessToken: raw,
		SetCookie:   buildRefreshCookie(refresh, !e.cfg.Auth.AllowInsecureDev, int(e.cfg.Auth.RefreshTokenTTL.Seconds())),
	}, nil
}

type refreshInput struct {
	Cookie string `header:"Cookie"`
}

func (e *AuthEndpoint) Refresh(ctx context.Context, in *refreshInput) (*tokenWithCookieOutput, error) {
	rawRefresh := cookieValue(in.Cookie, "refreshToken")
	if strings.TrimSpace(rawRefresh) == "" {
		return nil, httpx.NewError(401, "unauthorized")
	}

	// KV-backed opaque refresh token flow (preferred when cache is enabled).
	if e.cache != nil {
		session, err := e.consumeOpaqueRefresh(ctx, rawRefresh)
		if err != nil {
			return nil, httpx.NewError(401, "unauthorized", err)
		}
		access, err := e.signAccessToken(session.Subject, session.Roles)
		if err != nil {
			return nil, httpx.NewError(500, "token_sign_failed", err)
		}
		newRefresh, err := e.issueOpaqueRefresh(ctx, session.Subject, session.Roles)
		if err != nil {
			return nil, httpx.NewError(500, "token_sign_failed", err)
		}
		return &tokenWithCookieOutput{
			AccessToken: access,
			SetCookie:   buildRefreshCookie(newRefresh, !e.cfg.Auth.AllowInsecureDev, int(e.cfg.Auth.RefreshTokenTTL.Seconds())),
		}, nil
	}

	claims := authjwt.Claims{}
	_, err := jwt.ParseWithClaims(rawRefresh, &claims, func(token *jwt.Token) (any, error) {
		return []byte(e.cfg.Auth.JWTSecret), nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}))
	if err != nil {
		return nil, httpx.NewError(401, "unauthorized", err)
	}

	sub := strings.TrimSpace(claims.Subject)
	if sub == "" {
		return nil, httpx.NewError(401, "unauthorized")
	}

	roles := claims.Roles
	access, err := e.signAccessToken(sub, roles)
	if err != nil {
		return nil, httpx.NewError(500, "token_sign_failed", err)
	}
	newRefresh, err := e.signRefreshToken(sub, roles)
	if err != nil {
		return nil, httpx.NewError(500, "token_sign_failed", err)
	}

	return &tokenWithCookieOutput{
		AccessToken: access,
		SetCookie:   buildRefreshCookie(newRefresh, !e.cfg.Auth.AllowInsecureDev, int(e.cfg.Auth.RefreshTokenTTL.Seconds())),
	}, nil
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

