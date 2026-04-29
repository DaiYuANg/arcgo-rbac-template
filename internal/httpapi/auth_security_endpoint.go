package httpapi

import (
	"context"
	"fmt"
	"time"

	authjwt "github.com/arcgolabs/authx/jwt"
	"github.com/arcgolabs/httpx"
	"github.com/golang-jwt/jwt/v5"
)

type logoutInput struct {
	Cookie        string `header:"Cookie"`
	XForwardedFor string `header:"X-Forwarded-For"`
	XRealIP       string `header:"X-Real-IP"`
}

type logoutAllInput struct {
	Authorization string `header:"Authorization"`
	XForwardedFor string `header:"X-Forwarded-For"`
	XRealIP       string `header:"X-Real-IP"`
}

type logoutOutput struct {
	Body      map[string]bool `doc:"Logout result"`
	SetCookie string          `header:"Set-Cookie"`
}

func (e *AuthEndpoint) Logout(ctx context.Context, in *logoutInput) (*logoutOutput, error) {
	e.ensureRuntime()
	clientIP := normalizeClientIP(in.XForwardedFor, in.XRealIP)
	rawRefresh := cookieValue(in.Cookie, "refreshToken")
	if rawRefresh != "" {
		if err := e.revokeRefreshOnLogout(ctx, rawRefresh); err != nil {
			e.audit("logout", "", "", clientIP, false, "logout_failed")
			return nil, httpx.NewError(500, "logout_failed", err)
		}
	}
	e.audit("logout", "", "", clientIP, true, "")

	return &logoutOutput{
		Body:      map[string]bool{"success": true},
		SetCookie: buildExpiredRefreshCookie(!e.cfg.Auth.AllowInsecureDev),
	}, nil
}

func (e *AuthEndpoint) LogoutAll(ctx context.Context, in *logoutAllInput) (*logoutOutput, error) {
	e.ensureRuntime()
	clientIP := normalizeClientIP(in.XForwardedFor, in.XRealIP)
	if e.engine == nil {
		return nil, httpx.NewError(500, "auth_engine_missing")
	}

	p, err := e.authorizeAndEnforce(ctx, in.Authorization, "", "")
	if err != nil {
		e.audit("logout_all", "", "", clientIP, false, "unauthorized")
		return nil, err
	}
	userID := p.ID
	now := time.Now()

	if e.cache != nil {
		if err := e.setSubjectRefreshCutoff(ctx, userID, now); err != nil {
			e.audit("logout_all", userID, "", clientIP, false, "logout_all_failed")
			return nil, httpx.NewError(500, "logout_all_failed", err)
		}
	} else {
		e.revocations.revokeSubjectBefore(userID, now)
	}
	e.audit("logout_all", userID, "", clientIP, true, "")

	return &logoutOutput{
		Body:      map[string]bool{"success": true},
		SetCookie: buildExpiredRefreshCookie(!e.cfg.Auth.AllowInsecureDev),
	}, nil
}

func (e *AuthEndpoint) revokeRefreshOnLogout(ctx context.Context, rawRefresh string) error {
	if e.cache != nil {
		if err := e.cache.Delete(ctx, e.refreshKey(rawRefresh)); err != nil {
			return fmt.Errorf("delete refresh token: %w", err)
		}
		return nil
	}

	claims := authjwt.Claims{}
	if _, err := jwt.ParseWithClaims(rawRefresh, &claims, func(token *jwt.Token) (any, error) {
		return []byte(e.cfg.Auth.JWTSecret), nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name})); err == nil && claims.ExpiresAt != nil {
		e.revocations.revoke(rawRefresh, claims.ExpiresAt.Time)
	}
	return nil
}

func (e *AuthEndpoint) ensureRuntime() {
	e.runtimeOnce.Do(func() {
		if e.limiter == nil {
			e.limiter = newAuthRateLimiter()
		}
		if e.revocations == nil {
			e.revocations = newRefreshRevocations()
		}
	})
}

func (e *AuthEndpoint) loginRateLimit() int {
	if e.cfg.Auth.LoginRateLimit > 0 {
		return e.cfg.Auth.LoginRateLimit
	}
	return 20
}

func (e *AuthEndpoint) loginRateWindow() time.Duration {
	if e.cfg.Auth.LoginRateWindow > 0 {
		return e.cfg.Auth.LoginRateWindow
	}
	return time.Minute
}

func (e *AuthEndpoint) refreshRateLimit() int {
	if e.cfg.Auth.RefreshRateLimit > 0 {
		return e.cfg.Auth.RefreshRateLimit
	}
	return 60
}

func (e *AuthEndpoint) refreshRateWindow() time.Duration {
	if e.cfg.Auth.RefreshRateWindow > 0 {
		return e.cfg.Auth.RefreshRateWindow
	}
	return time.Minute
}
