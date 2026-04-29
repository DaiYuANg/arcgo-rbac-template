package httpapi

import (
	"log/slog"
	"strings"

	authjwt "github.com/arcgolabs/authx/jwt"
	"github.com/arcgolabs/httpx"
)

func (e *AuthEndpoint) subjectRevokedByClaims(subject string, claims *authjwt.Claims) bool {
	if claims == nil || claims.IssuedAt == nil {
		return false
	}
	return e.revocations.isSubjectRevoked(subject, claims.IssuedAt.Time)
}

func (e *AuthEndpoint) issueJWTRefreshPair(rawRefresh, subject string, claims authjwt.Claims, clientIP string) (*tokenWithCookieOutput, error) {
	access, err := e.signAccessToken(subject, claims.Roles)
	if err != nil {
		e.audit("refresh", subject, "", clientIP, false, "token_sign_failed")
		return nil, httpx.NewError(500, "token_sign_failed", err)
	}
	if claims.ExpiresAt != nil {
		e.revocations.revoke(rawRefresh, claims.ExpiresAt.Time)
	}
	newRefresh, err := e.signRefreshToken(subject, claims.Roles)
	if err != nil {
		e.audit("refresh", subject, "", clientIP, false, "refresh_sign_failed")
		return nil, httpx.NewError(500, "token_sign_failed", err)
	}
	e.audit("refresh", subject, "", clientIP, true, "")
	return &tokenWithCookieOutput{
		Body:      TokenResponse{AccessToken: access},
		SetCookie: buildRefreshCookie(newRefresh, !e.cfg.Auth.AllowInsecureDev, int(e.cfg.Auth.RefreshTokenTTL.Seconds())),
	}, nil
}

func (e *AuthEndpoint) audit(event, userID, username, clientIP string, success bool, reason string) {
	logger := e.logger
	if logger == nil {
		logger = slog.Default()
	}
	record := authAuditRecord{
		Event:    strings.TrimSpace(event),
		UserID:   strings.TrimSpace(userID),
		Username: strings.TrimSpace(username),
		ClientIP: strings.TrimSpace(clientIP),
		Success:  success,
		Reason:   strings.TrimSpace(reason),
	}
	logger.Info("auth_audit",
		"event", record.Event,
		"user_id", record.UserID,
		"username", record.Username,
		"client_ip", record.ClientIP,
		"success", record.Success,
		"reason", record.Reason,
	)
	if e.auditSink != nil {
		e.auditSink.Write(record)
	}
}
