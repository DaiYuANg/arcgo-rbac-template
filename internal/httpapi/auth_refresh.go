package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

type refreshSession struct {
	Subject string   `json:"sub"`
	Roles   []string `json:"roles"`
}

func (e *AuthEndpoint) refreshKey(token string) string {
	prefix := strings.TrimSpace(e.cachePrefix)
	if prefix == "" {
		prefix = "arcgo:"
	}
	return prefix + "rt:" + token
}

func (e *AuthEndpoint) issueOpaqueRefresh(ctx context.Context, subject string, roles []string) (string, error) {
	token, err := randomToken(32)
	if err != nil {
		return "", fmt.Errorf("random token: %w", err)
	}
	sess := refreshSession{Subject: subject, Roles: roles}
	raw, err := jsonMarshal(sess)
	if err != nil {
		return "", err
	}
	ttl := e.cfg.Auth.RefreshTokenTTL
	if ttl <= 0 {
		ttl = 7 * 24 * time.Hour
	}
	if err := e.cache.Set(ctx, e.refreshKey(token), raw, ttl); err != nil {
		return "", fmt.Errorf("refresh cache set: %w", err)
	}
	return token, nil
}

// consumeOpaqueRefresh loads and invalidates the refresh token (rotation).
func (e *AuthEndpoint) consumeOpaqueRefresh(ctx context.Context, token string) (refreshSession, error) {
	key := e.refreshKey(token)
	raw, err := e.cache.Get(ctx, key)
	if err != nil || len(raw) == 0 {
		return refreshSession{}, errors.New("refresh token not found")
	}
	if err := e.cache.Delete(ctx, key); err != nil {
		return refreshSession{}, fmt.Errorf("refresh cache delete: %w", err)
	}
	var sess refreshSession
	if err := jsonUnmarshal(raw, &sess); err != nil {
		return refreshSession{}, err
	}
	if strings.TrimSpace(sess.Subject) == "" {
		return refreshSession{}, errors.New("invalid refresh session")
	}
	if sess.Roles == nil {
		sess.Roles = []string{}
	}
	return sess, nil
}

func randomToken(n int) (string, error) {
	if n <= 0 {
		n = 32
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("rand read: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

