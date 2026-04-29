package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type refreshSession struct {
	Subject  string   `json:"sub"`
	Roles    []string `json:"roles"`
	IssuedAt int64    `json:"iat"`
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
	sess := refreshSession{Subject: subject, Roles: roles, IssuedAt: time.Now().Unix()}
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
	if deleteErr := e.cache.Delete(ctx, key); deleteErr != nil {
		return refreshSession{}, fmt.Errorf("refresh cache delete: %w", deleteErr)
	}
	sess, err := decodeRefreshSession(raw)
	if err != nil {
		return refreshSession{}, err
	}
	cutoff := e.loadSubjectRefreshCutoff(ctx, sess.Subject)
	if cutoff > 0 && sess.IssuedAt <= cutoff {
		return refreshSession{}, errors.New("refresh token revoked")
	}
	return sess, nil
}

func (e *AuthEndpoint) refreshCutoffKey(subject string) string {
	prefix := strings.TrimSpace(e.cachePrefix)
	if prefix == "" {
		prefix = "arcgo:"
	}
	return prefix + "rt_cutoff:" + strings.TrimSpace(subject)
}

func (e *AuthEndpoint) setSubjectRefreshCutoff(ctx context.Context, subject string, at time.Time) error {
	subject = strings.TrimSpace(subject)
	if subject == "" || e.cache == nil {
		return nil
	}
	ttl := e.cfg.Auth.RefreshTokenTTL
	if ttl <= 0 {
		ttl = 7 * 24 * time.Hour
	}
	if err := e.cache.Set(ctx, e.refreshCutoffKey(subject), []byte(strconv.FormatInt(at.Unix(), 10)), ttl); err != nil {
		return fmt.Errorf("set refresh cutoff: %w", err)
	}
	return nil
}

func (e *AuthEndpoint) loadSubjectRefreshCutoff(ctx context.Context, subject string) int64 {
	subject = strings.TrimSpace(subject)
	if subject == "" || e.cache == nil {
		return 0
	}
	raw, err := e.cache.Get(ctx, e.refreshCutoffKey(subject))
	if err != nil || len(raw) == 0 {
		return 0
	}
	v, parseErr := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if parseErr != nil {
		return 0
	}
	return v
}

func decodeRefreshSession(raw []byte) (refreshSession, error) {
	var sess refreshSession
	if err := jsonUnmarshal(raw, &sess); err != nil {
		return refreshSession{}, err
	}
	if strings.TrimSpace(sess.Subject) == "" {
		return refreshSession{}, errors.New("invalid refresh session")
	}
	if sess.IssuedAt <= 0 {
		sess.IssuedAt = time.Now().Unix()
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
