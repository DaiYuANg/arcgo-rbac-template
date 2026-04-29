package httpapi

import (
	"strings"
	"sync"
	"time"
)

type authRateLimiter struct {
	mu      sync.Mutex
	now     func() time.Time
	buckets map[string]rateBucket
}

type rateBucket struct {
	start time.Time
	hits  int
}

func newAuthRateLimiter() *authRateLimiter {
	return &authRateLimiter{
		now:     time.Now,
		buckets: map[string]rateBucket{},
	}
}

func (l *authRateLimiter) allow(key string, limit int, window time.Duration) (bool, time.Duration) {
	if l == nil || strings.TrimSpace(key) == "" {
		return true, 0
	}
	if limit <= 0 || window <= 0 {
		return true, 0
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	b, ok := l.buckets[key]
	if !ok || now.Sub(b.start) >= window {
		l.buckets[key] = rateBucket{start: now, hits: 1}
		l.gcExpired(now, window)
		return true, 0
	}

	if b.hits >= limit {
		retryAfter := window - now.Sub(b.start)
		retryAfter = max(retryAfter, 0)
		return false, retryAfter
	}

	b.hits++
	l.buckets[key] = b
	return true, 0
}

func (l *authRateLimiter) gcExpired(now time.Time, window time.Duration) {
	if len(l.buckets) < 2048 {
		return
	}
	maxAge := 2 * window
	for k, v := range l.buckets {
		if now.Sub(v.start) >= maxAge {
			delete(l.buckets, k)
		}
	}
}

func normalizeClientIP(xForwardedFor, xRealIP string) string {
	if xForwardedFor != "" {
		for part := range strings.SplitSeq(xForwardedFor, ",") {
			ip := strings.TrimSpace(part)
			if ip != "" {
				return ip
			}
		}
	}
	if strings.TrimSpace(xRealIP) != "" {
		return strings.TrimSpace(xRealIP)
	}
	return "unknown"
}
