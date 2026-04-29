package httpapi

import (
	"fmt"
	"strings"
	"time"
)

func buildRefreshCookie(token string, secure bool, maxAgeSeconds int) string {
	if maxAgeSeconds <= 0 {
		maxAgeSeconds = int((7 * 24 * time.Hour).Seconds())
	}
	parts := []string{
		"refreshToken=" + token,
		"Path=/",
		"HttpOnly",
		"SameSite=Lax",
		fmt.Sprintf("Max-Age=%d", maxAgeSeconds),
	}
	if secure {
		parts = append(parts, "Secure")
	}
	return strings.Join(parts, "; ")
}

func buildExpiredRefreshCookie(secure bool) string {
	parts := []string{
		"refreshToken=",
		"Path=/",
		"HttpOnly",
		"SameSite=Lax",
		"Max-Age=0",
		"Expires=Thu, 01 Jan 1970 00:00:00 GMT",
	}
	if secure {
		parts = append(parts, "Secure")
	}
	return strings.Join(parts, "; ")
}

func cookieValue(rawCookie, key string) string {
	rawCookie = strings.TrimSpace(rawCookie)
	if rawCookie == "" || strings.TrimSpace(key) == "" {
		return ""
	}
	for part := range strings.SplitSeq(rawCookie, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.TrimSpace(kv[0])
		v := strings.TrimSpace(kv[1])
		if k == key {
			return v
		}
	}
	return ""
}
