package httpapi

import (
	"strings"
	"sync"
	"time"
)

type refreshRevocations struct {
	mu            sync.Mutex
	now           func() time.Time
	until         map[string]time.Time
	subjectCutoff map[string]time.Time
}

func newRefreshRevocations() *refreshRevocations {
	return &refreshRevocations{
		now:           time.Now,
		until:         map[string]time.Time{},
		subjectCutoff: map[string]time.Time{},
	}
}

func (r *refreshRevocations) revoke(token string, expiresAt time.Time) {
	if r == nil {
		return
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.until[token] = expiresAt
	r.gcExpiredLocked(r.now())
}

func (r *refreshRevocations) isRevoked(token string) bool {
	if r == nil {
		return false
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	until, ok := r.until[token]
	if !ok {
		return false
	}
	if r.now().After(until) {
		delete(r.until, token)
		return false
	}
	return true
}

func (r *refreshRevocations) revokeSubjectBefore(subject string, at time.Time) {
	if r == nil {
		return
	}
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.subjectCutoff[subject] = at
}

func (r *refreshRevocations) isSubjectRevoked(subject string, issuedAt time.Time) bool {
	if r == nil {
		return false
	}
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff, ok := r.subjectCutoff[subject]
	if !ok {
		return false
	}
	return !issuedAt.After(cutoff)
}

func (r *refreshRevocations) gcExpiredLocked(now time.Time) {
	if len(r.until) < 2048 {
		return
	}
	for token, until := range r.until {
		if now.After(until) {
			delete(r.until, token)
		}
	}
}
