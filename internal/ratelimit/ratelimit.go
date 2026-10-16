// Package ratelimit provides a small request-level rate limiter shared by the
// DNS resolver and the HTTP probes.
package ratelimit

import (
	"context"
	"sync"
	"time"
)

// Limiter spaces requests evenly so that no more than the configured number
// start in any one second. A nil *Limiter never blocks.
type Limiter struct {
	mu       sync.Mutex
	next     time.Time
	interval time.Duration
}

// New returns a Limiter allowing perSecond requests per second.
// perSecond <= 0 disables limiting.
func New(perSecond int) *Limiter {
	if perSecond <= 0 {
		return nil
	}
	return &Limiter{interval: time.Second / time.Duration(perSecond)}
}

// Wait blocks until the next request may start or ctx is cancelled.
func (l *Limiter) Wait(ctx context.Context) error {
	if l == nil {
		return ctx.Err()
	}
	l.mu.Lock()
	now := time.Now()
	if l.next.Before(now) {
		l.next = now
	}
	wait := l.next.Sub(now)
	l.next = l.next.Add(l.interval)
	l.mu.Unlock()

	if wait <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
