package relay

import (
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Abuse controls for the hot paths. Both are generous by default and env-tunable
// so they only ever stop abuse, never legitimate sync / catch-up.
//
//   HIVE_RELAY_PUSH_RATE   per-IP envelope-push tokens/sec (0 disables)   default 100
//   HIVE_RELAY_PUSH_BURST  per-IP push burst capacity                     default 300
//   HIVE_RELAY_MAX_SSE     max concurrent SSE streams (0 = unlimited)     default 2000

// ipRateLimiter is a per-key token bucket. Keyed on the real client IP (see
// clientIP, which prefers Fly-Client-IP behind the edge).
type ipRateLimiter struct {
	mu     sync.Mutex
	rate   float64 // tokens per second
	burst  float64 // bucket capacity
	seen   map[string]*ipBucket
	lastGC time.Time
}

type ipBucket struct {
	tokens float64
	last   time.Time
}

func newIPRateLimiter(rate, burst float64) *ipRateLimiter {
	return &ipRateLimiter{rate: rate, burst: burst, seen: map[string]*ipBucket{}, lastGC: time.Now()}
}

// allow consumes one token for key; false means the caller is over the limit.
func (l *ipRateLimiter) allow(key string) bool {
	if l == nil || l.rate <= 0 {
		return true
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	// Occasionally drop idle buckets so the map can't grow without bound.
	if now.Sub(l.lastGC) > 10*time.Minute {
		for k, b := range l.seen {
			if now.Sub(b.last) > 10*time.Minute {
				delete(l.seen, k)
			}
		}
		l.lastGC = now
	}
	b := l.seen[key]
	if b == nil {
		b = &ipBucket{tokens: l.burst, last: now}
		l.seen[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// concurrencyLimiter caps concurrent long-lived handlers (SSE streams) so an
// attacker can't exhaust goroutines/FDs by opening streams without bound.
type concurrencyLimiter struct {
	max int64
	cur atomic.Int64
}

func newConcurrencyLimiter(max int64) *concurrencyLimiter { return &concurrencyLimiter{max: max} }

// acquire reserves a slot; ok=false means the cap is reached. Call the returned
// func to release (safe even when ok=false or the limiter is nil/unlimited).
func (c *concurrencyLimiter) acquire() (release func(), ok bool) {
	if c == nil || c.max <= 0 {
		return func() {}, true
	}
	if c.cur.Add(1) > c.max {
		c.cur.Add(-1)
		return func() {}, false
	}
	var once sync.Once
	return func() { once.Do(func() { c.cur.Add(-1) }) }, true
}

func envFloat(name string, def float64) float64 {
	if v := os.Getenv(name); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}

func envInt64(name string, def int64) int64 {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}
