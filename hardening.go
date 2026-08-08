package relay

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"sync"
	"time"
)

// Anti-abuse controls layered on top of the content-blind relay. Every limit
// here is generous by default and env-tunable, so it only ever stops abuse,
// never legitimate sync / catch-up. Thresholds are constants (below) unless an
// env override is set.
const (
	// Per-(workspace,writer) envelope-append rate. Bounds how fast one identity
	// can churn a single workspace's retention window, so it can't rapidly evict
	// another member's history (P1-6). writer = entitlement Sub (token-gated) or
	// client IP (open relay). Tokens/sec + burst.
	defaultWSWriterRate  = 20.0
	defaultWSWriterBurst = 200.0

	// Per-IP rate on GitHub-authenticated routes (directory / account / friends),
	// plus the identity-cache TTLs that collapse repeat verifications of the same
	// token so a flood can't amplify into one outbound api.github.com call each
	// (P1-8). Positive results cached briefly; verified-invalid tokens cached even
	// more briefly so a junk-token flood still can't amplify.
	defaultGitHubAuthRate  = 30.0
	defaultGitHubAuthBurst = 120.0
	ghIdentityTTL          = 60 * time.Second
	ghNegativeTTL          = 30 * time.Second

	// Account-inbox anti-spam (P1-7): per-(sender,recipient) invite rate + a hard
	// cap on retained inbox rows per recipient (oldest evicted past the cap), also
	// GC'd by age in the prune loop (P2-13).
	defaultInviteRate      = 0.05 // ~3 invites/min sustained per (sender,recipient)
	defaultInviteBurst     = 10.0
	defaultInboxMaxRows    = 5000
	defaultInboxMaxAgeDays = 30

	// Per-workspace structural caps that bound unauthenticated growth (P2-12):
	// live pairing codes across the instance, keyring rows per workspace, and
	// candidate/presence device blobs per workspace.
	defaultMaxLivePairings     = 50000
	defaultMaxKeyringPerWS     = 2000
	defaultMaxDeviceBlobsPerWS = 1000

	// Terminal friend requests (accepted/rejected/cancelled) are swept by age in
	// the prune loop (P2-13); pending ones already expire via requestTTLSecs.
	defaultFriendReqMaxAgeDays = 30

	// /v1/health caches its store Ping result for this long so a flood of probes
	// can't hammer the backend (P3-15).
	healthPingCacheTTL = time.Second
)

// envBool reports whether an env var is set to a truthy value (1/true/yes/on).
func envBool(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// plausibleGitHubToken cheaply rejects obviously-malformed tokens before any
// outbound verification call, so junk can't amplify into api.github.com traffic
// (P1-8). Deliberately permissive: it only screens out empty / absurdly-sized /
// non-printable inputs, never a well-formed token of any GitHub token flavor.
func plausibleGitHubToken(tok string) bool {
	if len(tok) < 8 || len(tok) > 255 {
		return false
	}
	for i := 0; i < len(tok); i++ {
		c := tok[i]
		if c < 0x21 || c > 0x7e { // printable, non-space ASCII only
			return false
		}
	}
	return true
}

// writerTag identifies the writing identity for the per-(workspace,writer)
// append quota without breaking content-blindness: it uses the entitlement
// subject when a signed token is present, else the client IP. It never inspects
// the request body.
func writerTag(ctx context.Context, ip string) string {
	if c := claimsFrom(ctx); c != nil && c.Sub != "" {
		return "sub:" + c.Sub
	}
	return "ip:" + ip
}

// identityCache memoizes GitHub token → identity verifications for a short TTL,
// keyed by the token's SHA-256 (never the raw token). A nil user is a cached
// negative (a token that verified as invalid). Bounds the amplification factor
// of the uncached outbound call in verifyGitHub (P1-8).
type identityCache struct {
	mu     sync.Mutex
	ttl    time.Duration
	negTTL time.Duration
	m      map[string]idEntry
	lastGC time.Time
}

type idEntry struct {
	user    *githubUser // nil = negative (verified-invalid) cache entry
	expires time.Time
}

func newIdentityCache(ttl, negTTL time.Duration) *identityCache {
	return &identityCache{ttl: ttl, negTTL: negTTL, m: map[string]idEntry{}, lastGC: time.Now()}
}

// get returns (user, negative, hit). hit=false means the caller must verify.
func (c *identityCache) get(hash string, now time.Time) (user *githubUser, negative, hit bool) {
	if c == nil {
		return nil, false, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[hash]
	if !ok || !e.expires.After(now) {
		return nil, false, false
	}
	return e.user, e.user == nil, true
}

// put stores a verification result: user!=nil positive (ttl), user==nil negative
// (negTTL). It also opportunistically drops expired entries so the map can't grow
// without bound.
func (c *identityCache) put(hash string, user *githubUser, now time.Time) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if now.Sub(c.lastGC) > c.ttl {
		for k, e := range c.m {
			if !e.expires.After(now) {
				delete(c.m, k)
			}
		}
		c.lastGC = now
	}
	ttl := c.ttl
	if user == nil {
		ttl = c.negTTL
	}
	c.m[hash] = idEntry{user: user, expires: now.Add(ttl)}
}
