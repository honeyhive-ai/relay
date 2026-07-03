package relay

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
)

// tokenPrefix is the first segment of the compact wire format:
//
//	hrt1.<b64url(claims_json)>.<b64url(ed25519_sig)>
//
// The signature covers the ASCII bytes of "hrt1.<b64url(claims_json)>" (the
// first two parts joined by "."), so claims can't be altered without the key.
const tokenPrefix = "hrt1"

// TokenClaims are carried by a signed entitlement token. Forward-compatible:
// unknown fields are ignored on decode, and the relay ignores any capability it
// does not yet enforce. Field names match the Rust issuer's serde output.
type TokenClaims struct {
	Sub           string   `json:"sub"`
	Plan          string   `json:"plan"`
	Exp           uint64   `json:"exp"`
	MaxMembers    *uint32  `json:"max_members"`
	RetentionDays *uint32  `json:"retention_days"`
	Turn          bool     `json:"turn"`
	Caps          []string `json:"caps"`
}

// IsExpired reports whether Exp is set and now-or-past.
func (c TokenClaims) IsExpired(nowUnix int64) bool {
	return c.Exp != 0 && uint64(nowUnix) >= c.Exp
}

// HasCap reports whether the subject holds a named RBAC capability.
func (c TokenClaims) HasCap(cap string) bool {
	for _, x := range c.Caps {
		if x == cap {
			return true
		}
	}
	return false
}

// verifyToken validates a compact hrt1 token against the issuer public key,
// returning the claims iff the signature is valid. Expiry is not checked here
// (kept clock-free); the caller checks IsExpired.
func verifyToken(token string, pub ed25519.PublicKey) (TokenClaims, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != tokenPrefix {
		return TokenClaims{}, false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return TokenClaims{}, false
	}
	signed := parts[0] + "." + parts[1]
	if !ed25519.Verify(pub, []byte(signed), sig) {
		return TokenClaims{}, false
	}
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return TokenClaims{}, false
	}
	var claims TokenClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return TokenClaims{}, false
	}
	return claims, true
}

// parsePubkey parses an Ed25519 public key from hex (64 chars) or base64
// (url-safe or standard, with or without padding).
func parsePubkey(s string) (ed25519.PublicKey, bool) {
	s = strings.TrimSpace(s)
	var raw []byte
	if len(s) == 64 && isHex(s) {
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, false
		}
		raw = b
	} else {
		for _, enc := range []*base64.Encoding{
			base64.RawURLEncoding, base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding,
		} {
			if b, err := enc.DecodeString(s); err == nil {
				raw = b
				break
			}
		}
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, false
	}
	return ed25519.PublicKey(raw), true
}

func isHex(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

// entitlementKind selects who may use the relay.
type entitlementKind int

const (
	// entOpen — self-host default: anyone may connect (the URL is not a secret).
	entOpen entitlementKind = iota
	// entTokens — a static allowlist of opaque bearer tokens (coarse on/off gate).
	entTokens
	// entSigned — signed hrt1 tokens verified against the issuer's public key.
	entSigned
)

// entitlementPolicy decides whether a presented bearer token is admitted.
type entitlementPolicy struct {
	kind   entitlementKind
	tokens map[string]struct{} // entTokens
	pubkey ed25519.PublicKey   // entSigned
}

// entitlementFromEnv resolves the policy, most specific first:
//  1. HIVE_RELAY_TOKEN_PUBKEY (hex/base64 Ed25519) → verify signed tokens;
//  2. HIVE_RELAY_ACCESS_TOKENS (comma-separated)   → static allowlist;
//  3. otherwise                                    → open (self-host default).
func entitlementFromEnv() entitlementPolicy {
	if pk := os.Getenv("HIVE_RELAY_TOKEN_PUBKEY"); pk != "" {
		if vk, ok := parsePubkey(pk); ok {
			return entitlementPolicy{kind: entSigned, pubkey: vk}
		}
		// Parsing failed — fall through, but make it loud.
		os.Stderr.WriteString("HIVE_RELAY_TOKEN_PUBKEY set but unparseable; ignoring\n")
	}
	if v := strings.TrimSpace(os.Getenv("HIVE_RELAY_ACCESS_TOKENS")); v != "" {
		set := map[string]struct{}{}
		for _, t := range strings.Split(v, ",") {
			if t = strings.TrimSpace(t); t != "" {
				set[t] = struct{}{}
			}
		}
		if len(set) > 0 {
			return entitlementPolicy{kind: entTokens, tokens: set}
		}
	}
	return entitlementPolicy{kind: entOpen}
}

// EntitlementFromEnv is the exported, interface-typed constructor the OSS binary
// and downstream builds use to get the default env-driven verifier.
func EntitlementFromEnv() EntitlementVerifier { return entitlementFromEnv() }

// Allow reports whether a presented bearer token is admitted at nowUnix. The
// returned claims are non-nil only for signed tokens (for per-plan enforcement).
// It satisfies EntitlementVerifier.
func (p entitlementPolicy) Allow(token string, nowUnix int64) (*TokenClaims, bool) {
	switch p.kind {
	case entOpen:
		return nil, true
	case entTokens:
		_, ok := p.tokens[token]
		return nil, ok
	case entSigned:
		claims, ok := verifyToken(token, p.pubkey)
		if !ok || claims.IsExpired(nowUnix) {
			return nil, false
		}
		return &claims, true
	default:
		return nil, false
	}
}
