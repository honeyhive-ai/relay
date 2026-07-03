package relay

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func testKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 7
	}
	return ed25519.NewKeyFromSeed(seed)
}

func TestTokenRoundtrip(t *testing.T) {
	sk := testKey(t)
	max := uint32(50)
	claims := TokenClaims{
		Sub: "org_acme", Plan: "team", Exp: 0,
		MaxMembers: &max, Turn: true, Caps: []string{"remove_member", "view_audit"},
	}
	tok := issueToken(sk, claims)
	got, ok := verifyToken(tok, sk.Public().(ed25519.PublicKey))
	if !ok {
		t.Fatal("valid token should verify")
	}
	if got.Sub != "org_acme" || got.Plan != "team" || got.MaxMembers == nil || *got.MaxMembers != 50 {
		t.Fatalf("claims mismatch: %+v", got)
	}
	if !got.HasCap("view_audit") || got.HasCap("manage_billing") {
		t.Fatal("cap check wrong")
	}
	if got.IsExpired(9_999_999_999) {
		t.Fatal("exp=0 never expires")
	}
}

func TestTokenRejectsTamperedClaims(t *testing.T) {
	sk := testKey(t)
	tok := issueToken(sk, TokenClaims{Sub: "a", Plan: "pro"})
	parts := strings.Split(tok, ".")
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"a","plan":"enterprise"}`))
	if _, ok := verifyToken(strings.Join(parts, "."), sk.Public().(ed25519.PublicKey)); ok {
		t.Fatal("tampered claims must not verify")
	}
}

func TestTokenRejectsWrongKey(t *testing.T) {
	sk := testKey(t)
	otherSeed := make([]byte, ed25519.SeedSize)
	for i := range otherSeed {
		otherSeed[i] = 9
	}
	other := ed25519.NewKeyFromSeed(otherSeed)
	tok := issueToken(sk, TokenClaims{Sub: "a"})
	if _, ok := verifyToken(tok, other.Public().(ed25519.PublicKey)); ok {
		t.Fatal("wrong key must not verify")
	}
}

func TestTokenRejectsMalformed(t *testing.T) {
	pub := testKey(t).Public().(ed25519.PublicKey)
	for _, bad := range []string{"nope", "hrt1.only-two", "hrt2.a.b"} {
		if _, ok := verifyToken(bad, pub); ok {
			t.Fatalf("%q should not verify", bad)
		}
	}
}

func TestExpiryCheck(t *testing.T) {
	c := TokenClaims{Exp: 1000}
	if c.IsExpired(999) || !c.IsExpired(1000) || !c.IsExpired(1001) {
		t.Fatal("expiry boundary wrong")
	}
	if (TokenClaims{Exp: 0}).IsExpired(1 << 62) {
		t.Fatal("exp=0 never expires")
	}
}

func TestPubkeyParsingHexAndB64(t *testing.T) {
	pub := testKey(t).Public().(ed25519.PublicKey)
	hexStr := hex.EncodeToString(pub)
	if got, ok := parsePubkey(hexStr); !ok || string(got) != string(pub) {
		t.Fatal("hex pubkey parse failed")
	}
	b64 := base64.StdEncoding.EncodeToString(pub)
	if got, ok := parsePubkey(b64); !ok || string(got) != string(pub) {
		t.Fatal("b64 pubkey parse failed")
	}
	if _, ok := parsePubkey("garbage"); ok {
		t.Fatal("garbage should not parse")
	}
}

// Interop: keygen/issue → verify, the path the operator + relay use together.
func TestKeygenIssueVerifyInterop(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	seedHex := hex.EncodeToString(priv.Seed())
	parsed, ok := parseSigningKey(seedHex)
	if !ok {
		t.Fatal("seed hex should parse")
	}
	tok := issueToken(parsed, TokenClaims{Sub: "cust_1", Plan: "pro", Caps: []string{}})
	pub, ok := parsePubkey(hex.EncodeToString(priv.Public().(ed25519.PublicKey)))
	if !ok {
		t.Fatal("pub hex should parse")
	}
	claims, ok := verifyToken(tok, pub)
	if !ok || claims.Sub != "cust_1" {
		t.Fatalf("interop verify failed: ok=%v %+v", ok, claims)
	}
}

func TestEntitlementPolicies(t *testing.T) {
	// Open allows everyone.
	open := entitlementPolicy{kind: entOpen}
	if _, ok := open.Allow("", 0); !ok {
		t.Fatal("open should allow no token")
	}
	if _, ok := open.Allow("anything", 0); !ok {
		t.Fatal("open should allow any token")
	}

	// Tokens checks membership.
	gated := entitlementPolicy{kind: entTokens, tokens: map[string]struct{}{"paid-tok": {}}}
	if _, ok := gated.Allow("", 0); ok {
		t.Fatal("gated should reject empty")
	}
	if _, ok := gated.Allow("free-guess", 0); ok {
		t.Fatal("gated should reject unknown")
	}
	if _, ok := gated.Allow("paid-tok", 0); !ok {
		t.Fatal("gated should accept member")
	}

	// Signed verifies + enforces expiry.
	sk := testKey(t)
	signed := entitlementPolicy{kind: entSigned, pubkey: sk.Public().(ed25519.PublicKey)}
	tok := issueToken(sk, TokenClaims{Sub: "x", Exp: 1000})
	if _, ok := signed.Allow(tok, 999); !ok {
		t.Fatal("valid unexpired token should pass")
	}
	if _, ok := signed.Allow(tok, 1001); ok {
		t.Fatal("expired token should fail")
	}
}
