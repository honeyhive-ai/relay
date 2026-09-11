package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// membershipServer builds a membership-enabled, signed-token relay for tests,
// returning the httptest server and the signing key (to mint per-user tokens
// whose Sub is the caller's account).
func membershipServer(t *testing.T) (*httptest.Server, ed25519.PrivateKey) {
	t.Helper()
	sk := testKey(t)
	srv := New(Options{
		Store:       newMemoryStore(),
		Entitlement: entitlementPolicy{kind: entSigned, pubkey: sk.Public().(ed25519.PublicKey)},
		Membership:  true,
	})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, sk
}

// req performs an authenticated JSON request and returns (status, body).
func req(t *testing.T, method, url, token string, body any) (int, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	r, _ := http.NewRequest(method, url, rdr)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

// ── Store-level ──────────────────────────────────────────────────────────────

func TestClaimFirstWins(t *testing.T) {
	s := newMemoryStore()
	ctx := context.Background()
	ok, err := s.ClaimWorkspace(ctx, "w", "github:1", "alice", 100)
	if err != nil || !ok {
		t.Fatalf("first claim should succeed: ok=%v err=%v", ok, err)
	}
	ok, _ = s.ClaimWorkspace(ctx, "w", "github:2", "bob", 200)
	if ok {
		t.Fatal("second claim must be a no-op (already claimed)")
	}
	role, found, _ := s.MemberRole(ctx, "w", "github:1")
	if !found || role != "owner" {
		t.Fatalf("claimer should be owner, got %q found=%v", role, found)
	}
	if _, found, _ := s.MemberRole(ctx, "w", "github:2"); found {
		t.Fatal("the losing claimant must not be enrolled")
	}
}

func TestUpsertAndRemove(t *testing.T) {
	s := newMemoryStore()
	ctx := context.Background()
	s.ClaimWorkspace(ctx, "w", "github:1", "alice", 1)
	if err := s.UpsertMember(ctx, "w", "github:2", "bob", "contributor", "github:1", 2); err != nil {
		t.Fatal(err)
	}
	// role change via upsert
	s.UpsertMember(ctx, "w", "github:2", "bob", "admin", "github:1", 3)
	if role, _, _ := s.MemberRole(ctx, "w", "github:2"); role != "admin" {
		t.Fatalf("role should be admin after upsert, got %q", role)
	}
	members, _ := s.WorkspaceMembers(ctx, "w")
	if len(members) != 2 || members[0].Role != "owner" { // sorted rank desc
		t.Fatalf("expected 2 members, owner first: %+v", members)
	}
	s.RemoveMember(ctx, "w", "github:2")
	if _, found, _ := s.MemberRole(ctx, "w", "github:2"); found {
		t.Fatal("member should be gone after remove")
	}
}

// ── Guard ────────────────────────────────────────────────────────────────────

func TestMembershipGuard(t *testing.T) {
	s := newMemoryStore()
	ctx := context.Background()
	g := membershipGuard{store: s}

	// Unclaimed workspace → open (content-blind), even with no claims.
	if err := g.CheckWrite(ctx, "open", nil, nil); err != nil {
		t.Fatalf("unclaimed workspace must allow: %v", err)
	}

	s.ClaimWorkspace(ctx, "w", "github:1", "alice", 1) // alice = owner
	s.UpsertMember(ctx, "w", "github:2", "carol", "viewer", "github:1", 2)

	owner := &TokenClaims{Sub: "github:1"}
	viewer := &TokenClaims{Sub: "github:2"}
	stranger := &TokenClaims{Sub: "github:99"}

	// Owner: read + write allowed.
	if err := g.CheckWrite(ctx, "w", owner, nil); err != nil {
		t.Fatalf("owner write: %v", err)
	}
	// Viewer: read allowed, write denied.
	if err := g.CheckRead(ctx, "w", viewer, nil); err != nil {
		t.Fatalf("viewer read should be allowed: %v", err)
	}
	if err := g.CheckWrite(ctx, "w", viewer, nil); err == nil {
		t.Fatal("viewer write must be denied")
	}
	// Non-member: denied.
	if err := g.CheckRead(ctx, "w", stranger, nil); err == nil {
		t.Fatal("non-member read must be denied")
	}
	// Claimed workspace + no identity: denied.
	if err := g.CheckWrite(ctx, "w", nil, nil); err == nil {
		t.Fatal("claimed workspace must require an identified token")
	}
}

// ── HTTP routes + authz ──────────────────────────────────────────────────────

func TestMembershipRoutes(t *testing.T) {
	ts, sk := membershipServer(t)
	base := ts.URL + "/v1/workspaces/wsM/members"
	owner := issueToken(sk, TokenClaims{Sub: "github:1"})
	stranger := issueToken(sk, TokenClaims{Sub: "github:99"})

	// Claim: first succeeds, second conflicts (client reads success=claimed).
	if code, _ := req(t, "POST", base+"/claim", owner, map[string]string{"login": "alice"}); code != http.StatusOK {
		t.Fatalf("first claim want 200, got %d", code)
	}
	if code, _ := req(t, "POST", base+"/claim", stranger, nil); code != http.StatusConflict {
		t.Fatalf("second claim want 409, got %d", code)
	}

	// List returns the owner.
	code, body := req(t, "GET", base, owner, nil)
	if code != http.StatusOK {
		t.Fatalf("list want 200, got %d", code)
	}
	var members []MemberRow
	json.Unmarshal(body, &members)
	if len(members) != 1 || members[0].Account != "github:1" || members[0].Role != "owner" {
		t.Fatalf("unexpected roster: %s", body)
	}

	// A non-member can't add members.
	add := map[string]string{"account": "github:2", "login": "bob", "role": "contributor"}
	if code, _ := req(t, "POST", base, stranger, add); code != http.StatusForbidden {
		t.Fatalf("non-member upsert want 403, got %d", code)
	}
	// The owner can.
	if code, _ := req(t, "POST", base, owner, add); code != http.StatusOK {
		t.Fatalf("owner upsert want 200, got %d", code)
	}
	// Last-owner protection: can't remove the sole owner.
	if code, _ := req(t, "DELETE", base+"/github:1", owner, nil); code != http.StatusConflict {
		t.Fatalf("removing sole owner want 409, got %d", code)
	}
	// But a non-owner member can be removed.
	if code, _ := req(t, "DELETE", base+"/github:2", owner, nil); code != http.StatusOK {
		t.Fatalf("remove member want 200, got %d", code)
	}
}

// Membership disabled → the roster routes don't exist (404), so the default
// content-blind relay is unchanged.
func TestMembershipDisabledRoutes404(t *testing.T) {
	sk := testKey(t)
	srv := New(Options{
		Store:       newMemoryStore(),
		Entitlement: entitlementPolicy{kind: entSigned, pubkey: sk.Public().(ed25519.PublicKey)},
		// Membership omitted → off.
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	tok := issueToken(sk, TokenClaims{Sub: "github:1"})
	if code, _ := req(t, "GET", ts.URL+"/v1/workspaces/w/members", tok, nil); code != http.StatusNotFound {
		t.Fatalf("members route should be 404 when membership disabled, got %d", code)
	}
}

// The identity verifier lets teams run on an OPEN relay: collaboration stays
// open (no token needed), but a signed identity token is read for membership so
// a *claimed* workspace still enforces — without fail-closing tokenless clients.
func TestMembershipOnOpenRelayViaIdentityKey(t *testing.T) {
	sk := testKey(t)
	pub := sk.Public().(ed25519.PublicKey)
	t.Setenv("HIVE_RELAY_MEMBERSHIP_PUBKEY", hexEncode(pub))
	srv := New(Options{
		Store:       newMemoryStore(),
		Entitlement: entitlementPolicy{kind: entOpen}, // OPEN — no entitlement token required
		Membership:  true,
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	wsBase := ts.URL + "/v1/workspaces/wsOpen"
	owner := issueToken(sk, TokenClaims{Sub: "github:1"})

	// Tokenless writes to an UNCLAIMED workspace stay open (collaboration intact).
	if code, _ := req(t, "POST", wsBase+"/envelopes", "", json.RawMessage(`{"x":1}`)); code != http.StatusOK {
		t.Fatalf("open relay unclaimed write should stay 200, got %d", code)
	}
	// An identified owner claims a DIFFERENT workspace.
	claimBase := ts.URL + "/v1/workspaces/wsClaimed"
	if code, _ := req(t, "POST", claimBase+"/members/claim", owner, nil); code != http.StatusOK {
		t.Fatalf("claim via identity token want 200, got %d", code)
	}
	// Now a tokenless write to the CLAIMED workspace is rejected (enforced)…
	if code, _ := req(t, "POST", claimBase+"/envelopes", "", json.RawMessage(`{"x":1}`)); code != http.StatusForbidden {
		t.Fatalf("claimed workspace tokenless write want 403, got %d", code)
	}
	// …while the owner (identified) can write.
	if code, _ := req(t, "POST", claimBase+"/envelopes", owner, json.RawMessage(`{"x":1}`)); code != http.StatusOK {
		t.Fatalf("owner write to claimed workspace want 200, got %d", code)
	}
}

func hexEncode(b []byte) string { return hex.EncodeToString(b) }
