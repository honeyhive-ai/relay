package relay

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

// End-to-end invite lifecycle over HTTP: an owner issues an invite, a stranger
// redeems it via /join and is enrolled at the invite's role, and a revoked or
// used-up invite is refused.
func TestInviteLifecycle(t *testing.T) {
	ts, sk := membershipServer(t)
	wsBase := ts.URL + "/v1/workspaces/wsInv"
	owner := issueToken(sk, TokenClaims{Sub: "github:1"})
	joiner := issueToken(sk, TokenClaims{Sub: "github:2"})
	other := issueToken(sk, TokenClaims{Sub: "github:3"})

	// Owner claims the workspace.
	if code, _ := req(t, "POST", wsBase+"/members/claim", owner, map[string]string{"login": "alice"}); code != http.StatusOK {
		t.Fatalf("claim want 200, got %d", code)
	}

	// A non-admin can't issue invites.
	if code, _ := req(t, "POST", wsBase+"/invites", joiner, map[string]any{"role": "contributor"}); code != http.StatusForbidden {
		t.Fatalf("non-admin invite want 403, got %d", code)
	}
	// Owner can't mint an owner invite (too dangerous).
	if code, _ := req(t, "POST", wsBase+"/invites", owner, map[string]any{"role": "owner"}); code != http.StatusBadRequest {
		t.Fatalf("owner-role invite want 400, got %d", code)
	}

	// Owner issues a single-use contributor invite; the code is returned once.
	code, body := req(t, "POST", wsBase+"/invites", owner, map[string]any{"role": "contributor", "maxUses": 1})
	if code != http.StatusOK {
		t.Fatalf("issue invite want 200, got %d: %s", code, body)
	}
	var issued struct {
		ID   string `json:"id"`
		Code string `json:"code"`
	}
	json.Unmarshal(body, &issued)
	if issued.Code == "" || issued.ID == "" {
		t.Fatalf("invite must return id + code: %s", body)
	}

	// The joiner redeems it and is enrolled as a contributor.
	if code, b := req(t, "POST", wsBase+"/join", joiner, map[string]string{"code": issued.Code, "login": "bob"}); code != http.StatusOK {
		t.Fatalf("join want 200, got %d: %s", code, b)
	}
	// Confirm enrollment via the roster.
	_, rosterBody := req(t, "GET", wsBase+"/members", owner, nil)
	var members []MemberRow
	json.Unmarshal(rosterBody, &members)
	found := false
	for _, m := range members {
		if m.Account == "github:2" && m.Role == "contributor" {
			found = true
		}
	}
	if !found {
		t.Fatalf("joiner should be a contributor: %s", rosterBody)
	}

	// The single-use invite is now exhausted → a second redeem is refused.
	if code, _ := req(t, "POST", wsBase+"/join", other, map[string]string{"code": issued.Code}); code != http.StatusForbidden {
		t.Fatalf("exhausted invite want 403, got %d", code)
	}
}

// A revoked invite can't be redeemed.
func TestInviteRevoke(t *testing.T) {
	ts, sk := membershipServer(t)
	wsBase := ts.URL + "/v1/workspaces/wsRev"
	owner := issueToken(sk, TokenClaims{Sub: "github:1"})
	joiner := issueToken(sk, TokenClaims{Sub: "github:2"})
	req(t, "POST", wsBase+"/members/claim", owner, nil)

	_, body := req(t, "POST", wsBase+"/invites", owner, map[string]any{"role": "viewer"})
	var issued struct{ ID, Code string }
	json.Unmarshal(body, &issued)

	// Revoke it, then a redeem must fail.
	if code, _ := req(t, "DELETE", wsBase+"/invites/"+issued.ID, owner, nil); code != http.StatusOK {
		t.Fatalf("revoke want 200, got %d", code)
	}
	if code, _ := req(t, "POST", wsBase+"/join", joiner, map[string]string{"code": issued.Code}); code != http.StatusForbidden {
		t.Fatalf("revoked invite want 403, got %d", code)
	}
}

// Store-level: RedeemInvite honors expiry + use caps.
func TestRedeemInviteRules(t *testing.T) {
	s := newMemoryStore()
	ctx := context.Background()
	s.CreateInvite(ctx, "w", "id1", HashToken("codeA"), "viewer", "github:1", 0, 2, 1)
	// Two redemptions succeed, the third fails (maxUses=2).
	for i := 0; i < 2; i++ {
		if role, ok, _ := s.RedeemInvite(ctx, "w", HashToken("codeA"), 10); !ok || role != "viewer" {
			t.Fatalf("redeem %d should succeed as viewer", i)
		}
	}
	if _, ok, _ := s.RedeemInvite(ctx, "w", HashToken("codeA"), 10); ok {
		t.Fatal("third redeem must fail (use cap)")
	}
	// Expired invite is refused.
	s.CreateInvite(ctx, "w", "id2", HashToken("codeB"), "viewer", "github:1", 100 /*expiresAt*/, 0, 1)
	if _, ok, _ := s.RedeemInvite(ctx, "w", HashToken("codeB"), 200 /*now>exp*/); ok {
		t.Fatal("expired invite must be refused")
	}
}
