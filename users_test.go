package relay

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUserTokenLifecycleMemory(t *testing.T) {
	ctx := context.Background()
	s := newMemoryStore()

	u, err := s.CreateUser(ctx, "Alice", "alice", 100)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	tok, err := s.IssueToken(ctx, u.ID, "laptop", HashToken(raw), 101)
	if err != nil {
		t.Fatal(err)
	}

	// The raw token resolves to the owning user's claims.
	claims, ok, err := s.ResolveToken(ctx, HashToken(raw), 102)
	if err != nil || !ok {
		t.Fatalf("expected token to resolve, got ok=%v err=%v", ok, err)
	}
	if claims.Sub != "alice" || claims.Plan != "team" {
		t.Fatalf("unexpected claims: %+v", claims)
	}

	// A wrong token does not resolve.
	if _, ok, _ := s.ResolveToken(ctx, HashToken("nope"), 103); ok {
		t.Fatal("bogus token should not resolve")
	}

	// Revoking kills it immediately.
	if err := s.RevokeToken(ctx, tok.ID, 104); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.ResolveToken(ctx, HashToken(raw), 105); ok {
		t.Fatal("revoked token should not resolve")
	}

	// Disabling the user kills their (new) tokens too.
	raw2, _ := GenerateToken()
	if _, err := s.IssueToken(ctx, u.ID, "phone", HashToken(raw2), 106); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUserDisabled(ctx, u.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.ResolveToken(ctx, HashToken(raw2), 107); ok {
		t.Fatal("token of disabled user should not resolve")
	}

	// Unknown user / token errors.
	if _, err := s.IssueToken(ctx, "ghost", "x", "h", 108); err != ErrUserNotFound {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
	if err := s.RevokeToken(ctx, "ghost", 109); err != ErrTokenNotFound {
		t.Fatalf("expected ErrTokenNotFound, got %v", err)
	}
}

func TestStoreEntitlementVerifier(t *testing.T) {
	ctx := context.Background()
	s := newMemoryStore()
	u, _ := s.CreateUser(ctx, "Bob", "bob", 1)
	raw, _ := GenerateToken()
	_, _ = s.IssueToken(ctx, u.ID, "", HashToken(raw), 1)

	v := StoreEntitlementVerifier{Store: s}
	if _, ok := v.Allow(raw, 2); !ok {
		t.Fatal("live token should be admitted")
	}
	if _, ok := v.Allow("", 2); ok {
		t.Fatal("empty token must be rejected")
	}
	if _, ok := v.Allow("garbage", 2); ok {
		t.Fatal("unknown token must be rejected")
	}
}

// allowAdmin is a test AdminAuthorizer that admits everyone.
type allowAdmin struct{}

func (allowAdmin) AuthorizeAdmin(*http.Request) (string, bool) { return "admin", true }

func TestAdminAPICreateAndResolve(t *testing.T) {
	s := New(Options{Store: newMemoryStore(), AdminAuth: allowAdmin{}})
	h := s.Handler()

	// Create a user via the admin API → get a raw token once.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/admin/users", strings.NewReader(`{"name":"Carol","login":"carol"}`))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("create user: got %d, body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"raw"`) {
		t.Fatalf("expected a raw token in response, got %s", rec.Body.String())
	}

	// That token must now pass the entitlement gate on a normal request.
	var body struct {
		Raw string `json:"raw"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Raw == "" {
		t.Fatalf("could not read raw token: %v", err)
	}
	// Point the verifier at the same store the server uses.
	got := httptest.NewRecorder()
	greq := httptest.NewRequest("GET", "/v1/workspaces/ws1/envelopes?after=0", nil)
	greq.Header.Set("Authorization", "Bearer "+body.Raw)
	// Rebuild server with a store-backed verifier over the same store.
	// (New() defaults entitlement to env; wire the store verifier explicitly.)
	// For this we reuse s.store via a fresh server.
	s2 := New(Options{Store: s.store, AdminAuth: allowAdmin{}, Entitlement: StoreEntitlementVerifier{Store: s.store}})
	s2.Handler().ServeHTTP(got, greq)
	if got.Code == http.StatusUnauthorized {
		t.Fatalf("freshly issued token should pass the gate, got 401")
	}
}

func TestAdminAPIDisabledWithoutAuthorizer(t *testing.T) {
	s := New(Options{Store: newMemoryStore()}) // no AdminAuth
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/v1/admin/users", nil)
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("admin API should be 404 without an authorizer, got %d", rec.Code)
	}
}
