package relay

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// These verify the extension seams: a downstream build injecting
// WriteGuard / Hooks / EntitlementVerifier via New(Options{...}) changes behavior
// without touching this package.

type denyWorkspaceGuard struct{ blocked string }

func (g denyWorkspaceGuard) CheckWrite(_ context.Context, workspace string, _ *TokenClaims, _ *http.Request) error {
	if workspace == g.blocked {
		return ErrNotYours // any non-nil error → 403
	}
	return nil
}

type recordingHooks struct {
	mu     sync.Mutex
	writes []string
}

func (h *recordingHooks) WorkspaceWritten(_ context.Context, workspace string, _ uint64, _ *TokenClaims) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.writes = append(h.writes, workspace)
}

func seamServer(t *testing.T, o Options) *httptest.Server {
	t.Helper()
	if o.Store == nil {
		o.Store = newMemoryStore()
	}
	srv := New(o)
	return httptest.NewServer(srv.Handler())
}

func TestWriteGuardSeamRejectsWrites(t *testing.T) {
	ts := seamServer(t, Options{WriteGuard: denyWorkspaceGuard{blocked: "secret"}})
	defer ts.Close()

	// Allowed workspace writes through.
	if resp, _ := do(t, "POST", ts.URL+"/v1/workspaces/open/envelopes", "", rawBody(`{"ct":"x"}`)); resp.StatusCode != 200 {
		t.Fatalf("open ws should be allowed, got %d", resp.StatusCode)
	}
	// Guarded workspace is rejected with 403 before the store is touched.
	if resp, _ := do(t, "POST", ts.URL+"/v1/workspaces/secret/envelopes", "", rawBody(`{"ct":"x"}`)); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("guarded ws should be 403, got %d", resp.StatusCode)
	}
	// Reads stay open (guard is pre-write only).
	if resp, _ := do(t, "GET", ts.URL+"/v1/workspaces/secret/envelopes?after=0", "", nil); resp.StatusCode != 200 {
		t.Fatalf("reads should not be guarded, got %d", resp.StatusCode)
	}
}

func TestHooksSeamObservesWrites(t *testing.T) {
	hooks := &recordingHooks{}
	ts := seamServer(t, Options{Hooks: hooks})
	defer ts.Close()

	do(t, "POST", ts.URL+"/v1/workspaces/wsA/envelopes", "", rawBody(`{"ct":"1"}`))
	do(t, "POST", ts.URL+"/v1/workspaces/wsA/keyring", "", rawBody(`{"v":1}`))
	// Candidate/presence writes are not metered (ephemeral) — only durable writes.
	do(t, "POST", ts.URL+"/v1/workspaces/wsA/candidates", "", map[string]any{"device_id": "d", "data": map[string]int{}})

	hooks.mu.Lock()
	defer hooks.mu.Unlock()
	if len(hooks.writes) != 2 || hooks.writes[0] != "wsA" || hooks.writes[1] != "wsA" {
		t.Fatalf("expected 2 durable-write hooks for wsA, got %v", hooks.writes)
	}
}

// customVerifier admits only a fixed bearer, proving EntitlementVerifier is
// injectable (e.g. a custom revocation or per-tenant policy).
type customVerifier struct{ ok string }

func (v customVerifier) Allow(token string, _ int64) (*TokenClaims, bool) {
	return nil, token == v.ok
}

func TestEntitlementVerifierSeam(t *testing.T) {
	ts := seamServer(t, Options{Entitlement: customVerifier{ok: "let-me-in"}})
	defer ts.Close()

	get := func(bearer string) int {
		req, _ := http.NewRequest("GET", ts.URL+"/v1/workspaces/ws/envelopes", nil)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if get("") != http.StatusUnauthorized {
		t.Fatal("no token should be 401")
	}
	if get("nope") != http.StatusUnauthorized {
		t.Fatal("wrong token should be 401")
	}
	if get("let-me-in") != http.StatusOK {
		t.Fatal("accepted token should pass")
	}
}

// rawBody sends a JSON body verbatim (json.RawMessage marshals to itself).
func rawBody(s string) any { return json.RawMessage(s) }
