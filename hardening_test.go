package relay

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// ── P2-15: route-template redaction ───────────────────────────────────────────

func TestRouteTemplateRedactsSecrets(t *testing.T) {
	cases := map[string]string{
		"/":                                     "/",
		"/metrics":                              "/metrics",
		"/v1/health":                            "/v1/health",
		"/v1/pair/AB12CD":                       "/v1/pair/{}", // pairing code redacted
		"/v1/pair":                              "/v1/pair",
		"/v1/workspaces/ws-secret-id/envelopes": "/v1/workspaces/{}/envelopes",
		"/v1/workspaces/ws-secret-id/events":    "/v1/workspaces/{}/events",
		"/v1/directory/octocat":                 "/v1/directory/{}", // handle redacted
		"/v1/friends/github%3A42/devices":       "/v1/friends/{}/devices",
		"/v1/friends/requests/fr-deadbeef/accept": "/v1/friends/requests/{}/accept",
		"/v1/admin/users/usr_123/tokens":          "/v1/admin/users/{}/tokens",
		"/v1/totally/unknown/probe/with?secret=x": "other",
	}
	for path, want := range cases {
		// strip any query the map keys carry
		p := path
		if i := indexByte(p, '?'); i >= 0 {
			p = p[:i]
		}
		if got := routeTemplate(p); got != want {
			t.Errorf("routeTemplate(%q) = %q, want %q", p, got, want)
		}
	}
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// ── P1-8: malformed-token screen + identity cache ─────────────────────────────

func TestPlausibleGitHubToken(t *testing.T) {
	bad := []string{"", "short", "has space inside", "ctrl\x01char", "line\nbreak"}
	for _, tok := range bad {
		if plausibleGitHubToken(tok) {
			t.Errorf("token %q should be implausible", tok)
		}
	}
	if !plausibleGitHubToken("ghp_0123456789abcdefABCDEF") {
		t.Error("a well-formed token should be plausible")
	}
}

func TestVerifyCachedCollapsesAndScreens(t *testing.T) {
	srv := New(Options{Store: newMemoryStore(), Entitlement: entitlementPolicy{kind: entOpen}})
	var calls atomic.Int64
	srv.verify = func(_ context.Context, token string) (*githubUser, error) {
		calls.Add(1)
		if token == "gho_validtoken123" {
			return &githubUser{ID: 1, Login: "alice"}, nil
		}
		return nil, nil // verified-invalid
	}

	// Malformed tokens never reach the outbound verify.
	if u, _ := srv.verifyCached(context.Background(), "bad"); u != nil {
		t.Fatal("malformed token must not verify")
	}
	if calls.Load() != 0 {
		t.Fatalf("malformed token triggered %d outbound calls, want 0", calls.Load())
	}

	// A valid token verifies once, then is served from cache.
	for i := 0; i < 3; i++ {
		if u, _ := srv.verifyCached(context.Background(), "gho_validtoken123"); u == nil || u.Login != "alice" {
			t.Fatalf("expected cached alice, got %+v", u)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("valid token verified %d times, want 1 (cached)", calls.Load())
	}

	// A verified-invalid token is negatively cached (one call, then cached).
	for i := 0; i < 3; i++ {
		if u, _ := srv.verifyCached(context.Background(), "gho_bogustoken999"); u != nil {
			t.Fatal("invalid token must not verify")
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("invalid token verified %d times, want 2 total (negatively cached)", calls.Load())
	}
}

// ── P1-6: per-(workspace,writer) append quota ─────────────────────────────────

func TestWorkspaceWriterQuota(t *testing.T) {
	t.Setenv("HIVE_RELAY_WS_WRITER_RATE", "0.0001")
	t.Setenv("HIVE_RELAY_WS_WRITER_BURST", "2")
	ts := testServer(entitlementPolicy{kind: entOpen}, nil)
	defer ts.Close()

	post := func(n int) int {
		resp, _ := do(t, "POST", ts.URL+"/v1/workspaces/wsq/envelopes", "", json.RawMessage(`{"n":`+itoa(n)+`}`))
		return resp.StatusCode
	}
	if post(1) != 200 || post(2) != 200 {
		t.Fatal("first two writes should pass the burst")
	}
	if code := post(3); code != http.StatusTooManyRequests {
		t.Fatalf("third write should exceed the writer quota (429), got %d", code)
	}
}

// ── P2-12: live-pairing cap + write limiter on pairing ────────────────────────

func TestLivePairingCap(t *testing.T) {
	t.Setenv("HIVE_RELAY_MAX_PAIRINGS", "2")
	ts := testServer(entitlementPolicy{kind: entOpen}, nil)
	defer ts.Close()

	mk := func() int {
		resp, _ := do(t, "POST", ts.URL+"/v1/pair", "", map[string]any{"payload": "x"})
		return resp.StatusCode
	}
	if mk() != 200 || mk() != 200 {
		t.Fatal("first two pairings should be created")
	}
	if code := mk(); code != http.StatusServiceUnavailable {
		t.Fatalf("third pairing should hit the cap (503), got %d", code)
	}
}

// ── P1-7: per-(sender,recipient) invite rate limit ────────────────────────────

func TestInviteRateLimit(t *testing.T) {
	t.Setenv("HIVE_RELAY_INVITE_RATE", "0.0001")
	t.Setenv("HIVE_RELAY_INVITE_BURST", "1")
	ts := testServer(entitlementPolicy{kind: entOpen}, nil)
	defer ts.Close()

	for _, u := range []struct{ login, id string }{{"alice", "1"}, {"bob", "2"}} {
		if resp, _ := do(t, "POST", ts.URL+"/v1/account/register", "tok:"+u.login+":"+u.id,
			map[string]any{"deviceId": "d-" + u.login}); resp.StatusCode != 200 {
			t.Fatalf("register %s failed", u.login)
		}
	}
	invite := func() int {
		resp, _ := do(t, "POST", ts.URL+"/v1/account/invites", "tok:alice:1",
			map[string]any{"toLogin": "@bob", "invite": json.RawMessage(`"sealed"`)})
		return resp.StatusCode
	}
	if invite() != 200 {
		t.Fatal("first invite should be delivered")
	}
	if code := invite(); code != http.StatusTooManyRequests {
		t.Fatalf("second invite should be rate limited (429), got %d", code)
	}
}

// ── P1-7 / P2-12: memory-store structural caps ────────────────────────────────

func TestInboxRowCapEvictsOldest(t *testing.T) {
	s := newMemoryStore()
	s.inboxMaxRows = 3
	for i := 0; i < 6; i++ {
		if _, err := s.PushAccountEvent(bg, "acct", raw(`{"n":`+itoa(i)+`}`)); err != nil {
			t.Fatal(err)
		}
	}
	rows, _ := s.AccountInboxAfter(bg, "acct", 0)
	if len(rows) != 3 {
		t.Fatalf("inbox should be capped at 3, got %d", len(rows))
	}
	if rows[0].Seq != 4 || rows[2].Seq != 6 {
		t.Fatalf("cap should retain the newest rows, got seqs %d..%d", rows[0].Seq, rows[2].Seq)
	}
}

func TestKeyringCapRetainsNewest(t *testing.T) {
	s := newMemoryStore()
	s.maxKeyringPerWS = 2
	for i := 0; i < 5; i++ {
		_ = s.AppendKeyRotation(bg, "ws", raw(`{"v":`+itoa(i)+`}`))
	}
	kr, _ := s.KeyRotations(bg, "ws")
	if len(kr) != 2 || string(kr[0]) != `{"v":3}` || string(kr[1]) != `{"v":4}` {
		t.Fatalf("keyring cap should keep the 2 newest, got %v", kr)
	}
}

func TestDeviceBlobCapBounded(t *testing.T) {
	s := newMemoryStore()
	s.maxDeviceBlobsPerWS = 2
	for i := 0; i < 5; i++ {
		_ = s.PutCandidate(bg, "ws", "dev"+itoa(i), raw(`{}`))
	}
	m, _ := s.Candidates(bg, "ws")
	if len(m) != 2 {
		t.Fatalf("candidate blobs should be bounded at 2, got %d", len(m))
	}
	// Re-publishing an existing device never grows past the cap.
	for k := range m {
		_ = s.PutCandidate(bg, "ws", k, raw(`{"x":1}`))
		break
	}
	if m2, _ := s.Candidates(bg, "ws"); len(m2) != 2 {
		t.Fatalf("re-publish should not grow past the cap, got %d", len(m2))
	}
}

// ── P1-5 seam: ReadGuard ──────────────────────────────────────────────────────

type denyReadGuard struct{ blocked string }

func (g denyReadGuard) CheckRead(_ context.Context, workspace string, _ *TokenClaims, _ *http.Request) error {
	if workspace == g.blocked {
		return ErrNotYours
	}
	return nil
}

func TestReadGuardSeam(t *testing.T) {
	srv := New(Options{Store: newMemoryStore(), Entitlement: entitlementPolicy{kind: entOpen}, ReadGuard: denyReadGuard{blocked: "secret"}})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Blocked workspace read → 403.
	if resp, _ := do(t, "GET", ts.URL+"/v1/workspaces/secret/envelopes?after=0", "", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("guarded read should be 403, got %d", resp.StatusCode)
	}
	// Other workspace read → open.
	if resp, _ := do(t, "GET", ts.URL+"/v1/workspaces/open/envelopes?after=0", "", nil); resp.StatusCode != 200 {
		t.Fatalf("unguarded read should be 200, got %d", resp.StatusCode)
	}
	// Writes are unaffected by the ReadGuard.
	if resp, _ := do(t, "POST", ts.URL+"/v1/workspaces/secret/envelopes", "", json.RawMessage(`{"ct":"x"}`)); resp.StatusCode != 200 {
		t.Fatalf("write should not be read-guarded, got %d", resp.StatusCode)
	}
}

// Default (nil ReadGuard) keeps the open relay's reads open — pinned so the seam
// can never silently start gating the open build.
func TestReadGuardNilKeepsReadsOpen(t *testing.T) {
	ts := testServer(entitlementPolicy{kind: entOpen}, nil)
	defer ts.Close()
	if resp, _ := do(t, "GET", ts.URL+"/v1/workspaces/any/envelopes?after=0", "", nil); resp.StatusCode != 200 {
		t.Fatalf("open relay read should stay open, got %d", resp.StatusCode)
	}
}

// ── P3-15: /metrics ops credential + health ping cache ────────────────────────

func TestMetricsOpsCredential(t *testing.T) {
	t.Setenv("HIVE_RELAY_METRICS_TOKEN", "ops-secret")
	ts := testServer(entitlementPolicy{kind: entOpen}, nil)
	defer ts.Close()

	// No credential → 401.
	if resp, _ := do(t, "GET", ts.URL+"/metrics", "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /metrics should be 401, got %d", resp.StatusCode)
	}
	// Correct bearer → 200.
	req, _ := http.NewRequest("GET", ts.URL+"/metrics", nil)
	req.Header.Set("Authorization", "Bearer ops-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("authenticated /metrics should be 200, got %d", resp.StatusCode)
	}
}

type countingPingStore struct {
	*memoryStore
	pings atomic.Int64
}

func (c *countingPingStore) Ping(context.Context) error { c.pings.Add(1); return nil }

func TestHealthPingCached(t *testing.T) {
	store := &countingPingStore{memoryStore: newMemoryStore()}
	srv := New(Options{Store: store, Entitlement: entitlementPolicy{kind: entOpen}})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	for i := 0; i < 4; i++ {
		if resp, _ := do(t, "GET", ts.URL+"/v1/health", "", nil); resp.StatusCode != 200 {
			t.Fatalf("health should be 200, got %d", resp.StatusCode)
		}
	}
	if n := store.pings.Load(); n != 1 {
		t.Fatalf("rapid health probes should share one cached DB ping, got %d", n)
	}
}

// ── P2-16: fail-fast when prod requires a DB but none is configured ────────────

func TestBuildStoreRequireDB(t *testing.T) {
	t.Setenv("HIVE_RELAY_REQUIRE_DB", "1")
	t.Setenv("DATABASE_URL", "")
	t.Setenv("HIVE_RELAY_DATA_DIR", "")
	if _, err := buildStore(context.Background()); err == nil {
		t.Fatal("buildStore should refuse to boot without DATABASE_URL when HIVE_RELAY_REQUIRE_DB is set")
	}
}

// itoa is a tiny int→string without importing strconv into the test churn.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
