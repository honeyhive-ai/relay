package relay

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// testServer wires a server whose GitHub verification is stubbed: the token
// "tok:<login>:<id>" resolves to that user; anything else is unauthorized.
func testServer(policy entitlementPolicy, friendCap *int) *httptest.Server {
	srv := New(Options{Store: newMemoryStore(), Entitlement: policy, FriendCap: friendCap})
	srv.verify = func(_ context.Context, token string) (*githubUser, error) {
		parts := strings.Split(token, ":")
		if len(parts) != 3 || parts[0] != "tok" {
			return nil, nil
		}
		var id uint64
		for _, c := range parts[2] {
			id = id*10 + uint64(c-'0')
		}
		login := parts[1]
		return &githubUser{ID: id, Login: login}, nil
	}
	return httptest.NewServer(srv.Handler())
}

func do(t *testing.T, method, url string, ghToken string, body any) (*http.Response, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = strings.NewReader(string(b))
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		t.Fatal(err)
	}
	if ghToken != "" {
		req.Header.Set("x-hive-github-token", ghToken)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, out
}

func TestHealthIsUngated(t *testing.T) {
	ts := testServer(entitlementPolicy{kind: entOpen}, nil)
	defer ts.Close()
	resp, body := do(t, "GET", ts.URL+"/v1/health", "", nil)
	if resp.StatusCode != 200 || string(body) != "ok" {
		t.Fatalf("health: %d %q", resp.StatusCode, body)
	}
}

func TestEntitlementGateRejectsWithoutToken(t *testing.T) {
	sk := testKey(t)
	policy := entitlementPolicy{kind: entSigned, pubkey: sk.Public().(ed25519.PublicKey)}
	ts := testServer(policy, nil)
	defer ts.Close()

	// No bearer → 401 on a gated route.
	resp, _ := do(t, "GET", ts.URL+"/v1/workspaces/ws1/envelopes", "", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}
	// Health stays open.
	if resp, _ := do(t, "GET", ts.URL+"/v1/health", "", nil); resp.StatusCode != 200 {
		t.Fatalf("health should stay open, got %d", resp.StatusCode)
	}
}

func TestEnvelopePostAndList(t *testing.T) {
	ts := testServer(entitlementPolicy{kind: entOpen}, nil)
	defer ts.Close()

	resp, body := do(t, "POST", ts.URL+"/v1/workspaces/ws1/envelopes", "", json.RawMessage(`{"ct":"opaque"}`))
	if resp.StatusCode != 200 {
		t.Fatalf("post: %d %s", resp.StatusCode, body)
	}
	var posted struct {
		Seq uint64 `json:"seq"`
	}
	_ = json.Unmarshal(body, &posted)
	if posted.Seq != 1 {
		t.Fatalf("seq want 1 got %d", posted.Seq)
	}

	_, body = do(t, "GET", ts.URL+"/v1/workspaces/ws1/envelopes?after=0", "", nil)
	var rows []Envelope
	_ = json.Unmarshal(body, &rows)
	if len(rows) != 1 || rows[0].Seq != 1 || string(rows[0].Body) != `{"ct":"opaque"}` {
		t.Fatalf("list: %s", body)
	}

	// after=1 → empty (cursor semantics).
	_, body = do(t, "GET", ts.URL+"/v1/workspaces/ws1/envelopes?after=1", "", nil)
	_ = json.Unmarshal(body, &rows)
	if len(rows) != 0 {
		t.Fatalf("after=1 should be empty: %s", body)
	}
}

func TestPairingCreateAndResolve(t *testing.T) {
	ts := testServer(entitlementPolicy{kind: entOpen}, nil)
	defer ts.Close()

	resp, body := do(t, "POST", ts.URL+"/v1/pair", "", map[string]any{"payload": "invite-blob"})
	if resp.StatusCode != 200 {
		t.Fatalf("pair: %d %s", resp.StatusCode, body)
	}
	var pr struct {
		Code      string `json:"code"`
		ExpiresIn uint64 `json:"expires_in"`
	}
	_ = json.Unmarshal(body, &pr)
	if len(pr.Code) != codeLen || pr.ExpiresIn != defaultPairTTL {
		t.Fatalf("pair resp: %+v", pr)
	}

	_, body = do(t, "GET", ts.URL+"/v1/pair/"+pr.Code, "", nil)
	var resolved struct {
		Payload string `json:"payload"`
	}
	_ = json.Unmarshal(body, &resolved)
	if resolved.Payload != "invite-blob" {
		t.Fatalf("resolve: %s", body)
	}

	// Unknown code → 404.
	if resp, _ := do(t, "GET", ts.URL+"/v1/pair/ZZZZZZ", "", nil); resp.StatusCode != 404 {
		t.Fatalf("unknown code want 404, got %d", resp.StatusCode)
	}
}

// End-to-end social flow over HTTP: two accounts register, one friends the
// other by handle, the request lands in the target's inbox.
func TestFriendRequestFlowOverHTTP(t *testing.T) {
	ts := testServer(entitlementPolicy{kind: entOpen}, nil)
	defer ts.Close()

	// Both sign in (register a device).
	for _, u := range []struct{ login, id string }{{"alice", "1"}, {"bob", "2"}} {
		resp, body := do(t, "POST", ts.URL+"/v1/account/register", "tok:"+u.login+":"+u.id,
			map[string]any{"deviceId": "d-" + u.login})
		if resp.StatusCode != 200 {
			t.Fatalf("register %s: %d %s", u.login, resp.StatusCode, body)
		}
	}

	// alice → bob by handle.
	resp, body := do(t, "POST", ts.URL+"/v1/friends/requests", "tok:alice:1", map[string]any{"toLogin": "@bob"})
	if resp.StatusCode != 200 {
		t.Fatalf("friend request: %d %s", resp.StatusCode, body)
	}

	// bob's inbox shows a friendRequest event.
	_, body = do(t, "GET", ts.URL+"/v1/account/inbox?after=0", "tok:bob:2", nil)
	var inbox []InboxRow
	_ = json.Unmarshal(body, &inbox)
	if len(inbox) != 1 {
		t.Fatalf("bob inbox: %s", body)
	}
	var ev map[string]any
	_ = json.Unmarshal(inbox[0].Body, &ev)
	if ev["kind"] != "friendRequest" || ev["fromLogin"] != "alice" {
		t.Fatalf("inbox event: %+v", ev)
	}

	// Requesting an unknown handle → 404.
	if resp, _ := do(t, "POST", ts.URL+"/v1/friends/requests", "tok:alice:1", map[string]any{"toLogin": "ghost"}); resp.StatusCode != 404 {
		t.Fatalf("unknown handle want 404, got %d", resp.StatusCode)
	}

	// Gated identity route without a token → 401.
	if resp, _ := do(t, "GET", ts.URL+"/v1/account/devices", "", nil); resp.StatusCode != 401 {
		t.Fatalf("no github token want 401, got %d", resp.StatusCode)
	}
}

func TestSignedHandleParsesHexKey(t *testing.T) {
	// Sanity: a hex pubkey from a generated key drives the signed policy.
	_, priv, _ := ed25519.GenerateKey(nil)
	pubHex := hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	pub, ok := parsePubkey(pubHex)
	if !ok {
		t.Fatal("pub hex should parse")
	}
	tok := issueToken(priv, TokenClaims{Sub: "s"})
	policy := entitlementPolicy{kind: entSigned, pubkey: pub}
	ts := testServer(policy, nil)
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/v1/workspaces/ws/envelopes", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("signed token should pass gate, got %d", resp.StatusCode)
	}
}
