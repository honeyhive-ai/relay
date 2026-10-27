package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// Golden vectors from the hive repo (docs/relay-tunnel/vectors.json, generated
// by docs/relay-tunnel/gen with flynn/noise and cross-checked with Rust snow).

type tunnelVectors struct {
	HostID    string `json:"hostId"`
	PID       string `json:"pid"`
	Challenge struct {
		HostAuthInputHex  string `json:"hostAuthInputHex"`
		HostAuthSig       string `json:"hostAuthSig"`
		Nonce             string `json:"nonce"`
		PhoneAuthInputHex string `json:"phoneAuthInputHex"`
		PhoneAuthSig      string `json:"phoneAuthSig"`
	} `json:"challenge"`
	Credential struct {
		ClaimsJSON string `json:"claimsJson"`
		Token      string `json:"token"`
	} `json:"credential"`
	Keys struct {
		HostSignPub       string `json:"hostSignPub"`
		HostSignSeedHex   string `json:"hostSignSeedHex"`
		HostStaticPrivHex string `json:"hostStaticPrivHex"`
		HostStaticPub     string `json:"hostStaticPub"`
		PhoneAuthPub      string `json:"phoneAuthPub"`
		PhoneAuthSeedHex  string `json:"phoneAuthSeedHex"`
		PhoneStaticPriv   string `json:"phoneStaticPrivHex"`
		PhoneStaticPub    string `json:"phoneStaticPub"`
	} `json:"keys"`
	Negative struct {
		CredentialTamperedClaims string `json:"credentialTamperedClaims"`
	} `json:"negative"`
	Pairing struct {
		Eid           string `json:"eid"`
		PairingSecret string `json:"pairingSecret"`
		PskHex        string `json:"pskHex"`
		Tag           string `json:"tag"`
		TagHash       string `json:"tagHash"`
	} `json:"pairing"`
	Enrollment tunnelTranscript `json:"enrollment"`
	Session    tunnelTranscript `json:"session"`
}

type tunnelTranscript struct {
	PrologueHex string `json:"prologueHex"`
	Msg1Hex     string `json:"msg1Hex"`
	Msg2Hex     string `json:"msg2Hex"`
	Transport   []struct {
		Dir  string `json:"dir"`
		Wire string `json:"wireHex"`
	} `json:"transport"`
}

func loadTunnelVectors(t *testing.T) tunnelVectors {
	t.Helper()
	b, err := os.ReadFile("testdata/tunnel_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v tunnelVectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustB64u(t *testing.T, s string) []byte {
	t.Helper()
	b, err := b64uDecode(s)
	if err != nil {
		t.Fatalf("b64u %q: %v", s, err)
	}
	return b
}

func vectorHostKey(t *testing.T, v tunnelVectors) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(mustHex(t, v.Keys.HostSignSeedHex))
}

// V-keys (the relay's share): host_id, ctx inputs, signatures, tagHash, eid.
func TestTunnelVectors_Keys(t *testing.T) {
	v := loadTunnelVectors(t)
	host := vectorHostKey(t, v)
	pub := host.Public().(ed25519.PublicKey)
	if b64u(pub) != v.Keys.HostSignPub {
		t.Fatalf("host pub mismatch")
	}
	if got := TunnelHostID(pub); got != v.HostID {
		t.Fatalf("host_id = %s, want %s", got, v.HostID)
	}
	nonce := mustB64u(t, v.Challenge.Nonce)
	hostIn := tunnelCtx("host-auth", []byte(v.HostID), nonce)
	if hex.EncodeToString(hostIn) != v.Challenge.HostAuthInputHex {
		t.Fatalf("host-auth ctx mismatch")
	}
	if b64u(ed25519.Sign(host, hostIn)) != v.Challenge.HostAuthSig {
		t.Fatalf("host-auth signature mismatch")
	}
	phone := ed25519.NewKeyFromSeed(mustHex(t, v.Keys.PhoneAuthSeedHex))
	phoneIn := tunnelCtx("phone-auth", []byte(v.HostID), nonce)
	if hex.EncodeToString(phoneIn) != v.Challenge.PhoneAuthInputHex {
		t.Fatalf("phone-auth ctx mismatch")
	}
	if !ed25519.Verify(phone.Public().(ed25519.PublicKey), phoneIn, mustB64u(t, v.Challenge.PhoneAuthSig)) {
		t.Fatalf("phone-auth vector signature does not verify")
	}
	if hex.EncodeToString(tunnelCtx("noise", []byte(v.HostID))) != v.Session.PrologueHex {
		t.Fatalf("noise prologue mismatch")
	}
	ps := mustB64u(t, v.Pairing.PairingSecret)
	hk := func(info string, n int) []byte {
		out, err := hkdf.Key(sha256.New, ps, []byte(tunnelLabel), info, n)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	if b64u(hk("enroll-id", 16)) != v.Pairing.Eid || b64u(hk("relay-tag", 32)) != v.Pairing.Tag {
		t.Fatalf("eid/tag derivation mismatch")
	}
	sum := sha256.Sum256(mustB64u(t, v.Pairing.Tag))
	if b64u(sum[:]) != v.Pairing.TagHash {
		t.Fatalf("tagHash mismatch")
	}
}

func TestTunnelB64uStrict(t *testing.T) {
	for _, bad := range []string{"QQ==", "QQ=", "Q Q", "QQ\n", "Q+", "Q/", "QR"} { // QR: non-zero trailing bits
		if _, err := b64uDecode(bad); err == nil {
			t.Errorf("b64uDecode(%q) accepted", bad)
		}
	}
	if b, err := b64uDecode("QQ"); err != nil || string(b) != "A" {
		t.Fatalf("b64uDecode(QQ) = %q, %v", b, err)
	}
}

// signCred mints an hpc1 token over arbitrary claims bytes.
func signCred(key ed25519.PrivateKey, claims []byte) string {
	signed := credPrefix + "." + b64u(claims)
	return signed + "." + b64u(ed25519.Sign(key, []byte(signed)))
}

// V-cred.
func TestTunnelCredential_Vectors(t *testing.T) {
	v := loadTunnelVectors(t)
	host := vectorHostKey(t, v)
	pub := host.Public().(ed25519.PublicKey)
	known := func(id string) (ed25519.PublicKey, bool, error) {
		if id == v.HostID {
			return pub, true, nil
		}
		return nil, false, nil
	}
	const now = 1793000100 // iat 1793000000, exp 1800776000

	if signCred(host, []byte(v.Credential.ClaimsJSON)) != v.Credential.Token {
		t.Fatalf("credential signing is not byte-identical to the vector")
	}
	cred, te := verifyPhoneCredential(v.Credential.Token, v.HostID, known, now)
	if te != nil {
		t.Fatalf("valid vector rejected: %v", te)
	}
	if cred.PID != v.PID || b64u(cred.PhoneKey) != v.Keys.PhoneAuthPub || cred.IssuedAt != 1793000000 || cred.Expires != 1800776000 {
		t.Fatalf("claims mismatch: %+v", cred)
	}

	parts := strings.Split(v.Credential.Token, ".")
	dupExp := strings.Replace(v.Credential.ClaimsJSON, `"exp":1800776000`, `"exp":1800776000,"exp":1900000000`, 1)
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	claims := func(mut func(m map[string]any)) []byte {
		var m map[string]any
		_ = json.Unmarshal([]byte(v.Credential.ClaimsJSON), &m)
		mut(m)
		b, _ := json.Marshal(m)
		return b
	}
	cases := []struct {
		name  string
		tok   string
		host  string
		now   int64
		want  tunnelCode
		known func(string) (ed25519.PublicKey, bool, error)
	}{
		{"tampered claims", v.Negative.CredentialTamperedClaims, v.HostID, now, tcUnauthorized, known},
		{"expired", v.Credential.Token, v.HostID, 1800776000, tcCredentialExpired, known},
		{"hid != host query", v.Credential.Token, "AAAAAAAAAAAAAAAAAAAAAA", now, tcUnauthorized, known},
		{"unknown host", v.Credential.Token, v.HostID, now, tcHostUnknown, func(string) (ed25519.PublicKey, bool, error) { return nil, false, nil }},
		{"padding on claims", parts[0] + "." + parts[1] + "=." + parts[2], v.HostID, now, tcUnauthorized, known},
		{"padding on sig", parts[0] + "." + parts[1] + "." + parts[2] + "==", v.HostID, now, tcUnauthorized, known},
		{"duplicate exp", signCred(host, []byte(dupExp)), v.HostID, now, tcUnauthorized, known},
		{"other host's key", signCred(other, []byte(v.Credential.ClaimsJSON)), v.HostID, now, tcUnauthorized, known},
		{"wrong prefix", "hpc2." + parts[1] + "." + parts[2], v.HostID, now, tcUnauthorized, known},
		{"two parts", parts[0] + "." + parts[1], v.HostID, now, tcUnauthorized, known},
		{"iat in the future", v.Credential.Token, v.HostID, 1793000000 - 301, tcUnauthorized, known},
		{"lifetime over 400 days", signCred(host, claims(func(m map[string]any) { m["exp"] = 1793000000 + 401*86400 })), v.HostID, now, tcUnauthorized, known},
		{"pk not 32 bytes", signCred(host, claims(func(m map[string]any) { m["pk"] = "AAAA" })), v.HostID, now, tcUnauthorized, known},
		{"missing pid", signCred(host, claims(func(m map[string]any) { delete(m, "pid") })), v.HostID, now, tcUnauthorized, known},
		{"float exp", signCred(host, claims(func(m map[string]any) { m["exp"] = 1800776000.5 })), v.HostID, now, tcUnauthorized, known},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, te := verifyPhoneCredential(c.tok, c.host, c.known, c.now)
			if te == nil {
				t.Fatalf("accepted")
			}
			if te.tc != c.want {
				t.Fatalf("got %v, want %v", te.tc, c.want)
			}
		})
	}
	// Within skew: iat up to 300 s ahead is fine.
	if _, te := verifyPhoneCredential(v.Credential.Token, v.HostID, known, 1793000000-300); te != nil {
		t.Fatalf("iat within skew rejected: %v", te)
	}
}

// ── Policy modes ─────────────────────────────────────────────────────────────

func TestTunnelPolicy_EnvModes(t *testing.T) {
	ctx := context.Background()
	id := TunnelHostID(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)).Public().(ed25519.PublicKey))
	other := TunnelHostID(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32)).Public().(ed25519.PublicKey))

	for _, off := range []string{"", "off", "OFF"} {
		if p, err := newEnvTunnelPolicy(off, "", nil); p != nil || err != nil {
			t.Fatalf("%q: want off, got %v %v", off, p, err)
		}
	}
	if _, err := newEnvTunnelPolicy("public", "", nil); err == nil {
		t.Fatal("unknown mode accepted")
	}
	if _, err := newEnvTunnelPolicy("allowlist", "", nil); err == nil {
		t.Fatal("empty allowlist accepted")
	}
	if _, err := newEnvTunnelPolicy("allowlist", "not-a-host", nil); err == nil {
		t.Fatal("malformed allowlist entry accepted")
	}

	open, _ := newEnvTunnelPolicy("open", "", nil)
	if err := open.Register(ctx, id, nil, ""); err != nil {
		t.Fatal(err)
	}
	if st, err := open.Status(ctx, other); err != nil || !st.Active {
		t.Fatalf("open: %+v %v", st, err)
	}

	al, _ := newEnvTunnelPolicy("allowlist", " "+id+" ,", nil)
	if err := al.Register(ctx, id, nil, ""); err != nil {
		t.Fatal(err)
	}
	if err := al.Register(ctx, other, nil, ""); err != ErrTunnelHostNotAllowed {
		t.Fatalf("allowlist admitted an unlisted host: %v", err)
	}
	if _, err := al.Status(ctx, other); err == nil {
		t.Fatal("allowlist status for unlisted host")
	}

	// With the relay's token gate configured, the registration token must pass it.
	gated, _ := newEnvTunnelPolicy("open", "", entitlementPolicy{kind: entTokens, tokenHashes: []string{sha256hex("op-token")}})
	if err := gated.Register(ctx, id, nil, ""); err != ErrTunnelRegistrationToken {
		t.Fatalf("no reg token: %v", err)
	}
	if err := gated.Register(ctx, id, nil, "op-token"); err != nil {
		t.Fatalf("valid reg token: %v", err)
	}
}

func TestTunnel_OffByDefault(t *testing.T) {
	t.Setenv("HIVE_RELAY_TUNNEL", "")
	srv := New(Options{Store: newMemoryStore()})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	for _, p := range []string{"/v1/tunnel/info", "/v1/tunnel/host", "/v1/tunnel/connect?host=x"} {
		res, err := http.Get(ts.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusNotFound {
			t.Fatalf("%s: %d, want 404", p, res.StatusCode)
		}
	}

	// Token-gated relay: the tunnel bypasses the bearer gate but stays off (404).
	t.Setenv("HIVE_RELAY_ACCESS_TOKENS", "secret")
	srv = New(Options{Store: newMemoryStore()})
	ts2 := httptest.NewServer(srv.Handler())
	defer ts2.Close()
	res, _ := http.Get(ts2.URL + "/v1/tunnel/info")
	res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("gated+off: %d", res.StatusCode)
	}
}

func TestTunnel_EnvOpenInfo(t *testing.T) {
	t.Setenv("HIVE_RELAY_TUNNEL", "open")
	t.Setenv("HIVE_RELAY_ACCESS_TOKENS", "secret") // gate on: tunnel still reachable without a bearer
	srv := New(Options{Store: newMemoryStore()})
	defer srv.ShutdownTunnels()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	res, err := http.Get(ts.URL + "/v1/tunnel/info")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var info map[string]any
	_ = json.NewDecoder(res.Body).Decode(&info)
	if res.StatusCode != 200 || info["push"] != false || info["billing"] != "none" {
		t.Fatalf("info: %d %v", res.StatusCode, info)
	}
	if vs, _ := info["versions"].([]any); len(vs) != 1 || vs[0] != float64(1) {
		t.Fatalf("versions: %v", info["versions"])
	}
}

// ── Store ────────────────────────────────────────────────────────────────────

func TestTunnelStore_MemorySnapshotRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := newMemoryStoreWithPersistence(dir)
	ctx := context.Background()
	rec := TunnelHostRecord{HostID: "h1", Pub: []byte{1, 2, 3}, CreatedAt: 10, LastSeen: 20, Active: true}
	_ = s.UpsertTunnelHost(ctx, rec)
	_ = s.RevokeTunnelPhone(ctx, "h1", "p1", 5000)
	_ = s.RevokeTunnelPhone(ctx, "h1", "p1", 4000) // keeps the later exp
	_ = s.SetTunnelPushToken(ctx, "h1", "p2", &PushToken{Token: "ab", Env: "production"}, 30)
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	r := newMemoryStoreWithPersistence(dir)
	got, _ := r.TunnelHost(ctx, "h1")
	if got == nil || !bytes.Equal(got.Pub, rec.Pub) || got.CreatedAt != 10 {
		t.Fatalf("host not restored: %+v", got)
	}
	if rv, _ := r.TunnelPhoneRevoked(ctx, "h1", "p1", 4500); !rv {
		t.Fatal("revocation not restored (or exp not kept at the max)")
	}
	if tok, _ := r.TunnelPushToken(ctx, "h1", "p2"); tok == nil || tok.Token != "ab" {
		t.Fatal("push token not restored")
	}
	// Revoking drops the push token; prune drops expired revocations and stale pending hosts.
	_ = r.RevokeTunnelPhone(ctx, "h1", "p2", 6000)
	if tok, _ := r.TunnelPushToken(ctx, "h1", "p2"); tok != nil {
		t.Fatal("revoke kept the push token")
	}
	_ = r.UpsertTunnelHost(ctx, TunnelHostRecord{HostID: "pend", Pub: []byte{9}, CreatedAt: 1, LastSeen: 1, Active: false})
	n, _ := r.PruneTunnel(ctx, 5500, 3600_000_000_000) // 1h
	if n != 2 {                                        // p1 revocation (exp 5000) + pending host
		t.Fatalf("pruned %d, want 2", n)
	}
	if h, _ := r.TunnelHost(ctx, "pend"); h != nil {
		t.Fatal("stale pending host survived")
	}
	if h, _ := r.TunnelHost(ctx, "h1"); h == nil {
		t.Fatal("active host pruned")
	}
	_ = r.DeleteTunnelHost(ctx, "h1")
	if rv, _ := r.TunnelPhoneRevoked(ctx, "h1", "p2", 0); rv {
		t.Fatal("deregister kept revocations")
	}
}

func TestTunnelStore_Postgres(t *testing.T) {
	ps := pgStore(t)
	ctx := context.Background()
	if _, err := ps.pool.Exec(ctx, `TRUNCATE relay_tunnel_hosts, relay_tunnel_revocations, relay_tunnel_push_tokens`); err != nil {
		t.Fatal(err)
	}
	_ = ps.UpsertTunnelHost(ctx, TunnelHostRecord{HostID: "h1", Pub: []byte{1}, CreatedAt: 1, LastSeen: 2, Active: true})
	_ = ps.UpsertTunnelHost(ctx, TunnelHostRecord{HostID: "h1", Pub: []byte{9}, CreatedAt: 9, LastSeen: 3, Active: true})
	if h, err := ps.TunnelHost(ctx, "h1"); err != nil || h == nil || h.Pub[0] != 1 || h.LastSeen != 3 {
		t.Fatalf("upsert: %+v %v", h, err)
	}
	_ = ps.SetTunnelPushToken(ctx, "h1", "p1", &PushToken{Token: "ab", Env: "development"}, 5)
	_ = ps.RevokeTunnelPhone(ctx, "h1", "p1", 100)
	if rv, _ := ps.TunnelPhoneRevoked(ctx, "h1", "p1", 50); !rv {
		t.Fatal("not revoked")
	}
	if tok, _ := ps.TunnelPushToken(ctx, "h1", "p1"); tok != nil {
		t.Fatal("revoke kept the push token")
	}
	if n, err := ps.PruneTunnel(ctx, 200, 0); err != nil || n != 1 {
		t.Fatalf("prune: %d %v", n, err)
	}
	_ = ps.DeleteTunnelHost(ctx, "h1")
	if h, _ := ps.TunnelHost(ctx, "h1"); h != nil {
		t.Fatal("not deleted")
	}
}
