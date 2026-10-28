package relay

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// testP8 writes a fresh P-256 key as an Apple-style PKCS#8 .p8 file.
func testP8(t *testing.T) (path string, pemText string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	pemText = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	path = filepath.Join(t.TempDir(), "AuthKey_TEST.p8")
	if err := os.WriteFile(path, []byte(pemText), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, pemText
}

func envMap(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestAPNsSenderFromEnv(t *testing.T) {
	path, pemText := testP8(t)
	full := func() map[string]string {
		return map[string]string{
			"HIVE_RELAY_APNS_KEY_FILE": path, "HIVE_RELAY_APNS_KEY_ID": "KEYID12345",
			"HIVE_RELAY_APNS_TEAM_ID": "TEAMID1234", "HIVE_RELAY_APNS_TOPIC": "com.example.hive",
		}
	}

	if s, err := apnsPushSenderFrom(envMap(nil)); s != nil || err != nil {
		t.Fatalf("unset must mean off: %v %v", s, err)
	}
	s, err := apnsPushSenderFrom(envMap(full()))
	if err != nil || s == nil || s.Env != APNsEnvAuto || s.Client.Topic != "com.example.hive" || s.Client.Key == nil {
		t.Fatalf("file config: %+v %v", s, err)
	}

	inline := full()
	delete(inline, "HIVE_RELAY_APNS_KEY_FILE")
	inline["HIVE_RELAY_APNS_KEY"] = strings.ReplaceAll(pemText, "\n", `\n`) // one-line env form
	inline["HIVE_RELAY_APNS_ENV"] = "Production"
	if s, err := apnsPushSenderFrom(envMap(inline)); err != nil || s.Env != APNsEnvProduction {
		t.Fatalf("inline config: %+v %v", s, err)
	}

	partial := full()
	delete(partial, "HIVE_RELAY_APNS_TEAM_ID")
	delete(partial, "HIVE_RELAY_APNS_TOPIC")
	if _, err := apnsPushSenderFrom(envMap(partial)); err == nil ||
		!strings.Contains(err.Error(), "HIVE_RELAY_APNS_TEAM_ID") || !strings.Contains(err.Error(), "HIVE_RELAY_APNS_TOPIC") {
		t.Fatalf("partial config: %v", err)
	}

	badEnv := full()
	badEnv["HIVE_RELAY_APNS_ENV"] = "staging"
	if _, err := apnsPushSenderFrom(envMap(badEnv)); err == nil {
		t.Fatal("unknown env accepted")
	}

	badKey := full()
	delete(badKey, "HIVE_RELAY_APNS_KEY_FILE")
	badKey["HIVE_RELAY_APNS_KEY"] = "-----BEGIN PRIVATE KEY-----\nc2VjcmV0LW1hdGVyaWFs\n-----END PRIVATE KEY-----"
	_, err = apnsPushSenderFrom(envMap(badKey))
	if err == nil || strings.Contains(err.Error(), "c2VjcmV0") {
		t.Fatalf("a bad key must fail without echoing it: %v", err)
	}

	missingFile := full()
	missingFile["HIVE_RELAY_APNS_KEY_FILE"] = filepath.Join(t.TempDir(), "nope.p8")
	if _, err := apnsPushSenderFrom(envMap(missingFile)); err == nil {
		t.Fatal("missing key file accepted")
	}
}

// fakeAPNs is an HTTP/2 TLS server standing in for APNs.
type fakeAPNs struct {
	mu     sync.Mutex
	reqs   []*http.Request
	bodies [][]byte
	status int
	reason string
}

func newFakeAPNs(t *testing.T) (*fakeAPNs, *httptest.Server) {
	f := &fakeAPNs{status: 200}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		defer f.mu.Unlock()
		f.reqs = append(f.reqs, r)
		f.bodies = append(f.bodies, b)
		w.WriteHeader(f.status)
		if f.reason != "" {
			_, _ = w.Write([]byte(`{"reason":"` + f.reason + `"}`))
		}
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return f, srv
}

func TestAPNsSenderEnvAndPriority(t *testing.T) {
	f, srv := newFakeAPNs(t)
	path, _ := testP8(t)
	s, err := apnsPushSenderFrom(envMap(map[string]string{
		"HIVE_RELAY_APNS_KEY_FILE": path, "HIVE_RELAY_APNS_KEY_ID": "KEYID12345",
		"HIVE_RELAY_APNS_TEAM_ID": "TEAMID1234", "HIVE_RELAY_APNS_TOPIC": "com.example.hive",
	}))
	if err != nil {
		t.Fatal(err)
	}
	s.Client.HTTP, s.Client.ProductionURL, s.Client.SandboxURL = srv.Client(), srv.URL+"/prod", srv.URL+"/sandbox"
	tok := strings.Repeat("ab", 32)
	ctx := context.Background()
	cases := []struct {
		env, tokEnv, prio    string
		wantPrefix, wantPrio string
	}{
		{APNsEnvAuto, "development", "high", "/sandbox/", "10"},
		{APNsEnvAuto, "production", "normal", "/prod/", "5"},
		{APNsEnvSandbox, "production", "", "/sandbox/", "10"},
		{APNsEnvProduction, "development", "high", "/prod/", "10"},
	}
	for i, c := range cases {
		s.Env = c.env
		if err := s.Send(ctx, "2LGZFj2lCKlo49_pwPzGjw", "lg7S2X1oS18S3AUMgTzRgQ", PushToken{Token: tok, Env: c.tokEnv}, []byte{1, 2, 3}, c.prio, ""); err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		r := f.reqs[i]
		if !strings.HasPrefix(r.URL.Path, c.wantPrefix) || r.Header.Get("apns-priority") != c.wantPrio {
			t.Fatalf("case %d: %s prio %s", i, r.URL.Path, r.Header.Get("apns-priority"))
		}
		exp, _ := strconv.ParseInt(r.Header.Get("apns-expiration"), 10, 64)
		if d := exp - time.Now().Add(time.Hour).Unix(); d < -5 || d > 5 {
			t.Fatalf("case %d: apns-expiration should be now + 1 h, off by %d s", i, d)
		}
	}
	f.status, f.reason = 429, "TooManyRequests"
	if err := s.Send(ctx, "h", "p", PushToken{Token: tok, Env: "production"}, []byte{1}, "", ""); err == nil || strings.Contains(err.Error(), ErrPushTokenGone.Error()) {
		t.Fatalf("throttled: %v", err)
	}
}

// T-push through the built-in sender: a relay configured only by env reports
// push, forwards the host's ciphertext to (fake) APNs untouched, and forgets a
// token APNs calls dead.
func TestTunnel_PushViaEnvAPNs(t *testing.T) {
	path, _ := testP8(t)
	t.Setenv("HIVE_RELAY_APNS_KEY_FILE", path)
	t.Setenv("HIVE_RELAY_APNS_KEY_ID", "KEYID12345")
	t.Setenv("HIVE_RELAY_APNS_TEAM_ID", "TEAMID1234")
	t.Setenv("HIVE_RELAY_APNS_TOPIC", "com.example.hive")
	f, apnsSrv := newFakeAPNs(t)

	env := newTunnelEnv(t, nil, nil, nil)
	sender, ok := env.hub.push.(*APNsPushSender)
	if !ok {
		t.Fatalf("env APNs config didn't install the built-in sender: %T", env.hub.push)
	}
	sender.Client.HTTP, sender.Client.ProductionURL, sender.Client.SandboxURL = apnsSrv.Client(), apnsSrv.URL, apnsSrv.URL+"/sandbox"

	res, err := http.Get(env.ts.URL + "/v1/tunnel/info")
	if err != nil {
		t.Fatal(err)
	}
	var info map[string]any
	_ = json.NewDecoder(res.Body).Decode(&info)
	res.Body.Close()
	if info["push"] != true || info["billing"] != "none" {
		t.Fatalf("info: %v", info)
	}

	h := newFakeHost(t, env)
	if w := h.connect(); w["push"] != true {
		t.Fatalf("welcome: %v", w)
	}
	p := newFakePhone()
	tok := strings.Repeat("0f", 32)
	now := time.Now().Unix()
	phone := p.connect(t, env, h.id, h.cred(p.pid, p.pub(), now, now+86400),
		map[string]any{"apns": map[string]any{"token": strings.ToUpper(tok), "env": "development"}})
	o := h.next("open")
	h.send(map[string]any{"t": "reject", "sid": o["sid"], "code": "host_rejected"})
	expectClose(t, phone, 4010)

	ct := []byte("opaque-ciphertext-from-the-host")
	if a := h.request(map[string]any{"t": "push", "id": "1", "pid": p.pid, "ct": b64u(ct), "prio": "high", "collapse": "c0llapse"}); a["ok"] != true {
		t.Fatalf("push: %v", a)
	}
	f.mu.Lock()
	r, body := f.reqs[0], f.bodies[0]
	f.mu.Unlock()
	if r.ProtoMajor != 2 || r.URL.Path != "/sandbox/3/device/"+tok || r.Header.Get("apns-topic") != "com.example.hive" ||
		r.Header.Get("apns-collapse-id") != "c0llapse" || r.Header.Get("apns-priority") != "10" || r.Header.Get("apns-push-type") != "alert" {
		t.Fatalf("APNs request %s %s %v", r.Proto, r.URL.Path, r.Header)
	}
	want := `{"aps":{"alert":{"body":"New activity on your host","title":"Hive"},"mutable-content":1},"hive":{"v":1,"hid":"` +
		h.id + `","pid":"` + p.pid + `","ct":"` + b64u(ct) + `"}}`
	if string(body) != want {
		t.Fatalf("payload\n got %s\nwant %s", body, want)
	}

	// APNs says the token is dead: push_failed, and the relay forgets it.
	f.mu.Lock()
	f.status, f.reason = 410, "Unregistered"
	f.mu.Unlock()
	if a := h.request(map[string]any{"t": "push", "id": "2", "pid": p.pid, "ct": b64u(ct)}); a["code"] != "push_failed" {
		t.Fatalf("dead token: %v", a)
	}
	if got, _ := env.hub.store.TunnelPushToken(context.Background(), h.id, p.pid); got != nil {
		t.Fatalf("dead token kept: %v", got)
	}
	if a := h.request(map[string]any{"t": "push", "id": "3", "pid": p.pid, "ct": b64u(ct)}); a["code"] != "no_push_token" {
		t.Fatalf("after forgetting: %v", a)
	}
}

// An explicitly injected sender (a downstream build) wins over the env one.
func TestInjectedPushSenderWinsOverEnv(t *testing.T) {
	path, _ := testP8(t)
	t.Setenv("HIVE_RELAY_APNS_KEY_FILE", path)
	t.Setenv("HIVE_RELAY_APNS_KEY_ID", "KEYID12345")
	t.Setenv("HIVE_RELAY_APNS_TEAM_ID", "TEAMID1234")
	t.Setenv("HIVE_RELAY_APNS_TOPIC", "com.example.hive")
	fp := &fakePush{}
	env := newTunnelEnv(t, nil, fp, nil)
	if env.hub.push != PushSender(fp) {
		t.Fatalf("injected sender replaced: %T", env.hub.push)
	}
	// Misconfigured env: push stays off, the relay still starts.
	t.Setenv("HIVE_RELAY_APNS_TOPIC", "")
	env2 := newTunnelEnv(t, nil, nil, nil)
	if env2.hub.push != nil {
		t.Fatalf("partial env config must leave push off: %T", env2.hub.push)
	}
}
