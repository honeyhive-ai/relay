package apns

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const devTok = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"

// newTestClient points a client at an httptest server that speaks HTTP/2 over
// TLS, as APNs does.
func newTestClient(t *testing.T, h http.HandlerFunc) (*Client, *ecdsa.PrivateKey) {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := New("KEYID12345", "TEAMID1234", "com.example.hive", key)
	c.HTTP = srv.Client()
	c.ProductionURL = srv.URL
	c.SandboxURL = srv.URL + "/sandbox"
	return c, key
}

// verifyJWT checks an ES256 compact JWT (raw r‖s signature) and decodes it.
func verifyJWT(pub *ecdsa.PublicKey, tok string, hdr, claims any) error {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return errors.New("not a JWT")
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return errors.New("bad signature encoding")
	}
	d := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(pub, d[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return errors.New("signature doesn't verify")
	}
	for i, out := range []any{hdr, claims} {
		b, err := b64.DecodeString(parts[i])
		if err != nil {
			return err
		}
		if err := json.Unmarshal(b, out); err != nil {
			return err
		}
	}
	return nil
}

func TestSendBuildsHTTP2RequestWithOpaquePayload(t *testing.T) {
	var got *http.Request
	var gotBody []byte
	c, key := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		got = r
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("apns-id", "abc-123")
		w.WriteHeader(200)
	})
	cipher := []byte{0x00, 0x01, 0xfe, 0xff, 'x'}
	exp := time.Unix(1_900_000_000, 0)
	res, err := c.Send(context.Background(), Message{DeviceToken: strings.ToUpper(devTok), HostID: "2LGZFj2lCKlo49_pwPzGjw", PID: "lg7S2X1oS18S3AUMgTzRgQ",
		Ciphertext: cipher, CollapseID: "chat-1", Priority: 5, Expiration: exp})
	if err != nil || !res.OK() || res.APNsID != "abc-123" {
		t.Fatalf("res %+v err %v", res, err)
	}
	if got.ProtoMajor != 2 {
		t.Fatalf("want HTTP/2, got %s", got.Proto)
	}
	if got.Method != http.MethodPost || got.URL.Path != "/3/device/"+devTok {
		t.Fatalf("%s %s", got.Method, got.URL.Path)
	}
	h := got.Header
	if h.Get("apns-topic") != "com.example.hive" || h.Get("apns-push-type") != "alert" || h.Get("apns-priority") != "5" ||
		h.Get("apns-collapse-id") != "chat-1" || h.Get("apns-expiration") != "1900000000" || h.Get("content-type") != "application/json" {
		t.Fatalf("headers %v", h)
	}
	var hdr, claims map[string]any
	if err := verifyJWT(&key.PublicKey, strings.TrimPrefix(h.Get("authorization"), "bearer "), &hdr, &claims); err != nil {
		t.Fatalf("provider token: %v", err)
	}
	if hdr["kid"] != "KEYID12345" || hdr["alg"] != "ES256" || claims["iss"] != "TEAMID1234" || claims["iat"] == nil {
		t.Fatalf("jwt %v %v", hdr, claims)
	}
	// Exactly the spec §14 body, byte for byte: nothing else leaks into it.
	want := `{"aps":{"alert":{"body":"New activity on your host","title":"Hive"},"mutable-content":1},"hive":{"v":1,"hid":"2LGZFj2lCKlo49_pwPzGjw","pid":"lg7S2X1oS18S3AUMgTzRgQ","ct":"AAH-_3g"}}`
	if string(gotBody) != want {
		t.Fatalf("payload\n got %s\nwant %s", gotBody, want)
	}
}

func TestPriorityDefaultsToImmediate(t *testing.T) {
	var prio, exp string
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		prio, exp = r.Header.Get("apns-priority"), r.Header.Get("apns-expiration")
	})
	if _, err := c.Send(context.Background(), Message{DeviceToken: devTok, Ciphertext: []byte("c")}); err != nil {
		t.Fatal(err)
	}
	if prio != "10" || exp != "" {
		t.Fatalf("priority %q expiration %q", prio, exp)
	}
}

func TestSandboxRoutingAndProviderTokenCache(t *testing.T) {
	var mu sync.Mutex
	var paths, auths []string
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		paths = append(paths, r.URL.Path)
		auths = append(auths, r.Header.Get("authorization"))
	})
	now := time.Unix(1_800_000_000, 0)
	c.Now = func() time.Time { return now }
	m := Message{DeviceToken: devTok, Ciphertext: []byte("c"), Sandbox: true}
	for i := 0; i < 2; i++ {
		if _, err := c.Send(context.Background(), m); err != nil {
			t.Fatal(err)
		}
	}
	now = now.Add(51 * time.Minute)
	m.Sandbox = false
	if _, err := c.Send(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	if paths[0] != "/sandbox/3/device/"+devTok || paths[2] != "/3/device/"+devTok {
		t.Fatalf("paths %v", paths)
	}
	if auths[0] != auths[1] {
		t.Fatal("provider token should be cached within its lifetime")
	}
	if auths[1] == auths[2] {
		t.Fatal("provider token should be refreshed after 50 minutes")
	}
}

func TestExpiredProviderTokenRetriedOnce(t *testing.T) {
	var n atomic.Int32
	var auths sync.Map
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		auths.Store(n.Add(1), r.Header.Get("authorization"))
		if n.Load() == 1 {
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`{"reason":"ExpiredProviderToken"}`))
			return
		}
		w.WriteHeader(200)
	})
	res, err := c.Send(context.Background(), Message{DeviceToken: devTok, Ciphertext: []byte("c")})
	if err != nil || !res.OK() || n.Load() != 2 {
		t.Fatalf("res %+v err %v calls %d", res, err, n.Load())
	}
	// A rejected provider token isn't retried forever.
	n.Store(0)
	c2, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(403)
		_, _ = w.Write([]byte(`{"reason":"InvalidProviderToken"}`))
	})
	res, err = c2.Send(context.Background(), Message{DeviceToken: devTok, Ciphertext: []byte("c")})
	if err != nil || res.OK() || res.Reason != "InvalidProviderToken" || n.Load() != 2 {
		t.Fatalf("res %+v err %v calls %d", res, err, n.Load())
	}
}

func TestUnregisteredAndBadTokens(t *testing.T) {
	var calls atomic.Int32
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(410)
		_, _ = w.Write([]byte(`{"reason":"Unregistered","timestamp":1}`))
	})
	res, err := c.Send(context.Background(), Message{DeviceToken: devTok, Ciphertext: []byte("c")})
	if err != nil || !res.DeviceGone() || res.Reason != "Unregistered" {
		t.Fatalf("res %+v err %v", res, err)
	}
	res, _ = c.Send(context.Background(), Message{DeviceToken: "not-hex", Ciphertext: []byte("c")})
	if !res.DeviceGone() || calls.Load() != 1 {
		t.Fatal("a malformed token should be reported gone without a request")
	}
	for _, reason := range []string{"BadDeviceToken", "DeviceTokenNotForTopic"} {
		if !(Result{Status: 400, Reason: reason}).DeviceGone() {
			t.Fatalf("%s should mean the token is gone", reason)
		}
	}
	if (Result{Status: 429, Reason: "TooManyRequests"}).DeviceGone() {
		t.Fatal("throttling isn't a dead token")
	}
}

func TestNotConfigured(t *testing.T) {
	if _, err := (&Client{}).Send(context.Background(), Message{DeviceToken: devTok, Ciphertext: []byte("c")}); err == nil {
		t.Fatal("an unconfigured client must refuse to send")
	}
}

func TestPayloadLimits(t *testing.T) {
	c := &Client{}
	if _, err := c.BuildPayload(Message{}); err == nil {
		t.Fatal("empty ciphertext accepted")
	}
	if _, err := c.BuildPayload(Message{Ciphertext: make([]byte, 3500)}); err == nil {
		t.Fatal("oversized payload accepted")
	}
	// The spec caps the raw ciphertext at 2 048 bytes; that always fits.
	if _, err := c.BuildPayload(Message{HostID: "2LGZFj2lCKlo49_pwPzGjw", PID: "lg7S2X1oS18S3AUMgTzRgQ", Ciphertext: make([]byte, 2048)}); err != nil {
		t.Fatalf("2048-byte ciphertext should fit: %v", err)
	}
	c.AlertTitle, c.AlertBody = "T", "B"
	b, _ := c.BuildPayload(Message{Ciphertext: []byte{1}})
	if !bytes.Contains(b, []byte(`"alert":{"body":"B","title":"T"}`)) {
		t.Fatalf("custom fallback alert: %s", b)
	}
}

func TestParseP8(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	got, err := ParseP8(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if err != nil || !got.Equal(key) {
		t.Fatalf("pkcs8: %v", err)
	}
	sec1, _ := x509.MarshalECPrivateKey(key)
	if got, err := ParseP8(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1})); err != nil || !got.Equal(key) {
		t.Fatalf("sec1: %v", err)
	}
	if _, err := ParseP8([]byte("nope")); err == nil {
		t.Fatal("garbage accepted")
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der, _ = x509.MarshalPKCS8PrivateKey(p384)
	if _, err := ParseP8(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err == nil {
		t.Fatal("a P-384 key must be refused")
	}
}
