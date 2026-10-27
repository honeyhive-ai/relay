package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/gorilla/websocket"
)

// Integration tests: a real relay (httptest) between a fake host and a fake
// phone that run Noise end to end through it. flynn/noise is a test-only
// dependency; the relay itself never terminates Noise.

var noiseSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

type tunnelEnv struct {
	t   *testing.T
	srv *Server
	ts  *httptest.Server
	hub *tunnelHub
}

func newTunnelEnv(t *testing.T, policy TunnelPolicy, push PushSender, tweak func(*tunnelLimits)) *tunnelEnv {
	return newTunnelEnvWith(t, policy, push, tweak, nil)
}

func newTunnelEnvWith(t *testing.T, policy TunnelPolicy, push PushSender, tweak func(*tunnelLimits), cfg func(*http.Server)) *tunnelEnv {
	t.Helper()
	if policy == nil {
		policy, _ = newEnvTunnelPolicy("open", "", nil)
	}
	srv := New(Options{Store: newMemoryStore(), TunnelPolicy: policy, PushSender: push})
	hub := srv.tunnel
	hub.lim.PingInterval = 200 * time.Millisecond
	hub.lim.AuthTimeout = 2 * time.Second
	hub.lim.OpenTimeout = 2 * time.Second
	hub.lim.WriteTimeout = 2 * time.Second
	hub.lim.ConnectsPerMin = 6000
	hub.lim.FailedAuthPerMin = 1000
	if tweak != nil {
		tweak(&hub.lim)
	}
	hub.applyLimits()
	ts := httptest.NewUnstartedServer(srv.Handler())
	if cfg != nil {
		cfg(ts.Config)
	}
	ts.Start()
	t.Cleanup(func() {
		srv.ShutdownTunnels()
		ts.Close()
	})
	return &tunnelEnv{t: t, srv: srv, ts: ts, hub: hub}
}

func (e *tunnelEnv) wsURL(path string) string {
	return "ws" + strings.TrimPrefix(e.ts.URL, "http") + path
}

func (e *tunnelEnv) dial(path string) (*websocket.Conn, error) {
	d := websocket.Dialer{Subprotocols: []string{tunnelSubprotocol}, HandshakeTimeout: 2 * time.Second}
	c, res, err := d.Dial(e.wsURL(path), nil)
	if err != nil {
		if res != nil {
			return nil, fmt.Errorf("%w (HTTP %d)", err, res.StatusCode)
		}
		return nil, err
	}
	if c.Subprotocol() != tunnelSubprotocol {
		return nil, errors.New("relay did not select the subprotocol")
	}
	return c, nil
}

func (e *tunnelEnv) mustDial(path string) *websocket.Conn {
	e.t.Helper()
	c, err := e.dial(path)
	if err != nil {
		e.t.Fatalf("dial %s: %v", path, err)
	}
	e.t.Cleanup(func() { c.Close() })
	return c
}

func readJSONMsg(t *testing.T, c *websocket.Conn) map[string]any {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	mt, data, err := c.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if mt != websocket.TextMessage {
		t.Fatalf("got binary, want text")
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func writeJSONMsg(t *testing.T, c *websocket.Conn, v any) {
	t.Helper()
	b, _ := json.Marshal(v)
	if err := c.WriteMessage(websocket.TextMessage, b); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// expectClose reads until the connection closes and asserts the close code
// (and, for relay codes, the preceding error message's code string).
func expectClose(t *testing.T, c *websocket.Conn, want int) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	var errCode string
	for {
		mt, data, err := c.ReadMessage()
		if err != nil {
			var ce *websocket.CloseError
			if !errors.As(err, &ce) {
				t.Fatalf("want close %d, got %v", want, err)
			}
			if ce.Code != want {
				t.Fatalf("close code %d (%s), want %d", ce.Code, ce.Text, want)
			}
			if want >= 4000 && errCode != "" && errCode != ce.Text {
				t.Fatalf("error code %q but close reason %q", errCode, ce.Text)
			}
			return
		}
		if mt == websocket.TextMessage {
			var m map[string]any
			_ = json.Unmarshal(data, &m)
			if m["t"] == "error" {
				errCode, _ = m["code"].(string)
			}
		}
	}
}

// ── fake host ────────────────────────────────────────────────────────────────

type fakeHost struct {
	t      *testing.T
	env    *tunnelEnv
	sign   ed25519.PrivateKey
	pub    ed25519.PublicKey
	id     string
	static noise.DHKey
	ctl    *websocket.Conn
	msgs   chan map[string]any
	closed chan error
	wmu    sync.Mutex
}

func newFakeHost(t *testing.T, env *tunnelEnv) *fakeHost {
	_, sign, _ := ed25519.GenerateKey(rand.Reader)
	static, _ := noise.DH25519.GenerateKeypair(rand.Reader)
	pub := sign.Public().(ed25519.PublicKey)
	return &fakeHost{t: t, env: env, sign: sign, pub: pub, id: TunnelHostID(pub), static: static}
}

func (h *fakeHost) hello(c *websocket.Conn, extra map[string]any) {
	ch := readJSONMsg(h.t, c)
	if ch["t"] != "challenge" || ch["v"] != float64(1) {
		h.t.Fatalf("challenge: %v", ch)
	}
	nonce := mustB64u(h.t, ch["nonce"].(string))
	m := map[string]any{"t": "hello", "v": 1, "hostId": h.id, "hostPub": b64u(h.pub),
		"sig": b64u(ed25519.Sign(h.sign, tunnelCtx("host-auth", []byte(h.id), nonce))), "agent": "fake-host/1"}
	for k, v := range extra {
		m[k] = v
	}
	writeJSONMsg(h.t, c, m)
}

// connect opens the control connection and returns the welcome.
func (h *fakeHost) connect() map[string]any {
	h.t.Helper()
	c := h.env.mustDial("/v1/tunnel/host")
	h.hello(c, nil)
	w := readJSONMsg(h.t, c)
	if w["t"] != "welcome" {
		h.t.Fatalf("welcome: %v", w)
	}
	h.ctl = c
	msgs, closed := make(chan map[string]any, 64), make(chan error, 1)
	h.msgs, h.closed = msgs, closed
	go func() {
		for {
			_ = c.SetReadDeadline(time.Time{})
			_, data, err := c.ReadMessage()
			if err != nil {
				closed <- err
				close(msgs)
				return
			}
			var m map[string]any
			_ = json.Unmarshal(data, &m)
			msgs <- m
		}
	}()
	return w
}

func (h *fakeHost) send(v any) {
	h.wmu.Lock()
	defer h.wmu.Unlock()
	writeJSONMsg(h.t, h.ctl, v)
}

func (h *fakeHost) next(t string) map[string]any {
	h.t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case m, ok := <-h.msgs:
			if !ok {
				h.t.Fatalf("control closed while waiting for %q: %v", t, <-h.closed)
			}
			if m["t"] == t {
				return m
			}
		case <-timeout:
			h.t.Fatalf("no %q on the control connection", t)
		}
	}
}

func (h *fakeHost) noOpen(within time.Duration) {
	h.t.Helper()
	timeout := time.After(within)
	for {
		select {
		case m, ok := <-h.msgs:
			if ok && m["t"] == "open" {
				h.t.Fatalf("host saw an open it shouldn't have: %v", m)
			}
			if !ok {
				return
			}
		case <-timeout:
			return
		}
	}
}

func (h *fakeHost) request(m map[string]any) map[string]any {
	h.t.Helper()
	h.send(m)
	for {
		a := h.next("ack")
		if a["id"] == m["id"] {
			return a
		}
	}
}

func (h *fakeHost) cred(pid string, phonePub ed25519.PublicKey, iat, exp int64) string {
	claims := fmt.Sprintf(`{"hid":%q,"pid":%q,"pk":%q,"iat":%d,"exp":%d}`, h.id, pid, b64u(phonePub), iat, exp)
	return signCred(h.sign, []byte(claims))
}

// ── fake phone ───────────────────────────────────────────────────────────────

type fakePhone struct {
	auth   ed25519.PrivateKey
	static noise.DHKey
	pid    string
}

func newFakePhone() *fakePhone {
	_, auth, _ := ed25519.GenerateKey(rand.Reader)
	static, _ := noise.DH25519.GenerateKeypair(rand.Reader)
	pid, _ := randomB64u(16)
	return &fakePhone{auth: auth, static: static, pid: pid}
}

func (p *fakePhone) pub() ed25519.PublicKey { return p.auth.Public().(ed25519.PublicKey) }

// connect dials /connect, answers the challenge with auth, and returns the conn.
func (p *fakePhone) connect(t *testing.T, env *tunnelEnv, hostID, cred string, extra map[string]any) *websocket.Conn {
	t.Helper()
	c := env.mustDial("/v1/tunnel/connect?host=" + hostID)
	ch := readJSONMsg(t, c)
	nonce := mustB64u(t, ch["nonce"].(string))
	m := map[string]any{"t": "auth", "cred": cred, "sig": b64u(ed25519.Sign(p.auth, tunnelCtx("phone-auth", []byte(hostID), nonce)))}
	for k, v := range extra {
		m[k] = v
	}
	writeJSONMsg(t, c, m)
	return c
}

// session sets up a spliced phone↔host session and returns both data conns.
func session(t *testing.T, env *tunnelEnv, h *fakeHost, p *fakePhone) (phone, host *websocket.Conn) {
	t.Helper()
	now := time.Now().Unix()
	phone = p.connect(t, env, h.id, h.cred(p.pid, p.pub(), now, now+90*86400), nil)
	open := h.next("open")
	if open["mode"] != "session" || open["pid"] != p.pid {
		t.Fatalf("open: %v", open)
	}
	host = env.mustDial("/v1/tunnel/accept?sid=" + open["sid"].(string))
	ready := readJSONMsg(t, phone)
	if ready["t"] != "ready" || ready["sid"] != open["sid"] {
		t.Fatalf("ready: %v", ready)
	}
	return phone, host
}

func frame(typ byte, stream uint32, payload []byte) []byte {
	out := make([]byte, 5, 5+len(payload))
	out[0] = typ
	binary.BigEndian.PutUint32(out[1:], stream)
	return append(out, payload...)
}

func readBinary(t *testing.T, c *websocket.Conn) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	mt, data, err := c.ReadMessage()
	if err != nil {
		t.Fatalf("read binary: %v", err)
	}
	if mt != websocket.BinaryMessage {
		t.Fatalf("got text %s, want binary", data)
	}
	return data
}

// noiseHandshake runs IK (or IKpsk1) through the splice and returns the
// phone's (send, recv) and host's (send, recv) cipher states plus msg payloads.
func noiseHandshake(t *testing.T, phoneC, hostC *websocket.Conn, p *fakePhone, h *fakeHost, psk []byte, p1, p2 []byte) (pSend, pRecv, hSend, hRecv *noise.CipherState, got1, got2 []byte) {
	t.Helper()
	prologue := tunnelCtx("noise", []byte(h.id))
	ci := noise.Config{CipherSuite: noiseSuite, Random: rand.Reader, Pattern: noise.HandshakeIK, Initiator: true,
		Prologue: prologue, StaticKeypair: p.static, PeerStatic: h.static.Public}
	cr := noise.Config{CipherSuite: noiseSuite, Random: rand.Reader, Pattern: noise.HandshakeIK, Initiator: false,
		Prologue: prologue, StaticKeypair: h.static}
	if psk != nil {
		ci.PresharedKey, ci.PresharedKeyPlacement = psk, 1
		cr.PresharedKey, cr.PresharedKeyPlacement = psk, 1
	}
	ini, err := noise.NewHandshakeState(ci)
	if err != nil {
		t.Fatal(err)
	}
	res, err := noise.NewHandshakeState(cr)
	if err != nil {
		t.Fatal(err)
	}
	m1, _, _, err := ini.WriteMessage(nil, p1)
	if err != nil {
		t.Fatal(err)
	}
	if err := phoneC.WriteMessage(websocket.BinaryMessage, m1); err != nil {
		t.Fatal(err)
	}
	got1, _, _, err = res.ReadMessage(nil, readBinary(t, hostC))
	if err != nil {
		t.Fatalf("host msg1: %v", err)
	}
	if !bytes.Equal(res.PeerStatic(), p.static.Public) {
		t.Fatal("host learned the wrong phone static")
	}
	m2, cs1, cs2, err := res.WriteMessage(nil, p2)
	if err != nil {
		t.Fatal(err)
	}
	hRecv, hSend = cs1, cs2
	if err := hostC.WriteMessage(websocket.BinaryMessage, m2); err != nil {
		t.Fatal(err)
	}
	got2, cs1, cs2, err = ini.ReadMessage(nil, readBinary(t, phoneC))
	if err != nil {
		t.Fatalf("phone msg2: %v", err)
	}
	pSend, pRecv = cs1, cs2
	return
}

func sendFrame(t *testing.T, c *websocket.Conn, cs *noise.CipherState, f []byte) {
	t.Helper()
	ct, err := cs.Encrypt(nil, nil, f)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.WriteMessage(websocket.BinaryMessage, ct); err != nil {
		t.Fatal(err)
	}
}

func recvFrame(t *testing.T, c *websocket.Conn, cs *noise.CipherState) []byte {
	t.Helper()
	pt, err := cs.Decrypt(nil, nil, readBinary(t, c))
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	return pt
}

// ── Tests ────────────────────────────────────────────────────────────────────

// The headline test: host control + implicit registration, phone credential +
// PoP admission, accept, ready, a Noise IK handshake end to end through the
// relay, and a framed GET /v1/health request/response — while the relay only
// ever sees ciphertext (T-relay-canary).
func TestTunnel_SessionEndToEnd(t *testing.T) {
	env := newTunnelEnv(t, nil, nil, nil)
	canary := []byte("canary-" + strings.Repeat("x", 8) + fmt.Sprint(time.Now().UnixNano()))
	var tapped [][]byte
	var tapMu sync.Mutex
	env.hub.tap = func(_ bool, msg []byte) {
		tapMu.Lock()
		tapped = append(tapped, append([]byte(nil), msg...))
		tapMu.Unlock()
	}

	h := newFakeHost(t, env)
	w := h.connect()
	if w["status"] != "active" || w["maxSessions"] != float64(8) || w["push"] != false {
		t.Fatalf("welcome: %v", w)
	}
	if rec, _ := env.hub.store.TunnelHost(context.Background(), h.id); rec == nil || !bytes.Equal(rec.Pub, h.pub) {
		t.Fatal("host was not registered on first hello")
	}

	p := newFakePhone()
	phone, host := session(t, env, h, p)
	pSend, pRecv, hSend, hRecv, got1, got2 := noiseHandshake(t, phone, host, p, h, nil, []byte(`{"v":1}`), []byte(`{"v":1}`))
	if string(got1) != `{"v":1}` || string(got2) != `{"v":1}` {
		t.Fatalf("payloads %q %q", got1, got2)
	}

	head := fmt.Sprintf(`{"method":"GET","path":"/v1/health","headers":[["x-canary",%q]]}`, canary)
	sendFrame(t, phone, pSend, frame(0x01, 1, []byte(head)))
	sendFrame(t, phone, pSend, frame(0x03, 1, nil))
	if f := recvFrame(t, host, hRecv); f[0] != 0x01 || binary.BigEndian.Uint32(f[1:5]) != 1 || !bytes.Contains(f[5:], canary) {
		t.Fatalf("host got OPEN %x", f)
	}
	if f := recvFrame(t, host, hRecv); f[0] != 0x03 {
		t.Fatalf("host got %x, want FIN", f)
	}
	sendFrame(t, host, hSend, frame(0x05, 1, []byte(`{"status":200,"headers":[["content-type","text/plain"]]}`)))
	sendFrame(t, host, hSend, frame(0x02, 1, []byte("ok")))
	sendFrame(t, host, hSend, frame(0x03, 1, nil))
	if f := recvFrame(t, phone, pRecv); f[0] != 0x05 || !bytes.Contains(f, []byte(`"status":200`)) {
		t.Fatalf("phone got %x, want RESPONSE", f)
	}
	if f := recvFrame(t, phone, pRecv); f[0] != 0x02 || string(f[5:]) != "ok" {
		t.Fatalf("phone got %x, want DATA ok", f)
	}
	if f := recvFrame(t, phone, pRecv); f[0] != 0x03 {
		t.Fatalf("phone got %x, want FIN", f)
	}

	tapMu.Lock()
	n := len(tapped)
	for _, m := range tapped {
		if bytes.Contains(m, canary) || bytes.Contains(m, []byte("/v1/health")) {
			t.Fatal("the relay saw plaintext")
		}
	}
	tapMu.Unlock()
	if n != 7 { // msg1, msg2, OPEN, FIN, RESPONSE, DATA, FIN — 1:1, nothing injected
		t.Fatalf("relay forwarded %d messages, want 7", n)
	}

	// A normal close passes through as 1000.
	_ = phone.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseGoingAway, ""), time.Now().Add(time.Second))
	expectClose(t, host, websocket.CloseNormalClosure)
}

// The relay forwards Noise bytes unchanged: the vector transcript replays
// byte-for-byte through a splice (session and enrollment).
func TestTunnel_SpliceIsByteExact(t *testing.T) {
	v := loadTunnelVectors(t)
	env := newTunnelEnv(t, nil, nil, nil)
	h := newFakeHost(t, env)
	h.connect()
	phone, host := session(t, env, h, newFakePhone())
	for _, tr := range []tunnelTranscript{v.Session, v.Enrollment} {
		for _, m := range []string{tr.Msg1Hex} {
			_ = phone.WriteMessage(websocket.BinaryMessage, mustHex(t, m))
			if got := readBinary(t, host); !bytes.Equal(got, mustHex(t, m)) {
				t.Fatal("msg1 altered")
			}
		}
		_ = host.WriteMessage(websocket.BinaryMessage, mustHex(t, tr.Msg2Hex))
		if got := readBinary(t, phone); !bytes.Equal(got, mustHex(t, tr.Msg2Hex)) {
			t.Fatal("msg2 altered")
		}
		for _, x := range tr.Transport {
			src, dst := phone, host
			if x.Dir == "host->phone" {
				src, dst = host, phone
			}
			_ = src.WriteMessage(websocket.BinaryMessage, mustHex(t, x.Wire))
			if got := readBinary(t, dst); !bytes.Equal(got, mustHex(t, x.Wire)) {
				t.Fatal("transport altered")
			}
		}
	}
}

// Enrollment: window over control, phone enroll with tag, IKpsk1 end to end,
// credential delivered in msg2, PING/PONG, enrollClose.
func TestTunnel_EnrollmentEndToEnd(t *testing.T) {
	env := newTunnelEnv(t, nil, nil, nil)
	h := newFakeHost(t, env)
	h.connect()
	ps := make([]byte, 32)
	_, _ = rand.Read(ps)
	derive := func(info string, n int) []byte { return hkdfTest(t, ps, info, n) }
	eid, tag, psk := b64u(derive("enroll-id", 16)), derive("relay-tag", 32), derive("noise-psk", 32)
	tagHash := sha256.Sum256(tag)
	a := h.request(map[string]any{"t": "enroll", "id": "e1", "eid": eid, "tagHash": b64u(tagHash[:]), "exp": time.Now().Unix() + 600})
	if a["ok"] != true {
		t.Fatalf("enroll ack: %v", a)
	}

	p := newFakePhone()
	phone := env.mustDial("/v1/tunnel/connect?host=" + h.id)
	readJSONMsg(t, phone) // challenge
	writeJSONMsg(t, phone, map[string]any{"t": "enroll", "eid": eid, "tag": b64u(tag)})
	open := h.next("open")
	if open["mode"] != "enroll" || open["eid"] != eid {
		t.Fatalf("open: %v", open)
	}
	host := env.mustDial("/v1/tunnel/accept?sid=" + open["sid"].(string))
	if r := readJSONMsg(t, phone); r["t"] != "ready" {
		t.Fatalf("ready: %v", r)
	}
	now := time.Now().Unix()
	cred := h.cred(p.pid, p.pub(), now, now+90*86400)
	msg1 := fmt.Sprintf(`{"v":1,"name":"Test iPhone","pk":%q}`, b64u(p.pub()))
	msg2 := fmt.Sprintf(`{"v":1,"pid":%q,"cred":%q}`, p.pid, cred)
	pSend, pRecv, hSend, hRecv, got1, got2 := noiseHandshake(t, phone, host, p, h, psk, []byte(msg1), []byte(msg2))
	if string(got1) != msg1 || string(got2) != msg2 {
		t.Fatal("enrollment payloads mismatch")
	}
	sendFrame(t, phone, pSend, frame(0x07, 0, []byte{1, 2, 3, 4, 5, 6, 7, 8}))
	if f := recvFrame(t, host, hRecv); f[0] != 0x07 {
		t.Fatal("no PING")
	}
	sendFrame(t, host, hSend, frame(0x08, 0, []byte{1, 2, 3, 4, 5, 6, 7, 8}))
	if f := recvFrame(t, phone, pRecv); f[0] != 0x08 {
		t.Fatal("no PONG")
	}
	if a := h.request(map[string]any{"t": "enrollClose", "id": "e2", "eid": eid}); a["ok"] != true {
		t.Fatalf("enrollClose: %v", a)
	}
	// The issued credential now admits a session.
	phone.Close()
	host.Close()
	ph2 := p.connect(t, env, h.id, cred, nil)
	if o := h.next("open"); o["pid"] != p.pid {
		t.Fatalf("open: %v", o)
	}
	_ = ph2
	// The closed window is gone (T-qr-reuse).
	ph3 := env.mustDial("/v1/tunnel/connect?host=" + h.id)
	readJSONMsg(t, ph3)
	writeJSONMsg(t, ph3, map[string]any{"t": "enroll", "eid": eid, "tag": b64u(tag)})
	expectClose(t, ph3, 4001)
}

func hkdfTest(t *testing.T, ikm []byte, info string, n int) []byte {
	t.Helper()
	out, err := hkdf.Key(sha256.New, ikm, []byte(tunnelLabel), info, n)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// T-relay-gate: bad admissions are closed with the right code and the host
// never sees an open.
func TestTunnel_RelayGate(t *testing.T) {
	env := newTunnelEnv(t, nil, nil, func(l *tunnelLimits) { l.AuthTimeout = 300 * time.Millisecond })
	h := newFakeHost(t, env)
	h.connect()
	other := newFakeHost(t, env)
	p := newFakePhone()
	now := time.Now().Unix()
	good := h.cred(p.pid, p.pub(), now, now+86400)

	t.Run("no auth", func(t *testing.T) {
		c := env.mustDial("/v1/tunnel/connect?host=" + h.id)
		readJSONMsg(t, c)
		expectClose(t, c, 4012)
	})
	t.Run("bad PoP", func(t *testing.T) {
		c := newFakePhone().connect(t, env, h.id, good, nil) // signs with another key
		expectClose(t, c, 4001)
	})
	t.Run("replayed auth", func(t *testing.T) {
		c := env.mustDial("/v1/tunnel/connect?host=" + h.id)
		readJSONMsg(t, c)
		stale := b64u(ed25519.Sign(p.auth, tunnelCtx("phone-auth", []byte(h.id), make([]byte, 32))))
		writeJSONMsg(t, c, map[string]any{"t": "auth", "cred": good, "sig": stale})
		expectClose(t, c, 4001)
	})
	t.Run("credential from another host's key", func(t *testing.T) {
		forged := signCred(other.sign, []byte(fmt.Sprintf(`{"hid":%q,"pid":%q,"pk":%q,"iat":%d,"exp":%d}`, h.id, p.pid, b64u(p.pub()), now, now+86400)))
		expectClose(t, p.connect(t, env, h.id, forged, nil), 4001)
	})
	t.Run("expired", func(t *testing.T) {
		expectClose(t, p.connect(t, env, h.id, h.cred(p.pid, p.pub(), now-200, now-100), nil), 4002)
	})
	t.Run("unknown host", func(t *testing.T) {
		expectClose(t, p.connect(t, env, other.id, other.cred(p.pid, p.pub(), now, now+100), nil), 4004)
	})
	t.Run("unknown t is ignored, then auth", func(t *testing.T) {
		c := env.mustDial("/v1/tunnel/connect?host=" + h.id)
		ch := readJSONMsg(t, c)
		writeJSONMsg(t, c, map[string]any{"t": "future-thing"})
		nonce := mustB64u(t, ch["nonce"].(string))
		writeJSONMsg(t, c, map[string]any{"t": "auth", "cred": "nope", "sig": b64u(ed25519.Sign(p.auth, tunnelCtx("phone-auth", []byte(h.id), nonce)))})
		expectClose(t, c, 4001)
	})
	t.Run("revoked", func(t *testing.T) {
		if a := h.request(map[string]any{"t": "revoke", "id": "r1", "pid": p.pid, "exp": now + 86400}); a["ok"] != true {
			t.Fatalf("revoke ack: %v", a)
		}
		expectClose(t, p.connect(t, env, h.id, good, nil), 4003)
	})
	h.noOpen(200 * time.Millisecond)
}

// T-revoke at the relay: a live splice ends at once, reconnects get 4003, and
// the push token is dropped.
func TestTunnel_RevocationKillsLiveSessions(t *testing.T) {
	push := &fakePush{}
	env := newTunnelEnv(t, nil, push, nil)
	h := newFakeHost(t, env)
	h.connect()
	p := newFakePhone()
	now := time.Now().Unix()
	cred := h.cred(p.pid, p.pub(), now, now+86400)
	phone := p.connect(t, env, h.id, cred, map[string]any{"apns": map[string]any{"token": "ABCDEF01", "env": "production"}})
	open := h.next("open")
	host := env.mustDial("/v1/tunnel/accept?sid=" + open["sid"].(string))
	readJSONMsg(t, phone) // ready
	if tok, _ := env.hub.store.TunnelPushToken(context.Background(), h.id, p.pid); tok == nil || tok.Token != "abcdef01" {
		t.Fatalf("apns token not stored: %v", tok)
	}

	other := newFakePhone()
	ph2, _ := session(t, env, h, other) // unaffected

	start := time.Now()
	if a := h.request(map[string]any{"t": "revoke", "id": "r", "pid": p.pid, "exp": now + 86400}); a["ok"] != true {
		t.Fatalf("ack %v", a)
	}
	expectClose(t, phone, 4003)
	expectClose(t, host, 4003)
	if time.Since(start) > time.Second {
		t.Fatal("revocation took longer than 1 s")
	}
	if tok, _ := env.hub.store.TunnelPushToken(context.Background(), h.id, p.pid); tok != nil {
		t.Fatal("push token survived revocation")
	}
	expectClose(t, p.connect(t, env, h.id, cred, nil), 4003)
	// The other phone's session is still up.
	if err := ph2.WriteMessage(websocket.BinaryMessage, []byte{1}); err != nil {
		t.Fatal(err)
	}
	// Revocation survives a relay restart (durable store).
	ms := env.srv.store.(*memoryStore)
	if rv, _ := ms.TunnelPhoneRevoked(context.Background(), h.id, p.pid, now); !rv {
		t.Fatal("revocation not in the durable store")
	}
}

type fakePush struct {
	mu    sync.Mutex
	sent  [][]byte
	token PushToken
}

func (f *fakePush) Send(_ context.Context, _, _ string, tok PushToken, ct []byte, _, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, ct)
	f.token = tok
	return nil
}

func TestTunnel_Push(t *testing.T) {
	push := &fakePush{}
	env := newTunnelEnv(t, nil, push, nil)
	h := newFakeHost(t, env)
	if w := h.connect(); w["push"] != true {
		t.Fatalf("welcome push: %v", w)
	}
	p := newFakePhone()
	ct := b64u(bytes.Repeat([]byte{0xAB}, 100))
	if a := h.request(map[string]any{"t": "push", "id": "1", "pid": p.pid, "ct": ct, "prio": "high"}); a["ok"] != false || a["code"] != "no_push_token" {
		t.Fatalf("push without token: %v", a)
	}
	now := time.Now().Unix()
	phone := p.connect(t, env, h.id, h.cred(p.pid, p.pub(), now, now+86400), map[string]any{"apns": map[string]any{"token": "00ff", "env": "development"}})
	o := h.next("open")
	h.send(map[string]any{"t": "reject", "sid": o["sid"], "code": "host_rejected"})
	expectClose(t, phone, 4010)
	if a := h.request(map[string]any{"t": "push", "id": "2", "pid": p.pid, "ct": ct, "prio": "high", "collapse": "abc"}); a["ok"] != true {
		t.Fatalf("push: %v", a)
	}
	push.mu.Lock()
	if len(push.sent) != 1 || !bytes.Equal(push.sent[0], bytes.Repeat([]byte{0xAB}, 100)) || push.token.Env != "development" {
		t.Fatalf("sender got %v %v", push.sent, push.token)
	}
	push.mu.Unlock()
	if a := h.request(map[string]any{"t": "push", "id": "3", "pid": p.pid, "ct": b64u(make([]byte, 2049))}); a["code"] != "protocol" {
		t.Fatalf("oversized push: %v", a)
	}

	// No PushSender: push_unavailable.
	env2 := newTunnelEnv(t, nil, nil, nil)
	h2 := newFakeHost(t, env2)
	h2.connect()
	if a := h2.request(map[string]any{"t": "push", "id": "1", "pid": p.pid, "ct": ct}); a["code"] != "push_unavailable" {
		t.Fatalf("no sender: %v", a)
	}
}

func TestTunnel_HostAuth(t *testing.T) {
	env := newTunnelEnv(t, nil, nil, nil)
	t.Run("wrong subprotocol → 426", func(t *testing.T) {
		d := websocket.Dialer{Subprotocols: []string{"hive-tunnel.2"}}
		_, res, err := d.Dial(env.wsURL("/v1/tunnel/host"), nil)
		if err == nil || res == nil || res.StatusCode != http.StatusUpgradeRequired {
			t.Fatalf("got %v %v", res, err)
		}
	})
	t.Run("v:2 → 4026", func(t *testing.T) {
		h := newFakeHost(t, env)
		c := env.mustDial("/v1/tunnel/host")
		h.hello(c, map[string]any{"v": 2})
		expectClose(t, c, 4026)
	})
	t.Run("someone else's hostId → 4001 (T-hostid-claim)", func(t *testing.T) {
		victim, h := newFakeHost(t, env), newFakeHost(t, env)
		c := env.mustDial("/v1/tunnel/host")
		h.hello(c, map[string]any{"hostId": victim.id})
		expectClose(t, c, 4001)
	})
	t.Run("bad signature → 4001", func(t *testing.T) {
		h := newFakeHost(t, env)
		c := env.mustDial("/v1/tunnel/host")
		h.hello(c, map[string]any{"sig": b64u(make([]byte, 64))})
		expectClose(t, c, 4001)
	})
	t.Run("no hello → 4012", func(t *testing.T) {
		env.hub.lim.AuthTimeout = 200 * time.Millisecond
		defer func() { env.hub.lim.AuthTimeout = 2 * time.Second }()
		c := env.mustDial("/v1/tunnel/host")
		readJSONMsg(t, c)
		expectClose(t, c, 4012)
	})
	t.Run("second control supersedes the first", func(t *testing.T) {
		h := newFakeHost(t, env)
		h.connect()
		first := h.ctl
		firstClosed := h.closed
		h.connect()
		err := <-firstClosed
		var ce *websocket.CloseError
		if !errors.As(err, &ce) || ce.Code != 4009 {
			t.Fatalf("first control: %v", err)
		}
		_ = first
		// The new one still serves.
		if a := h.request(map[string]any{"t": "enrollClose", "id": "x", "eid": "AAAAAAAAAAAAAAAAAAAAAA"}); a["ok"] != true {
			t.Fatalf("ack: %v", a)
		}
	})
	t.Run("allowlist rejects unlisted hosts", func(t *testing.T) {
		listed := newFakeHost(t, env)
		pol, _ := newEnvTunnelPolicy("allowlist", listed.id, nil)
		env2 := newTunnelEnv(t, pol, nil, nil)
		listed.env = env2
		listed.connect()
		h := newFakeHost(t, env2)
		c := env2.mustDial("/v1/tunnel/host")
		h.hello(c, nil)
		expectClose(t, c, 4001)
	})
	t.Run("registration token checked against the entitlement gate", func(t *testing.T) {
		pol, _ := newEnvTunnelPolicy("open", "", entitlementPolicy{kind: entTokens, tokenHashes: []string{sha256hex("op")}})
		env2 := newTunnelEnv(t, pol, nil, nil)
		h := newFakeHost(t, env2)
		c := env2.mustDial("/v1/tunnel/host")
		h.hello(c, map[string]any{"reg": "wrong"})
		expectClose(t, c, 4001)
		c = env2.mustDial("/v1/tunnel/host")
		h.hello(c, map[string]any{"reg": "op"})
		if w := readJSONMsg(t, c); w["t"] != "welcome" {
			t.Fatalf("welcome: %v", w)
		}
	})
}

// stubPolicy reports a fixed status (the hosted build's seam).
type stubPolicy struct {
	mu sync.Mutex
	st HostStatus
}

func (s *stubPolicy) Register(context.Context, string, ed25519.PublicKey, string) error { return nil }
func (s *stubPolicy) Status(context.Context, string) (HostStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st, nil
}

// A pending host: sessions are refused (4006) but enrollment works, capped.
func TestTunnel_PendingHost(t *testing.T) {
	pol := &stubPolicy{st: HostStatus{Active: false}}
	env := newTunnelEnv(t, pol, nil, func(l *tunnelLimits) {
		l.EnrollSpliceBytes = 1000
		l.StatusTTL = 100 * time.Millisecond
	})
	h := newFakeHost(t, env)
	if w := h.connect(); w["status"] != "pending" {
		t.Fatalf("welcome: %v", w)
	}
	p := newFakePhone()
	now := time.Now().Unix()
	cred := h.cred(p.pid, p.pub(), now, now+86400)
	expectClose(t, p.connect(t, env, h.id, cred, nil), 4006)

	tag := bytes.Repeat([]byte{3}, 32)
	sum := sha256.Sum256(tag)
	eid, _ := randomB64u(16)
	h.request(map[string]any{"t": "enroll", "id": "e", "eid": eid, "tagHash": b64u(sum[:]), "exp": now + 300})
	phone := env.mustDial("/v1/tunnel/connect?host=" + h.id)
	readJSONMsg(t, phone)
	writeJSONMsg(t, phone, map[string]any{"t": "enroll", "eid": eid, "tag": b64u(tag)})
	host := env.mustDial("/v1/tunnel/accept?sid=" + h.next("open")["sid"].(string))
	readJSONMsg(t, phone) // ready
	_ = phone.WriteMessage(websocket.BinaryMessage, make([]byte, 600))
	readBinary(t, host)
	_ = phone.WriteMessage(websocket.BinaryMessage, make([]byte, 600)) // over the 1000-byte cap
	expectClose(t, phone, 4029)
	expectClose(t, host, 4029)

	// Entitlement arrives: the host is told, and sessions work.
	pol.mu.Lock()
	pol.st = HostStatus{Active: true, MaxSessions: 2}
	pol.mu.Unlock()
	if s := h.next("status"); s["status"] != "active" {
		t.Fatalf("status: %v", s)
	}
	time.Sleep(150 * time.Millisecond) // let the cache expire
	session(t, env, h, p)
}

func TestTunnel_Limits(t *testing.T) {
	t.Run("sessions per phone", func(t *testing.T) {
		env := newTunnelEnv(t, nil, nil, nil)
		h := newFakeHost(t, env)
		h.connect()
		p := newFakePhone()
		for i := 0; i < 3; i++ {
			session(t, env, h, p)
		}
		now := time.Now().Unix()
		expectClose(t, p.connect(t, env, h.id, h.cred(p.pid, p.pub(), now, now+100), nil), 4029)
	})
	t.Run("text message over 8 KiB → 1009", func(t *testing.T) {
		env := newTunnelEnv(t, nil, nil, nil)
		c := env.mustDial("/v1/tunnel/connect?host=AAAAAAAAAAAAAAAAAAAAAA")
		readJSONMsg(t, c)
		_ = c.WriteMessage(websocket.TextMessage, []byte(`{"t":"auth","cred":"`+strings.Repeat("a", 9000)+`"}`))
		expectClose(t, c, websocket.CloseMessageTooBig)
	})
	t.Run("binary over 65535 → 1009, passed to the other side", func(t *testing.T) {
		env := newTunnelEnv(t, nil, nil, nil)
		h := newFakeHost(t, env)
		h.connect()
		phone, host := session(t, env, h, newFakePhone())
		_ = phone.WriteMessage(websocket.BinaryMessage, make([]byte, 65535)) // max is fine
		if got := readBinary(t, host); len(got) != 65535 {
			t.Fatal("max-size message not forwarded")
		}
		_ = phone.WriteMessage(websocket.BinaryMessage, make([]byte, 65536))
		expectClose(t, phone, websocket.CloseMessageTooBig)
		expectClose(t, host, websocket.CloseMessageTooBig)
	})
	t.Run("text after ready → 4000", func(t *testing.T) {
		env := newTunnelEnv(t, nil, nil, nil)
		h := newFakeHost(t, env)
		h.connect()
		phone, host := session(t, env, h, newFakePhone())
		writeJSONMsg(t, phone, map[string]any{"t": "hello"})
		expectClose(t, phone, 4000)
		expectClose(t, host, 4000)
	})
	t.Run("failed auth blocks the IP", func(t *testing.T) {
		env := newTunnelEnv(t, nil, nil, func(l *tunnelLimits) { l.FailedAuthPerMin = 3 })
		h := newFakeHost(t, env)
		h.connect()
		p := newFakePhone()
		for i := 0; i < 3; i++ {
			expectClose(t, p.connect(t, env, h.id, "hpc1.bad.bad", nil), 4001)
		}
		c := env.mustDial("/v1/tunnel/connect?host=" + h.id)
		expectClose(t, c, 4029)
	})
	t.Run("connect rate per IP", func(t *testing.T) {
		env := newTunnelEnv(t, nil, nil, func(l *tunnelLimits) { l.ConnectsPerMin = 2 })
		for i := 0; i < 2; i++ {
			c := env.mustDial("/v1/tunnel/connect?host=AAAAAAAAAAAAAAAAAAAAAA")
			if m := readJSONMsg(t, c); m["t"] != "challenge" {
				t.Fatalf("%v", m)
			}
		}
		expectClose(t, env.mustDial("/v1/tunnel/connect?host=AAAAAAAAAAAAAAAAAAAAAA"), 4029)
	})
	t.Run("enrollment windows and attempts", func(t *testing.T) {
		env := newTunnelEnv(t, nil, nil, nil)
		h := newFakeHost(t, env)
		h.connect()
		now := time.Now().Unix()
		tag := bytes.Repeat([]byte{5}, 32)
		sum := sha256.Sum256(tag)
		eids := make([]string, 3)
		for i := range eids {
			eids[i], _ = randomB64u(16)
		}
		for i, want := range []bool{true, true, false} {
			a := h.request(map[string]any{"t": "enroll", "id": fmt.Sprint(i), "eid": eids[i], "tagHash": b64u(sum[:]), "exp": now + 300})
			if a["ok"] != want {
				t.Fatalf("window %d: %v", i, a)
			}
		}
		if a := h.request(map[string]any{"t": "enroll", "id": "long", "eid": eids[0], "tagHash": b64u(sum[:]), "exp": now + 3600}); a["ok"] != false {
			t.Fatalf("over-long window accepted: %v", a)
		}
		for i := 0; i < 5; i++ { // 5 wrong tags use up the window…
			c := env.mustDial("/v1/tunnel/connect?host=" + h.id)
			readJSONMsg(t, c)
			writeJSONMsg(t, c, map[string]any{"t": "enroll", "eid": eids[0], "tag": b64u(make([]byte, 32))})
			expectClose(t, c, 4001)
		}
		c := env.mustDial("/v1/tunnel/connect?host=" + h.id) // …so even the right tag fails now
		readJSONMsg(t, c)
		writeJSONMsg(t, c, map[string]any{"t": "enroll", "eid": eids[0], "tag": b64u(tag)})
		expectClose(t, c, 4001)
		h.noOpen(100 * time.Millisecond)
	})
}

func TestTunnel_OpenOutcomes(t *testing.T) {
	env := newTunnelEnv(t, nil, nil, func(l *tunnelLimits) { l.OpenTimeout = 300 * time.Millisecond })
	h := newFakeHost(t, env)
	p := newFakePhone()
	now := time.Now().Unix()
	// Registered but offline.
	h.connect()
	cred := h.cred(p.pid, p.pub(), now, now+86400)
	h.ctl.Close()
	time.Sleep(100 * time.Millisecond)
	expectClose(t, p.connect(t, env, h.id, cred, nil), 4008)

	h.connect()
	t.Run("host never attaches → 4012, sid then dead", func(t *testing.T) {
		phone := p.connect(t, env, h.id, cred, nil)
		sid := h.next("open")["sid"].(string)
		expectClose(t, phone, 4012)
		expectClose(t, env.mustDial("/v1/tunnel/accept?sid="+sid), 4001)
	})
	t.Run("sid is single-use", func(t *testing.T) {
		phone := p.connect(t, env, h.id, cred, nil)
		sid := h.next("open")["sid"].(string)
		env.mustDial("/v1/tunnel/accept?sid=" + sid)
		readJSONMsg(t, phone)
		expectClose(t, env.mustDial("/v1/tunnel/accept?sid="+sid), 4001)
	})
	t.Run("unknown sid", func(t *testing.T) {
		expectClose(t, env.mustDial("/v1/tunnel/accept?sid=nope"), 4001)
	})
	t.Run("custom close codes pass through", func(t *testing.T) {
		phone, host := session(t, env, h, p)
		_ = host.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(4321, "bye"), time.Now().Add(time.Second))
		expectClose(t, phone, 4321)
	})
	t.Run("deregister forgets the host", func(t *testing.T) {
		phone, _ := session(t, env, h, p)
		if a := h.request(map[string]any{"t": "deregister", "id": "d"}); a["ok"] != true {
			t.Fatalf("%v", a)
		}
		expectClose(t, phone, 4004)
		expectClose(t, p.connect(t, env, h.id, cred, nil), 4004)
	})
}

// The http.Server's read/write timeouts must not sever a hijacked tunnel conn
// (spec §10): a session idles past them and still works.
func TestTunnel_ServerTimeoutsCleared(t *testing.T) {
	env := newTunnelEnvWith(t, nil, nil, nil, func(s *http.Server) {
		s.ReadTimeout = 300 * time.Millisecond
		s.WriteTimeout = 300 * time.Millisecond
	})
	h := newFakeHost(t, env)
	h.connect()
	phone, host := session(t, env, h, newFakePhone())
	time.Sleep(time.Second)
	_ = phone.WriteMessage(websocket.BinaryMessage, []byte("late"))
	if got := readBinary(t, host); string(got) != "late" {
		t.Fatal("message lost")
	}
	_ = host.WriteMessage(websocket.BinaryMessage, []byte("reply"))
	if got := readBinary(t, phone); string(got) != "reply" {
		t.Fatal("reply lost")
	}
	if a := h.request(map[string]any{"t": "enrollClose", "id": "x", "eid": "AAAAAAAAAAAAAAAAAAAAAA"}); a["ok"] != true {
		t.Fatal("control conn died")
	}
}

// Keepalive: the relay pings; a peer that stops answering (and sends nothing)
// is closed. gorilla answers pings only while reading, so a non-reading client
// is silent.
func TestTunnel_SilentPeerClosed(t *testing.T) {
	env := newTunnelEnv(t, nil, nil, func(l *tunnelLimits) {
		l.PingInterval = 50 * time.Millisecond
		l.PeerSilence = 300 * time.Millisecond
	})
	h := newFakeHost(t, env)
	h.connect()
	// drain reads a conn until it closes (answering pings), reporting the error.
	drain := func(c *websocket.Conn, pings *atomic.Int32) <-chan error {
		done := make(chan error, 1)
		c.SetPingHandler(func(s string) error {
			pings.Add(1)
			return c.WriteControl(websocket.PongMessage, []byte(s), time.Now().Add(time.Second))
		})
		go func() {
			for {
				_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
				if _, _, err := c.ReadMessage(); err != nil {
					done <- err
					return
				}
			}
		}()
		return done
	}
	var livePings, hostPings, silentHostPings atomic.Int32
	livePhone, liveHost := session(t, env, h, newFakePhone())
	liveDone, liveHostDone := drain(livePhone, &livePings), drain(liveHost, &hostPings)
	silentPhone, silentHost := session(t, env, h, newFakePhone()) // never reads → never pongs
	silentHostDone := drain(silentHost, &silentHostPings)

	select {
	case err := <-silentHostDone:
		var ce *websocket.CloseError
		if !errors.As(err, &ce) || ce.Code != 4012 {
			t.Fatalf("silent session's host side: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("silent phone not closed")
	}
	expectClose(t, silentPhone, 4012) // buffered: error + close frame

	time.Sleep(400 * time.Millisecond) // past PeerSilence again
	select {
	case err := <-liveDone:
		t.Fatalf("live session closed: %v", err)
	case err := <-liveHostDone:
		t.Fatalf("live host closed: %v", err)
	default:
	}
	if livePings.Load() < 3 {
		t.Fatalf("relay pings: %d", livePings.Load())
	}
}

func TestTunnel_ShutdownClosesWith4011(t *testing.T) {
	env := newTunnelEnv(t, nil, nil, nil)
	h := newFakeHost(t, env)
	h.connect()
	phone, host := session(t, env, h, newFakePhone())
	env.srv.ShutdownTunnels()
	expectClose(t, phone, 4011)
	expectClose(t, host, 4011)
	err := <-h.closed
	var ce *websocket.CloseError
	if !errors.As(err, &ce) || ce.Code != 4011 {
		t.Fatalf("control: %v", err)
	}
	c, err := env.dial("/v1/tunnel/host")
	if err == nil {
		expectClose(t, c, 4011)
	}
}

// T-backpressure (relay share): a phone that stops reading stalls the host's
// writes instead of making the relay buffer — at most one message is in flight
// per direction — and nothing is lost or reordered once it reads again.
func TestTunnel_Backpressure(t *testing.T) {
	env := newTunnelEnv(t, nil, nil, func(l *tunnelLimits) { l.WriteTimeout = 20 * time.Second })
	var tapped atomic.Int64
	env.hub.tap = func(bool, []byte) { tapped.Add(1) }
	h := newFakeHost(t, env)
	h.connect()
	phone, host := session(t, env, h, newFakePhone())

	const size = 60000
	var sent atomic.Int64
	stop := make(chan struct{})
	go func() {
		msg := make([]byte, size)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			binary.BigEndian.PutUint64(msg, uint64(i))
			_ = host.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := host.WriteMessage(websocket.BinaryMessage, msg); err != nil {
				return
			}
			sent.Add(1)
		}
	}()
	// Wait until the host's writes stall.
	var last int64 = -1
	for i := 0; i < 50; i++ {
		time.Sleep(200 * time.Millisecond)
		if n := sent.Load(); n == last && n > 0 {
			break
		} else {
			last = n
		}
	}
	stalled := sent.Load()
	if stalled*size > 64<<20 {
		t.Fatalf("host wrote %d MB without the phone reading: no backpressure", stalled*size>>20)
	}
	// The relay read at most one message beyond what it delivered: everything it
	// tapped was written to the phone's socket or is the one in flight.
	if tp := tapped.Load(); tp > stalled {
		t.Fatalf("relay forwarded %d of %d sent", tp, stalled)
	}
	close(stop)
	for i := int64(0); i < stalled; i++ {
		got := readBinary(t, phone)
		if len(got) != size || binary.BigEndian.Uint64(got) != uint64(i) {
			t.Fatalf("message %d out of order or altered", i)
		}
	}
}

// RefreshTunnelStatus applies a policy change at once (no StatusTTL wait): the
// connected host gets {"t":"status"} and the next phone connect is admitted.
func TestTunnel_RefreshTunnelStatus(t *testing.T) {
	pol := &stubPolicy{st: HostStatus{Active: false}}
	env := newTunnelEnv(t, pol, nil, nil) // default StatusTTL: 60 s
	h := newFakeHost(t, env)
	if w := h.connect(); w["status"] != "pending" {
		t.Fatalf("welcome: %v", w)
	}
	p := newFakePhone()
	now := time.Now().Unix()
	expectClose(t, p.connect(t, env, h.id, h.cred(p.pid, p.pub(), now, now+86400), nil), 4006)

	pol.mu.Lock()
	pol.st = HostStatus{Active: true}
	pol.mu.Unlock()
	env.srv.RefreshTunnelStatus(h.id)
	if s := h.next("status"); s["status"] != "active" {
		t.Fatalf("status: %v", s)
	}
	session(t, env, h, p)

	// Unknown host ids and repeated calls are harmless.
	env.srv.RefreshTunnelStatus("AAAAAAAAAAAAAAAAAAAAAA")
	env.srv.RefreshTunnelStatus(h.id)
	env.srv.RefreshTunnelStatus(h.id)
}
