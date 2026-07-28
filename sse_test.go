package relay

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// readFrame reads one SSE frame (up to the blank-line terminator) from r,
// returning the joined lines. It fails the test if nothing arrives before the
// bufio read blocks past the client's context deadline.
func readSSEChunk(t *testing.T, br *bufio.Reader) string {
	t.Helper()
	var b strings.Builder
	for {
		line, err := br.ReadString('\n')
		b.WriteString(line)
		if err != nil {
			return b.String()
		}
		if line == "\n" { // blank line terminates an SSE event
			return b.String()
		}
	}
}

// dialSSE opens the events stream and returns the response + a reader positioned
// after the response headers. The caller cancels ctx to close the stream.
func dialSSE(t *testing.T, ctx context.Context, url, bearer string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// TestSSEConnectedPreamble: connecting yields the `: connected` preamble and the
// text/event-stream content type.
func TestSSEConnectedPreamble(t *testing.T) {
	ts := testServer(entitlementPolicy{kind: entOpen}, nil)
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resp := dialSSE(t, ctx, ts.URL+"/v1/workspaces/wsSSE/events", "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("connect want 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("content-type want text/event-stream, got %q", ct)
	}
	br := bufio.NewReader(resp.Body)
	if chunk := readSSEChunk(t, br); !strings.Contains(chunk, ": connected") {
		t.Fatalf("first frame want `: connected`, got %q", chunk)
	}
}

// TestSSEPushOnAppend: appending an envelope to the workspace pushes a
// `data: {"seq":N}` event to a live subscriber.
func TestSSEPushOnAppend(t *testing.T) {
	store := newMemoryStore()
	srv := New(Options{Store: store, Entitlement: entitlementPolicy{kind: entOpen}})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resp := dialSSE(t, ctx, ts.URL+"/v1/workspaces/wsPush/events", "")
	defer resp.Body.Close()
	br := bufio.NewReader(resp.Body)

	// Drain the `: connected` preamble and the initial `data: {"seq":0}` head.
	_ = readSSEChunk(t, br) // : connected
	if head := readSSEChunk(t, br); !strings.Contains(head, `"seq":0`) {
		t.Fatalf("initial head want seq 0, got %q", head)
	}

	// Append directly to the store (the same path POST /envelopes takes) and
	// expect the push. Give the subscription a beat to be registered first.
	time.Sleep(20 * time.Millisecond)
	seq, err := store.AppendEnvelope(context.Background(), "wsPush", json.RawMessage(`{"ct":"x"}`), "")
	if err != nil {
		t.Fatal(err)
	}
	if seq != 1 {
		t.Fatalf("append seq want 1, got %d", seq)
	}

	got := make(chan string, 1)
	go func() { got <- readSSEChunk(t, br) }()
	select {
	case chunk := <-got:
		if !strings.Contains(chunk, `data: {"seq":1}`) {
			t.Fatalf("push frame want `data: {\"seq\":1}`, got %q", chunk)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for SSE push after append")
	}

	// A dedup re-push of the identical body must NOT emit a new frame.
	if _, err := store.AppendEnvelope(context.Background(), "wsPush", json.RawMessage(`{"ct":"dup"}`), "dk1"); err != nil {
		t.Fatal(err)
	}
	drain := make(chan string, 1)
	go func() { drain <- readSSEChunk(t, br) }()
	select {
	case chunk := <-drain:
		if !strings.Contains(chunk, `"seq":2`) {
			t.Fatalf("first keyed append should push seq 2, got %q", chunk)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for keyed append push")
	}
	// Re-push the same key: no new frame should arrive (verified via timeout).
	if _, err := store.AppendEnvelope(context.Background(), "wsPush", json.RawMessage(`{"ct":"dup"}`), "dk1"); err != nil {
		t.Fatal(err)
	}
	quiet := make(chan string, 1)
	go func() { quiet <- readSSEChunk(t, br) }()
	select {
	case chunk := <-quiet:
		t.Fatalf("dedup re-push must not push a frame, got %q", chunk)
	case <-time.After(300 * time.Millisecond):
		// expected: no frame
	}
}

// TestSSEReadAuthRejected: under a token-gated policy an unauthenticated connect
// is 401 (read-auth), and a valid token connects 200.
func TestSSEReadAuthRejected(t *testing.T) {
	sk := testKey(t)
	policy := entitlementPolicy{kind: entSigned, pubkey: sk.Public().(ed25519.PublicKey)}
	ts := testServer(policy, nil)
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resp := dialSSE(t, ctx, ts.URL+"/v1/workspaces/wsAuth/events", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated SSE connect want 401, got %d", resp.StatusCode)
	}

	tok := issueToken(sk, TokenClaims{Sub: "reader"})
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	resp2 := dialSSE(t, ctx2, ts.URL+"/v1/workspaces/wsAuth/events", tok)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("authenticated SSE connect want 200, got %d", resp2.StatusCode)
	}
}

// TestSSEWriteDeadlineNotSevered pins the WriteTimeout fix: the handler clears
// this connection's write deadline, so a stream held well past a *short* server
// WriteTimeout is NOT killed and still delivers a push. Without the fix the
// server would close the connection at the deadline and the append frame would
// never arrive.
func TestSSEWriteDeadlineNotSevered(t *testing.T) {
	store := newMemoryStore()
	srv := New(Options{Store: store, Entitlement: entitlementPolicy{kind: entOpen}})
	ts := httptest.NewUnstartedServer(srv.Handler())
	ts.Config.WriteTimeout = 250 * time.Millisecond // would sever a normal response
	ts.Start()
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resp := dialSSE(t, ctx, ts.URL+"/v1/workspaces/wsDL/events", "")
	defer resp.Body.Close()
	br := bufio.NewReader(resp.Body)
	_ = readSSEChunk(t, br) // : connected
	_ = readSSEChunk(t, br) // data: {"seq":0}

	// Hold the stream idle well past the server WriteTimeout, then append.
	time.Sleep(600 * time.Millisecond)
	if _, err := store.AppendEnvelope(context.Background(), "wsDL", json.RawMessage(`{"ct":"late"}`), ""); err != nil {
		t.Fatal(err)
	}
	got := make(chan string, 1)
	go func() { got <- readSSEChunk(t, br) }()
	select {
	case chunk := <-got:
		if !strings.Contains(chunk, `data: {"seq":1}`) {
			t.Fatalf("post-deadline push want seq 1, got %q", chunk)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stream was severed by the write deadline (no push after WriteTimeout)")
	}
}
