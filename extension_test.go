package relay

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func extDo(t *testing.T, h http.Handler, method, path, bearer, body string) (int, string) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func TestAssembleZeroExtensionIsTheOpenRelay(t *testing.T) {
	a, err := Assemble(context.Background(), newMemoryStore(), Extension{})
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := extDo(t, a.Handler, "POST", "/v1/workspaces/w1/envelopes", "", `{"x":1}`); code != 200 {
		t.Fatalf("open relay envelope post: %d", code)
	}
	if code, _ := extDo(t, a.Handler, "GET", "/v1/tunnel/info", "", ""); code != 404 {
		t.Fatalf("tunnel must be off by default: %d", code)
	}
}

func TestAssembleExtensionAddsRoutesAndKeepsTheRelay(t *testing.T) {
	t.Setenv("HIVE_RELAY_ACCESS_TOKENS", "secret-token")
	closed := false
	var started *Server
	ext := Extension{Setup: func(ctx context.Context, st Store) (*Addon, error) {
		return &Addon{
			TunnelPolicy:  allowAllPolicy{},
			TunnelBilling: "appstore",
			Routes: map[string]http.Handler{"/v1/extra/": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.WriteString(w, "extra")
			})},
			Started: func(s *Server) { started = s },
			Close:   func() { closed = true },
		}, nil
	}}
	a, err := Assemble(context.Background(), newMemoryStore(), ext)
	if err != nil {
		t.Fatal(err)
	}
	if started != a.Server {
		t.Fatal("Started must get the assembled server")
	}
	// The relay's gate is unchanged: sync routes still need the access token.
	if code, _ := extDo(t, a.Handler, "GET", "/v1/workspaces/w1/envelopes", "", ""); code != 401 {
		t.Fatalf("gated relay must 401 without a token: %d", code)
	}
	if code, _ := extDo(t, a.Handler, "GET", "/v1/workspaces/w1/envelopes", "secret-token", ""); code != 200 {
		t.Fatalf("gated relay with token: %d", code)
	}
	if code, body := extDo(t, a.Handler, "GET", "/v1/extra/x", "", ""); code != 200 || body != "extra" {
		t.Fatalf("extension route: %d %q", code, body)
	}
	if code, body := extDo(t, a.Handler, "GET", "/v1/tunnel/info", "", ""); code != 200 || !strings.Contains(body, `"billing":"appstore"`) {
		t.Fatalf("tunnel info: %d %s", code, body)
	}
	a.Close()
	if !closed {
		t.Fatal("Close hook not run")
	}
}

func TestAssembleFallsBackToTheOpenRelay(t *testing.T) {
	for name, ext := range map[string]Extension{
		"setup error": {Setup: func(context.Context, Store) (*Addon, error) { return nil, errors.New("boom") }},
		"nil addon":   {Setup: func(context.Context, Store) (*Addon, error) { return nil, nil }},
		"overlapping route": {Setup: func(context.Context, Store) (*Addon, error) {
			return &Addon{TunnelPolicy: allowAllPolicy{}, Routes: map[string]http.Handler{"/v1/workspaces/": http.NotFoundHandler()}}, nil
		}},
	} {
		t.Run(name, func(t *testing.T) {
			a, err := Assemble(context.Background(), newMemoryStore(), ext)
			if err == nil {
				t.Fatal("want the setup error reported")
			}
			if code, _ := extDo(t, a.Handler, "POST", "/v1/workspaces/w1/envelopes", "", `{"x":1}`); code != 200 {
				t.Fatalf("fallback must serve the open relay: %d", code)
			}
			if code, _ := extDo(t, a.Handler, "GET", "/v1/tunnel/info", "", ""); code != 404 {
				t.Fatalf("fallback must not carry the extension's tunnel: %d", code)
			}
		})
	}
}

func TestExtensionPrefixValidation(t *testing.T) {
	for _, p := range []string{"/v1/remote/", "/v1/appstore/", "/v1/push-gateway/"} {
		if err := validateExtensionPrefix(p); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
	for _, p := range []string{"/", "/v1/", "/v1/tunnel/", "/v1/tunnel/x/", "/v1/pair/", "/v1/friends/", "/v1/health/", "/v2/x/", "/v1/remote", "/v1/admin/"} {
		if err := validateExtensionPrefix(p); err == nil {
			t.Errorf("%s: want refused", p)
		}
	}
}

// TestTunnelInfoBillingOpenBuild pins what the iOS app relies on to hide its
// paywall: a self-hosted relay with HIVE_RELAY_TUNNEL=open says billing none.
func TestTunnelInfoBillingOpenBuild(t *testing.T) {
	t.Setenv("HIVE_RELAY_TUNNEL", "open")
	a, err := Assemble(context.Background(), newMemoryStore(), Extension{})
	if err != nil {
		t.Fatal(err)
	}
	code, body := extDo(t, a.Handler, "GET", "/v1/tunnel/info", "", "")
	if code != 200 || !strings.Contains(body, `"billing":"none"`) || !strings.Contains(body, `"push":false`) {
		t.Fatalf("open tunnel info: %d %s", code, body)
	}
}

type allowAllPolicy struct{}

func (allowAllPolicy) Register(context.Context, string, ed25519.PublicKey, string) error { return nil }
func (allowAllPolicy) Status(context.Context, string) (HostStatus, error) {
	return HostStatus{Active: true}, nil
}
