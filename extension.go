package relay

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// Extension lets a downstream binary run the standard relay with extra pieces
// (MainWith). It can't change what the open relay does: storage, env, the
// entitlement gate and every open route stay exactly as in cmd/hive-relay. It
// can only
//
//   - set the tunnel seams (TunnelPolicy, PushSender, billing label), which
//     otherwise come from HIVE_RELAY_TUNNEL;
//   - serve extra routes under path prefixes the relay doesn't use;
//   - add subcommands (the built-in ones win).
//
// A hosted build that shares an app with the open relay must stay a strict
// superset of it; this type is how the relay guarantees that.
type Extension struct {
	// Commands are extra subcommands: name → run(args after the name).
	Commands map[string]func(args []string) error
	// Setup runs once, with the Store built from the environment exactly as the
	// open relay builds it. ctx is cancelled at shutdown. A nil Setup is the
	// open relay. A Setup error (or an invalid Addon) is logged and the relay
	// serves as the open binary would: an extension never takes the relay down.
	Setup func(ctx context.Context, store Store) (*Addon, error)
}

// Addon is what Extension.Setup contributes.
type Addon struct {
	// Tunnel seams (Options). nil TunnelPolicy = the env policy.
	TunnelPolicy  TunnelPolicy
	PushSender    PushSender
	TunnelBilling string
	// Routes are served beside the relay, keyed by path prefix (it must start
	// with "/v1/" and end with "/"). A prefix that overlaps a relay route is
	// refused. These requests don't pass the relay's entitlement gate.
	Routes map[string]http.Handler
	// Started runs once the Server exists, before the listener opens (for
	// example to wire Server.RefreshTunnelStatus).
	Started func(*Server)
	// Close runs at shutdown, after the listener stops and before the final
	// store flush.
	Close func()
}

// relayPrefixes are the path prefixes the relay serves (Server.Handler). An
// extension route may not overlap any of them.
var relayPrefixes = []string{
	"/v1/health", "/v1/workspaces/", "/v1/pair", "/v1/directory/", "/v1/account/",
	"/v1/friends", "/v1/admin/", "/v1/tunnel/", "/metrics",
}

func validateExtensionPrefix(p string) error {
	if !strings.HasPrefix(p, "/v1/") || !strings.HasSuffix(p, "/") || p == "/v1/" {
		return fmt.Errorf("extension route %q: must be a /v1/<name>/ prefix", p)
	}
	for _, r := range relayPrefixes {
		if strings.HasPrefix(p, r) || strings.HasPrefix(r, p) {
			return fmt.Errorf("extension route %q overlaps the relay's %q", p, r)
		}
	}
	return nil
}

// Assembled is a relay built by Assemble.
type Assembled struct {
	Server  *Server
	Handler http.Handler
	close   func()
}

// Close runs the extension's Close hook (if any).
func (a *Assembled) Close() {
	if a.close != nil {
		a.close()
	}
}

// openOptions are the Options the open binary passes to New.
func openOptions(store Store) Options {
	return Options{Store: store, FriendCap: friendCapFromEnv()}
}

// Assemble builds the relay exactly as MainWith serves it, without a listener:
// the open relay (New(openOptions)) plus the extension's tunnel seams and
// routes. With a zero Extension it is the open binary's handler. On a Setup
// error or an invalid Addon it returns the open relay together with the error.
// Tests use it to compare a downstream build against the open relay.
func Assemble(ctx context.Context, store Store, ext Extension) (*Assembled, error) {
	open := func() *Assembled {
		srv := New(openOptions(store))
		return &Assembled{Server: srv, Handler: srv.Handler()}
	}
	if ext.Setup == nil {
		return open(), nil
	}
	add, err := ext.Setup(ctx, store)
	if err == nil && add == nil {
		err = fmt.Errorf("extension setup returned no addon")
	}
	if err == nil {
		for p := range add.Routes {
			if err = validateExtensionPrefix(p); err != nil {
				break
			}
		}
	}
	if err != nil {
		if add != nil && add.Close != nil {
			add.Close()
		}
		return open(), err
	}

	o := openOptions(store)
	o.TunnelPolicy, o.PushSender, o.TunnelBilling = add.TunnelPolicy, add.PushSender, add.TunnelBilling
	srv := New(o)
	if add.Started != nil {
		add.Started(srv)
	}
	relayH := srv.Handler()
	var h http.Handler = relayH
	if len(add.Routes) > 0 {
		routes := make(map[string]http.Handler, len(add.Routes))
		for p, rh := range add.Routes {
			routes[p] = rh
		}
		// A plain prefix dispatch, not a ServeMux: everything else reaches the
		// relay's own handler untouched (no extra path cleaning or redirects).
		h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for p, rh := range routes {
				if strings.HasPrefix(r.URL.Path, p) {
					rh.ServeHTTP(w, r)
					return
				}
			}
			relayH.ServeHTTP(w, r)
		})
	}
	return &Assembled{Server: srv, Handler: h, close: add.Close}, nil
}
