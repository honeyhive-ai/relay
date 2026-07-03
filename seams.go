package relay

import (
	"context"
	"net/http"
)

// Extension seams.
//
// This package is a complete, self-hostable relay on its own (see cmd/hive-relay).
// The interfaces below are extension points: a downstream build can implement
// them and pass them to New(Options{...}) to add custom authorization,
// accounting, or storage without forking. The default (nil) implementations
// yield a fully-working relay; nothing here gates core function or security.
//
// The four seams:
//
//   - Store               — durable backend (in-memory/snapshot or Postgres here).
//                            See store.go.
//   - EntitlementVerifier — who may use the relay (open / token allowlist /
//                            signed tokens from env). Swap in a custom policy.
//   - WriteGuard          — optional pre-write authorization hook. Default nil =
//                            content-blind forwarding.
//   - Hooks               — optional lifecycle observers (e.g. audit / accounting).
//                            Default nil = no-op.

// EntitlementVerifier decides whether a presented bearer token is admitted at
// nowUnix. The returned claims (non-nil for signed tokens) let downstream
// enforcement read per-plan limits + RBAC capabilities.
type EntitlementVerifier interface {
	Allow(token string, nowUnix int64) (*TokenClaims, bool)
}

// WriteGuard runs before any workspace write (envelopes / keyring / candidates /
// presence). Return a non-nil error to reject the write (mapped to 403). Default
// nil = pure content-blind forwarding. A downstream build can set one to enforce
// workspace membership / roles from the verified claims.
type WriteGuard interface {
	CheckWrite(ctx context.Context, workspace string, claims *TokenClaims, r *http.Request) error
}

// Hooks observe successful operations for audit + usage metering. All methods
// must tolerate a nil claims (open / token-allowlist policies carry none). The
// open relay leaves this nil (no-op).
type Hooks interface {
	// WorkspaceWritten fires after a durable workspace write (envelope or key
	// rotation), carrying the assigned server sequence — the natural metering
	// + audit point.
	WorkspaceWritten(ctx context.Context, workspace string, seq uint64, claims *TokenClaims)
}
