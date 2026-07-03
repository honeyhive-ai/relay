// Package main — the Hive relay: a content-blind rendezvous + envelope-forwarding
// server. Clients post opaque (end-to-end encrypted) event envelopes keyed by
// workspace and fetch everything after a cursor; the relay also brokers short
// pairing codes, an identity directory, a poll-based account inbox, the friend
// graph, and presence. It never sees plaintext.
//
// This is a Go port of the reference Rust relay (crates/hive-relay), preserving
// the JSON /v1 wire contract and the hrt1 entitlement-token format byte-for-byte
// so existing clients and issued tokens keep working.
package relay

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// ── Durable domain types ─────────────────────────────────────────────────────
//
// Opaque JSON bodies are carried as json.RawMessage so the relay forwards the
// exact ciphertext bytes it received (it is content-blind).

// Envelope is one stored workspace event: a monotonic server sequence + the
// opaque body verbatim.
type Envelope struct {
	Seq  uint64          `json:"seq"`
	Body json.RawMessage `json:"body"`
}

// InboxRow is one account-channel event (same shape as Envelope on the wire).
type InboxRow struct {
	Seq  uint64          `json:"seq"`
	Body json.RawMessage `json:"body"`
}

// DeviceRow is a registered device as returned to callers.
type DeviceRow struct {
	DeviceID string  `json:"deviceId"`
	NodeID   *string `json:"nodeId"`
	Label    *string `json:"label"`
	LastSeen int64   `json:"lastSeen"`
}

// DirAccount is a directory entry: a verified GitHub identity + each device's
// X25519 key-agreement public key (opaque to the relay), so a teammate can be
// invited by @handle and the workspace key sealed to all their devices.
type DirAccount struct {
	GitHubID uint64
	Login    string
	Name     *string
	Devices  map[string]string // device id → ka public key
}

// Friend is an accepted friend (account key + login).
type Friend struct {
	AccountKey string
	Login      string
}

// FriendPresence is a friend plus their presence state.
type FriendPresence struct {
	AccountKey string
	Login      string
	Presence   string
}

// RequestState is the lifecycle of a friend request.
type RequestState string

const (
	StatePending   RequestState = "pending"
	StateAccepted  RequestState = "accepted"
	StateRejected  RequestState = "rejected"
	StateCancelled RequestState = "cancelled"
)

// FriendRequest is a pending/closed friend request. FromAccount/ToAccount are
// account keys (github:<id>); the relay stamps From from the verified GitHub
// token, so a request can't be forged to look like another user.
type FriendRequest struct {
	ID          string
	FromAccount string
	FromLogin   string
	ToAccount   string
	ToLogin     string
	CreatedAt   int64
	State       RequestState
}

// requestEvent / resolvedEvent build the inbox event bodies (so handlers and
// tests agree on shape), matching the Rust relay.
func (r FriendRequest) requestEvent() json.RawMessage {
	return mustJSON(map[string]any{
		"kind":        "friendRequest",
		"requestId":   r.ID,
		"fromAccount": r.FromAccount,
		"fromLogin":   r.FromLogin,
		"createdAt":   r.CreatedAt,
	})
}

func (r FriendRequest) resolvedEvent() json.RawMessage {
	return mustJSON(map[string]any{
		"kind":        "friendResolved",
		"requestId":   r.ID,
		"state":       string(r.State),
		"fromAccount": r.FromAccount,
		"toAccount":   r.ToAccount,
	})
}

// ── Friend-operation errors (mapped to HTTP status in the handlers) ──────────

var (
	ErrSelfRequest    = errors.New("cannot friend yourself")
	ErrAlreadyFriends = errors.New("already friends")
	ErrCapReached     = errors.New("friend cap reached")
	ErrNotFound       = errors.New("request not found")
	ErrNotYours       = errors.New("not your request")
	ErrNotPending     = errors.New("request not pending")
	ErrTooManyPending = errors.New("too many pending outbound requests")
)

// ── Tunables (mirror the Rust relay) ─────────────────────────────────────────

const (
	onlineWindowSecs   = 70
	awayWindowSecs     = 300
	requestTTLSecs     = 14 * 24 * 60 * 60
	maxPendingOutbound = 50
)

// presenceStr maps a last-seen timestamp to an account presence state.
func presenceStr(lastSeen, now int64) string {
	age := now - lastSeen
	if age < 0 {
		age = 0
	}
	switch {
	case lastSeen == 0 || age > awayWindowSecs:
		return "offline"
	case age <= onlineWindowSecs:
		return "online"
	default:
		return "away"
	}
}

// accountKey is the canonical key derived from a GitHub numeric id. Every device
// of the account computes the same value, so the inbox/registry are shared.
func accountKey(githubID uint64) string {
	return fmt.Sprintf("github:%d", githubID)
}

// canonicalPair returns the (sorted) account-key pair, so a friendship edge is
// stored once regardless of who sent the request.
func canonicalPair(a, b string) [2]string {
	if a <= b {
		return [2]string{a, b}
	}
	return [2]string{b, a}
}

// newRequestID is an opaque, collision-resistant friend-request id.
func newRequestID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return "fr" + hex.EncodeToString(b[:])
}

// randRead fills b with cryptographically-random bytes.
func randRead(b []byte) { _, _ = rand.Read(b) }

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// ── Store: the durable-state seam ────────────────────────────────────────────
//
// Every piece of state that must survive restarts and (for HA) be shared across
// instances goes through this interface, so the backend is a deployment choice
// with no future data migration:
//
//   - memoryStore — in-process maps + an optional JSON snapshot (self-host
//     default, zero deps, what tests run against).
//   - postgresStore (Phase 2) — a shared SQL store selected via DATABASE_URL,
//     so running multiple relay instances works with no data migration.
//
// Ephemeral, instance-local state (short pairing codes) stays out of here — see
// the Server. friendCap is threaded through the friend-graph methods so the
// store stays free of policy.
type Store interface {
	// Workspace sync (opaque envelopes + rendezvous + key rotations).
	AppendEnvelope(ctx context.Context, workspace string, body json.RawMessage) (uint64, error)
	EnvelopesAfter(ctx context.Context, workspace string, after uint64) ([]Envelope, error)
	PutCandidate(ctx context.Context, workspace, deviceID string, candidate json.RawMessage) error
	Candidates(ctx context.Context, workspace string) (map[string]json.RawMessage, error)
	PutPresence(ctx context.Context, workspace, deviceID string, presence json.RawMessage) error
	PresenceBlobs(ctx context.Context, workspace string) (map[string]json.RawMessage, error)
	AppendKeyRotation(ctx context.Context, workspace string, blob json.RawMessage) error
	KeyRotations(ctx context.Context, workspace string) ([]json.RawMessage, error)

	// Identity directory (invite-by-handle, seal-to-all-devices).
	UpsertDirDevice(ctx context.Context, githubID uint64, login string, name *string, deviceID, kaPub string) error
	DirAccountByHandle(ctx context.Context, handle string) (*DirAccount, error)

	// Account registry + per-account inbox (the social channel).
	RegisterAccountDevice(ctx context.Context, githubID uint64, login, deviceID string, nodeID, label *string, now int64) (string, error)
	HeartbeatDevice(ctx context.Context, githubID uint64, deviceID string, now int64) (bool, error)
	PushAccountEvent(ctx context.Context, accountKey string, body json.RawMessage) (uint64, error)
	AccountInboxAfter(ctx context.Context, accountKey string, after uint64) ([]InboxRow, error)
	AccountDevices(ctx context.Context, accountKey string) ([]DeviceRow, error)
	AccountKeyForLogin(ctx context.Context, login string) (string, bool, error)
	SetVisibility(ctx context.Context, githubID uint64, appearOffline bool) error
	PresenceOf(ctx context.Context, accountKey string, now int64) (string, error)

	// Friend graph.
	AreFriends(ctx context.Context, a, b string) (bool, error)
	CreateFriendRequest(ctx context.Context, fromAccount, fromLogin, toAccount, toLogin string, now int64, friendCap *int) (FriendRequest, error)
	AcceptFriendRequest(ctx context.Context, requestID, acceptor string, friendCap *int) (FriendRequest, error)
	CloseFriendRequest(ctx context.Context, requestID, actor string) (FriendRequest, error)
	RemoveFriend(ctx context.Context, account, other string) (bool, error)
	ListFriends(ctx context.Context, account string) ([]Friend, error)
	IncomingRequests(ctx context.Context, account string, now int64) ([]FriendRequest, error)
	// FriendDevices returns a friend's devices; the bool is false (→ 403) when
	// caller and friend are not accepted friends.
	FriendDevices(ctx context.Context, caller, friend string) ([]DeviceRow, bool, error)
	FriendCount(ctx context.Context, account string) (int, error)
	FriendPresence(ctx context.Context, account string, now int64) ([]FriendPresence, error)

	// Durability (snapshot-backed stores only; no-op otherwise).
	Flush(ctx context.Context) error
	PersistenceEnabled() bool
	Close() error
}
