package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// postgresStore is the shared SQL backend selected by $DATABASE_URL, so running
// multiple relay instances works with no data migration: every relay reads and
// writes the same tables. It implements the same Store interface as memoryStore,
// so the HTTP handlers are unchanged.
//
// Monotonic server sequences (per workspace, per inbox) come from a single
// counters table updated with INSERT … ON CONFLICT DO UPDATE … RETURNING, which
// takes a row lock — correct under concurrency across instances.
type postgresStore struct {
	pool *pgxpool.Pool
}

func newPostgresStore(ctx context.Context, dsn string) (Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("connect postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	s := &postgresStore{pool: pool}
	if err := s.migrate(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

func (s *postgresStore) Close() error { s.pool.Close(); return nil }

// migrate creates the schema (idempotent — safe to run on every boot and from
// every instance).
func (s *postgresStore) migrate(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, schemaSQL)
	return err
}

const schemaSQL = `
CREATE TABLE IF NOT EXISTS relay_seq (
  scope    TEXT PRIMARY KEY,
  next_seq BIGINT NOT NULL
);
-- Opaque (E2EE) bodies are stored as TEXT, not JSONB, so the relay forwards the
-- exact bytes it received: content-blind, no key reordering / whitespace
-- normalization, identical to the in-memory store.
CREATE TABLE IF NOT EXISTS relay_envelopes (
  workspace TEXT   NOT NULL,
  seq       BIGINT NOT NULL,
  body      TEXT   NOT NULL,
  PRIMARY KEY (workspace, seq)
);
CREATE TABLE IF NOT EXISTS relay_candidates (
  workspace TEXT NOT NULL,
  device_id TEXT NOT NULL,
  blob      TEXT NOT NULL,
  PRIMARY KEY (workspace, device_id)
);
CREATE TABLE IF NOT EXISTS relay_presence (
  workspace TEXT NOT NULL,
  device_id TEXT NOT NULL,
  blob      TEXT NOT NULL,
  PRIMARY KEY (workspace, device_id)
);
CREATE TABLE IF NOT EXISTS relay_keyring (
  id        BIGSERIAL PRIMARY KEY,
  workspace TEXT NOT NULL,
  blob      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS relay_keyring_ws ON relay_keyring (workspace, id);
CREATE TABLE IF NOT EXISTS relay_directory (
  login     TEXT PRIMARY KEY,
  github_id BIGINT NOT NULL,
  name      TEXT
);
CREATE TABLE IF NOT EXISTS relay_directory_devices (
  login     TEXT NOT NULL,
  device_id TEXT NOT NULL,
  ka_pub    TEXT NOT NULL,
  PRIMARY KEY (login, device_id)
);
CREATE TABLE IF NOT EXISTS relay_accounts (
  account_key   TEXT PRIMARY KEY,
  login         TEXT NOT NULL DEFAULT '',
  appear_offline BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE TABLE IF NOT EXISTS relay_account_devices (
  account_key TEXT NOT NULL,
  device_id   TEXT NOT NULL,
  node_id     TEXT,
  label       TEXT,
  last_seen   BIGINT NOT NULL,
  PRIMARY KEY (account_key, device_id)
);
CREATE TABLE IF NOT EXISTS relay_login_index (
  login       TEXT PRIMARY KEY,
  account_key TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS relay_inbox (
  account_key TEXT   NOT NULL,
  seq         BIGINT NOT NULL,
  body        TEXT   NOT NULL,
  PRIMARY KEY (account_key, seq)
);
CREATE TABLE IF NOT EXISTS relay_friend_requests (
  id           TEXT PRIMARY KEY,
  from_account TEXT NOT NULL,
  from_login   TEXT NOT NULL,
  to_account   TEXT NOT NULL,
  to_login     TEXT NOT NULL,
  created_at   BIGINT NOT NULL,
  state        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS relay_friend_requests_to   ON relay_friend_requests (to_account, state);
CREATE INDEX IF NOT EXISTS relay_friend_requests_from ON relay_friend_requests (from_account, state);
CREATE TABLE IF NOT EXISTS relay_friend_edges (
  a TEXT NOT NULL,
  b TEXT NOT NULL,
  PRIMARY KEY (a, b)
);
`

// pgxQuerier is satisfied by both *pgxpool.Pool and pgx.Tx, so read/helper
// methods work either standalone or inside a transaction.
type pgxQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// ── Workspace sync ───────────────────────────────────────────────────────────

func (s *postgresStore) AppendEnvelope(ctx context.Context, workspace string, body json.RawMessage) (uint64, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	seq, err := s.nextSeqTx(ctx, tx, "ws:"+workspace)
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO relay_envelopes (workspace, seq, body) VALUES ($1, $2, $3)`,
		workspace, seq, []byte(body)); err != nil {
		return 0, err
	}
	return seq, tx.Commit(ctx)
}

func (s *postgresStore) EnvelopesAfter(ctx context.Context, workspace string, after uint64) ([]Envelope, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT seq, body FROM relay_envelopes WHERE workspace = $1 AND seq > $2 ORDER BY seq`,
		workspace, after)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Envelope{}
	for rows.Next() {
		var e Envelope
		var body []byte
		if err := rows.Scan(&e.Seq, &body); err != nil {
			return nil, err
		}
		e.Body = json.RawMessage(body)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *postgresStore) PutCandidate(ctx context.Context, workspace, deviceID string, candidate json.RawMessage) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO relay_candidates (workspace, device_id, blob) VALUES ($1, $2, $3)
		 ON CONFLICT (workspace, device_id) DO UPDATE SET blob = EXCLUDED.blob`,
		workspace, deviceID, []byte(candidate))
	return err
}

func (s *postgresStore) Candidates(ctx context.Context, workspace string) (map[string]json.RawMessage, error) {
	return s.deviceBlobs(ctx, "relay_candidates", workspace)
}

func (s *postgresStore) PutPresence(ctx context.Context, workspace, deviceID string, presence json.RawMessage) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO relay_presence (workspace, device_id, blob) VALUES ($1, $2, $3)
		 ON CONFLICT (workspace, device_id) DO UPDATE SET blob = EXCLUDED.blob`,
		workspace, deviceID, []byte(presence))
	return err
}

func (s *postgresStore) PresenceBlobs(ctx context.Context, workspace string) (map[string]json.RawMessage, error) {
	return s.deviceBlobs(ctx, "relay_presence", workspace)
}

func (s *postgresStore) deviceBlobs(ctx context.Context, table, workspace string) (map[string]json.RawMessage, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT device_id, blob FROM `+table+` WHERE workspace = $1`, workspace)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]json.RawMessage{}
	for rows.Next() {
		var id string
		var blob []byte
		if err := rows.Scan(&id, &blob); err != nil {
			return nil, err
		}
		out[id] = json.RawMessage(blob)
	}
	return out, rows.Err()
}

func (s *postgresStore) AppendKeyRotation(ctx context.Context, workspace string, blob json.RawMessage) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO relay_keyring (workspace, blob) VALUES ($1, $2)`, workspace, []byte(blob))
	return err
}

func (s *postgresStore) KeyRotations(ctx context.Context, workspace string) ([]json.RawMessage, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT blob FROM relay_keyring WHERE workspace = $1 ORDER BY id`, workspace)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []json.RawMessage{}
	for rows.Next() {
		var blob []byte
		if err := rows.Scan(&blob); err != nil {
			return nil, err
		}
		out = append(out, json.RawMessage(blob))
	}
	return out, rows.Err()
}

// ── Identity directory ─────────────────────────────────────────────────────────

func (s *postgresStore) UpsertDirDevice(ctx context.Context, githubID uint64, login string, name *string, deviceID, kaPub string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	key := lower(login)
	if _, err := tx.Exec(ctx,
		`INSERT INTO relay_directory (login, github_id, name) VALUES ($1, $2, $3)
		 ON CONFLICT (login) DO UPDATE SET github_id = EXCLUDED.github_id, name = EXCLUDED.name`,
		key, int64(githubID), name); err != nil {
		return err
	}
	if kaPub != "" && deviceID != "" {
		if _, err := tx.Exec(ctx,
			`INSERT INTO relay_directory_devices (login, device_id, ka_pub) VALUES ($1, $2, $3)
			 ON CONFLICT (login, device_id) DO UPDATE SET ka_pub = EXCLUDED.ka_pub`,
			key, deviceID, kaPub); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *postgresStore) DirAccountByHandle(ctx context.Context, handle string) (*DirAccount, error) {
	key := normHandle(handle)
	var acct DirAccount
	var ghID int64
	err := s.pool.QueryRow(ctx,
		`SELECT github_id, login, name FROM relay_directory WHERE login = $1`, key).
		Scan(&ghID, &acct.Login, &acct.Name)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	acct.GitHubID = uint64(ghID)
	acct.Devices = map[string]string{}
	rows, err := s.pool.Query(ctx,
		`SELECT device_id, ka_pub FROM relay_directory_devices WHERE login = $1`, key)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, pk string
		if err := rows.Scan(&id, &pk); err != nil {
			return nil, err
		}
		acct.Devices[id] = pk
	}
	return &acct, rows.Err()
}

// ── Account registry + inbox ──────────────────────────────────────────────────

func (s *postgresStore) RegisterAccountDevice(ctx context.Context, githubID uint64, login, deviceID string, nodeID, label *string, now int64) (string, error) {
	key := accountKey(githubID)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx,
		`INSERT INTO relay_login_index (login, account_key) VALUES ($1, $2)
		 ON CONFLICT (login) DO UPDATE SET account_key = EXCLUDED.account_key`,
		lower(login), key); err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO relay_accounts (account_key, login) VALUES ($1, $2)
		 ON CONFLICT (account_key) DO UPDATE SET login = EXCLUDED.login`,
		key, login); err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO relay_account_devices (account_key, device_id, node_id, label, last_seen)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (account_key, device_id)
		 DO UPDATE SET node_id = EXCLUDED.node_id, label = EXCLUDED.label, last_seen = EXCLUDED.last_seen`,
		key, deviceID, nodeID, label, now); err != nil {
		return "", err
	}
	return key, tx.Commit(ctx)
}

func (s *postgresStore) HeartbeatDevice(ctx context.Context, githubID uint64, deviceID string, now int64) (bool, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE relay_account_devices SET last_seen = $3 WHERE account_key = $1 AND device_id = $2`,
		accountKey(githubID), deviceID, now)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func (s *postgresStore) PushAccountEvent(ctx context.Context, key string, body json.RawMessage) (uint64, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	// Ensure the account row exists so a push to a not-yet-registered account
	// still works (mirrors the in-memory entry-or-default behavior).
	if _, err := tx.Exec(ctx,
		`INSERT INTO relay_accounts (account_key) VALUES ($1) ON CONFLICT DO NOTHING`, key); err != nil {
		return 0, err
	}
	seq, err := s.nextSeqTx(ctx, tx, "inbox:"+key)
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO relay_inbox (account_key, seq, body) VALUES ($1, $2, $3)`,
		key, seq, []byte(body)); err != nil {
		return 0, err
	}
	return seq, tx.Commit(ctx)
}

func (s *postgresStore) AccountInboxAfter(ctx context.Context, key string, after uint64) ([]InboxRow, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT seq, body FROM relay_inbox WHERE account_key = $1 AND seq > $2 ORDER BY seq`, key, after)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []InboxRow{}
	for rows.Next() {
		var r InboxRow
		var body []byte
		if err := rows.Scan(&r.Seq, &body); err != nil {
			return nil, err
		}
		r.Body = json.RawMessage(body)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *postgresStore) AccountDevices(ctx context.Context, key string) ([]DeviceRow, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT device_id, node_id, label, last_seen FROM relay_account_devices
		 WHERE account_key = $1 ORDER BY device_id`, key)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DeviceRow{}
	for rows.Next() {
		var d DeviceRow
		if err := rows.Scan(&d.DeviceID, &d.NodeID, &d.Label, &d.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *postgresStore) AccountKeyForLogin(ctx context.Context, login string) (string, bool, error) {
	var key string
	err := s.pool.QueryRow(ctx,
		`SELECT account_key FROM relay_login_index WHERE login = $1`, normHandle(login)).Scan(&key)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return key, true, nil
}

func (s *postgresStore) SetVisibility(ctx context.Context, githubID uint64, appearOffline bool) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE relay_accounts SET appear_offline = $2 WHERE account_key = $1`,
		accountKey(githubID), appearOffline)
	return err
}

func (s *postgresStore) PresenceOf(ctx context.Context, key string, now int64) (string, error) {
	var appearOffline bool
	err := s.pool.QueryRow(ctx, `SELECT appear_offline FROM relay_accounts WHERE account_key = $1`, key).Scan(&appearOffline)
	if errors.Is(err, pgx.ErrNoRows) {
		return "offline", nil
	}
	if err != nil {
		return "", err
	}
	if appearOffline {
		return "offline", nil
	}
	var latest *int64
	if err := s.pool.QueryRow(ctx,
		`SELECT MAX(last_seen) FROM relay_account_devices WHERE account_key = $1`, key).Scan(&latest); err != nil {
		return "", err
	}
	if latest == nil {
		return "offline", nil
	}
	return presenceStr(*latest, now), nil
}

// ── Friend graph ───────────────────────────────────────────────────────────────

func (s *postgresStore) AreFriends(ctx context.Context, a, b string) (bool, error) {
	pair := canonicalPair(a, b)
	var exists bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM relay_friend_edges WHERE a = $1 AND b = $2)`, pair[0], pair[1]).Scan(&exists)
	return exists, err
}

func (s *postgresStore) friendCountTx(ctx context.Context, q pgxQuerier, account string) (int, error) {
	var n int
	err := q.QueryRow(ctx,
		`SELECT COUNT(*) FROM relay_friend_edges WHERE a = $1 OR b = $1`, account).Scan(&n)
	return n, err
}

func (s *postgresStore) FriendCount(ctx context.Context, account string) (int, error) {
	return s.friendCountTx(ctx, s.pool, account)
}

func (s *postgresStore) expirePending(ctx context.Context, q pgxQuerier, now int64) error {
	_, err := q.Exec(ctx,
		`UPDATE relay_friend_requests SET state = 'cancelled'
		 WHERE state = 'pending' AND $1 - created_at > $2`, now, int64(requestTTLSecs))
	return err
}

func (s *postgresStore) CreateFriendRequest(ctx context.Context, fromAccount, fromLogin, toAccount, toLogin string, now int64, friendCap *int) (FriendRequest, error) {
	if fromAccount == toAccount {
		return FriendRequest{}, ErrSelfRequest
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return FriendRequest{}, err
	}
	defer tx.Rollback(ctx)

	if friends, err := s.areFriendsTx(ctx, tx, fromAccount, toAccount); err != nil {
		return FriendRequest{}, err
	} else if friends {
		return FriendRequest{}, ErrAlreadyFriends
	}
	if friendCap != nil {
		if n, err := s.friendCountTx(ctx, tx, fromAccount); err != nil {
			return FriendRequest{}, err
		} else if n >= *friendCap {
			return FriendRequest{}, ErrCapReached
		}
	}
	if err := s.expirePending(ctx, tx, now); err != nil {
		return FriendRequest{}, err
	}

	// Idempotent on a pending duplicate.
	var existing FriendRequest
	err = tx.QueryRow(ctx,
		`SELECT id, from_account, from_login, to_account, to_login, created_at, state
		 FROM relay_friend_requests
		 WHERE state = 'pending' AND from_account = $1 AND to_account = $2 LIMIT 1`,
		fromAccount, toAccount).Scan(&existing.ID, &existing.FromAccount, &existing.FromLogin,
		&existing.ToAccount, &existing.ToLogin, &existing.CreatedAt, &existing.State)
	if err == nil {
		return existing, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return FriendRequest{}, err
	}

	var pendingOut int
	if err := tx.QueryRow(ctx,
		`SELECT COUNT(*) FROM relay_friend_requests WHERE state = 'pending' AND from_account = $1`,
		fromAccount).Scan(&pendingOut); err != nil {
		return FriendRequest{}, err
	}
	if pendingOut >= maxPendingOutbound {
		return FriendRequest{}, ErrTooManyPending
	}

	req := FriendRequest{
		ID: newRequestID(), FromAccount: fromAccount, FromLogin: fromLogin,
		ToAccount: toAccount, ToLogin: toLogin, CreatedAt: now, State: StatePending,
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO relay_friend_requests (id, from_account, from_login, to_account, to_login, created_at, state)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		req.ID, req.FromAccount, req.FromLogin, req.ToAccount, req.ToLogin, req.CreatedAt, string(req.State)); err != nil {
		return FriendRequest{}, err
	}
	return req, tx.Commit(ctx)
}

func (s *postgresStore) areFriendsTx(ctx context.Context, q pgxQuerier, a, b string) (bool, error) {
	pair := canonicalPair(a, b)
	var exists bool
	err := q.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM relay_friend_edges WHERE a = $1 AND b = $2)`, pair[0], pair[1]).Scan(&exists)
	return exists, err
}

func (s *postgresStore) AcceptFriendRequest(ctx context.Context, requestID, acceptor string, friendCap *int) (FriendRequest, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return FriendRequest{}, err
	}
	defer tx.Rollback(ctx)

	var req FriendRequest
	err = tx.QueryRow(ctx,
		`SELECT id, from_account, from_login, to_account, to_login, created_at, state
		 FROM relay_friend_requests WHERE id = $1 FOR UPDATE`, requestID).
		Scan(&req.ID, &req.FromAccount, &req.FromLogin, &req.ToAccount, &req.ToLogin, &req.CreatedAt, &req.State)
	if errors.Is(err, pgx.ErrNoRows) {
		return FriendRequest{}, ErrNotFound
	}
	if err != nil {
		return FriendRequest{}, err
	}
	if req.ToAccount != acceptor {
		return FriendRequest{}, ErrNotYours
	}
	if req.State != StatePending {
		return FriendRequest{}, ErrNotPending
	}
	if friendCap != nil {
		for _, acc := range []string{req.FromAccount, req.ToAccount} {
			if n, err := s.friendCountTx(ctx, tx, acc); err != nil {
				return FriendRequest{}, err
			} else if n >= *friendCap {
				return FriendRequest{}, ErrCapReached
			}
		}
	}
	pair := canonicalPair(req.FromAccount, req.ToAccount)
	if _, err := tx.Exec(ctx,
		`INSERT INTO relay_friend_edges (a, b) VALUES ($1, $2) ON CONFLICT DO NOTHING`, pair[0], pair[1]); err != nil {
		return FriendRequest{}, err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE relay_friend_requests SET state = 'accepted' WHERE id = $1`, requestID); err != nil {
		return FriendRequest{}, err
	}
	req.State = StateAccepted
	return req, tx.Commit(ctx)
}

func (s *postgresStore) CloseFriendRequest(ctx context.Context, requestID, actor string) (FriendRequest, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return FriendRequest{}, err
	}
	defer tx.Rollback(ctx)

	var req FriendRequest
	err = tx.QueryRow(ctx,
		`SELECT id, from_account, from_login, to_account, to_login, created_at, state
		 FROM relay_friend_requests WHERE id = $1 FOR UPDATE`, requestID).
		Scan(&req.ID, &req.FromAccount, &req.FromLogin, &req.ToAccount, &req.ToLogin, &req.CreatedAt, &req.State)
	if errors.Is(err, pgx.ErrNoRows) {
		return FriendRequest{}, ErrNotFound
	}
	if err != nil {
		return FriendRequest{}, err
	}
	if req.State != StatePending {
		return FriendRequest{}, ErrNotPending
	}
	switch actor {
	case req.ToAccount:
		req.State = StateRejected
	case req.FromAccount:
		req.State = StateCancelled
	default:
		return FriendRequest{}, ErrNotYours
	}
	if _, err := tx.Exec(ctx,
		`UPDATE relay_friend_requests SET state = $2 WHERE id = $1`, requestID, string(req.State)); err != nil {
		return FriendRequest{}, err
	}
	return req, tx.Commit(ctx)
}

func (s *postgresStore) RemoveFriend(ctx context.Context, account, other string) (bool, error) {
	pair := canonicalPair(account, other)
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM relay_friend_edges WHERE a = $1 AND b = $2`, pair[0], pair[1])
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func (s *postgresStore) ListFriends(ctx context.Context, account string) ([]Friend, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT CASE WHEN e.a = $1 THEN e.b ELSE e.a END AS other,
		        COALESCE(acc.login, '') AS login
		 FROM relay_friend_edges e
		 LEFT JOIN relay_accounts acc
		   ON acc.account_key = CASE WHEN e.a = $1 THEN e.b ELSE e.a END
		 WHERE e.a = $1 OR e.b = $1
		 ORDER BY other`, account)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Friend{}
	for rows.Next() {
		var f Friend
		if err := rows.Scan(&f.AccountKey, &f.Login); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *postgresStore) IncomingRequests(ctx context.Context, account string, now int64) ([]FriendRequest, error) {
	if err := s.expirePending(ctx, s.pool, now); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx,
		`SELECT id, from_account, from_login, to_account, to_login, created_at, state
		 FROM relay_friend_requests WHERE state = 'pending' AND to_account = $1 ORDER BY created_at`, account)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []FriendRequest{}
	for rows.Next() {
		var r FriendRequest
		if err := rows.Scan(&r.ID, &r.FromAccount, &r.FromLogin, &r.ToAccount, &r.ToLogin, &r.CreatedAt, &r.State); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *postgresStore) FriendDevices(ctx context.Context, caller, friend string) ([]DeviceRow, bool, error) {
	if friends, err := s.AreFriends(ctx, caller, friend); err != nil {
		return nil, false, err
	} else if !friends {
		return nil, false, nil
	}
	devs, err := s.AccountDevices(ctx, friend)
	return devs, true, err
}

func (s *postgresStore) FriendPresence(ctx context.Context, account string, now int64) ([]FriendPresence, error) {
	friends, err := s.ListFriends(ctx, account)
	if err != nil {
		return nil, err
	}
	out := make([]FriendPresence, 0, len(friends))
	for _, f := range friends {
		pres, err := s.PresenceOf(ctx, f.AccountKey, now)
		if err != nil {
			return nil, err
		}
		out = append(out, FriendPresence{AccountKey: f.AccountKey, Login: f.Login, Presence: pres})
	}
	return out, nil
}

// ── Durability ─────────────────────────────────────────────────────────────────

func (s *postgresStore) Flush(context.Context) error { return nil } // writes are already durable
func (s *postgresStore) PersistenceEnabled() bool    { return false }

// nextSeqTx is nextSeq bound to a transaction.
func (s *postgresStore) nextSeqTx(ctx context.Context, tx pgx.Tx, scope string) (uint64, error) {
	var seq uint64
	err := tx.QueryRow(ctx,
		`INSERT INTO relay_seq (scope, next_seq) VALUES ($1, 1)
		 ON CONFLICT (scope) DO UPDATE SET next_seq = relay_seq.next_seq + 1
		 RETURNING next_seq`, scope).Scan(&seq)
	return seq, err
}
