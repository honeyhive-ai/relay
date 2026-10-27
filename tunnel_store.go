package relay

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// Durable relay-only tunnel state (spec §15.1): registered hosts, revoked
// phones and APNs push tokens. Both built-in backends implement TunnelStore
// (memory/snapshot and Postgres). It's an optional interface so a downstream
// Store that predates the tunnel keeps compiling: the relay then falls back to
// an in-process (non-durable) tunnel store and logs that.

// TunnelHostRecord is one registered host.
type TunnelHostRecord struct {
	HostID    string `json:"hostId"`
	Pub       []byte `json:"pub"` // Ed25519 signing key, 32 bytes
	CreatedAt int64  `json:"createdAt"`
	LastSeen  int64  `json:"lastSeen"`
	// Active is the last status the policy reported (false = pending). Only
	// used to GC pending hosts that haven't been seen for 30 days.
	Active bool `json:"active"`
}

// TunnelStore is the tunnel's durable state.
type TunnelStore interface {
	// TunnelHost returns the host, or nil when it isn't registered.
	TunnelHost(ctx context.Context, hostID string) (*TunnelHostRecord, error)
	// UpsertTunnelHost inserts the host, or updates LastSeen + Active (never
	// Pub or CreatedAt) when it exists.
	UpsertTunnelHost(ctx context.Context, rec TunnelHostRecord) error
	// DeleteTunnelHost forgets the host plus its revocations and push tokens.
	DeleteTunnelHost(ctx context.Context, hostID string) error
	// RevokeTunnelPhone records (host, pid) as revoked until exp (keeping the
	// later exp if already revoked) and deletes the phone's push token.
	RevokeTunnelPhone(ctx context.Context, hostID, pid string, exp int64) error
	// TunnelPhoneRevoked reports whether (host, pid) is revoked at now.
	TunnelPhoneRevoked(ctx context.Context, hostID, pid string, now int64) (bool, error)
	// SetTunnelPushToken stores the phone's push token; nil clears it.
	SetTunnelPushToken(ctx context.Context, hostID, pid string, tok *PushToken, now int64) error
	// TunnelPushToken returns the phone's push token, or nil.
	TunnelPushToken(ctx context.Context, hostID, pid string) (*PushToken, error)
	// PruneTunnel drops expired revocations and pending hosts not seen since
	// now-pendingMaxAge (with their state). Returns rows removed.
	PruneTunnel(ctx context.Context, now int64, pendingMaxAge time.Duration) (int64, error)
}

type tunnelPair struct{ Host, PID string }

// memTunnel is the in-process TunnelStore. memoryStore embeds it (so its state
// rides the JSON snapshot); the server also uses a standalone one when the
// configured Store doesn't implement TunnelStore.
type memTunnel struct {
	tmu     sync.RWMutex
	tHosts  map[string]*TunnelHostRecord
	tRevoke map[tunnelPair]int64
	tPush   map[tunnelPair]tunnelPushRow
}

type tunnelPushRow struct {
	Tok       PushToken
	UpdatedAt int64
}

func newMemTunnel() *memTunnel {
	return &memTunnel{
		tHosts:  map[string]*TunnelHostRecord{},
		tRevoke: map[tunnelPair]int64{},
		tPush:   map[tunnelPair]tunnelPushRow{},
	}
}

func (m *memTunnel) TunnelHost(_ context.Context, hostID string) (*TunnelHostRecord, error) {
	m.tmu.RLock()
	defer m.tmu.RUnlock()
	if h := m.tHosts[hostID]; h != nil {
		c := *h
		c.Pub = append([]byte(nil), h.Pub...)
		return &c, nil
	}
	return nil, nil
}

func (m *memTunnel) UpsertTunnelHost(_ context.Context, rec TunnelHostRecord) error {
	m.tmu.Lock()
	defer m.tmu.Unlock()
	if h := m.tHosts[rec.HostID]; h != nil {
		h.LastSeen, h.Active = rec.LastSeen, rec.Active
		return nil
	}
	c := rec
	c.Pub = append([]byte(nil), rec.Pub...)
	m.tHosts[rec.HostID] = &c
	return nil
}

func (m *memTunnel) DeleteTunnelHost(_ context.Context, hostID string) error {
	m.tmu.Lock()
	defer m.tmu.Unlock()
	m.deleteHostLocked(hostID)
	return nil
}

func (m *memTunnel) deleteHostLocked(hostID string) {
	delete(m.tHosts, hostID)
	for k := range m.tRevoke {
		if k.Host == hostID {
			delete(m.tRevoke, k)
		}
	}
	for k := range m.tPush {
		if k.Host == hostID {
			delete(m.tPush, k)
		}
	}
}

func (m *memTunnel) RevokeTunnelPhone(_ context.Context, hostID, pid string, exp int64) error {
	m.tmu.Lock()
	defer m.tmu.Unlock()
	k := tunnelPair{hostID, pid}
	if cur, ok := m.tRevoke[k]; !ok || exp > cur {
		m.tRevoke[k] = exp
	}
	delete(m.tPush, k)
	return nil
}

func (m *memTunnel) TunnelPhoneRevoked(_ context.Context, hostID, pid string, now int64) (bool, error) {
	m.tmu.RLock()
	defer m.tmu.RUnlock()
	exp, ok := m.tRevoke[tunnelPair{hostID, pid}]
	return ok && exp > now, nil
}

func (m *memTunnel) SetTunnelPushToken(_ context.Context, hostID, pid string, tok *PushToken, now int64) error {
	m.tmu.Lock()
	defer m.tmu.Unlock()
	k := tunnelPair{hostID, pid}
	if tok == nil {
		delete(m.tPush, k)
		return nil
	}
	m.tPush[k] = tunnelPushRow{Tok: *tok, UpdatedAt: now}
	return nil
}

func (m *memTunnel) TunnelPushToken(_ context.Context, hostID, pid string) (*PushToken, error) {
	m.tmu.RLock()
	defer m.tmu.RUnlock()
	if row, ok := m.tPush[tunnelPair{hostID, pid}]; ok {
		t := row.Tok
		return &t, nil
	}
	return nil, nil
}

func (m *memTunnel) PruneTunnel(_ context.Context, now int64, pendingMaxAge time.Duration) (int64, error) {
	m.tmu.Lock()
	defer m.tmu.Unlock()
	var n int64
	for k, exp := range m.tRevoke {
		if exp <= now {
			delete(m.tRevoke, k)
			n++
		}
	}
	cutoff := now - int64(pendingMaxAge/time.Second)
	for id, h := range m.tHosts {
		if !h.Active && h.LastSeen < cutoff {
			m.deleteHostLocked(id)
			n++
		}
	}
	return n, nil
}

// ── Snapshot ─────────────────────────────────────────────────────────────────

type tunnelSnap struct {
	Hosts       map[string]TunnelHostRecord `json:"hosts,omitempty"`
	Revocations []tunnelRevocationSnap      `json:"revocations,omitempty"`
	PushTokens  []tunnelPushSnap            `json:"pushTokens,omitempty"`
}

type tunnelRevocationSnap struct {
	Host string `json:"host"`
	PID  string `json:"pid"`
	Exp  int64  `json:"exp"`
}

type tunnelPushSnap struct {
	Host      string    `json:"host"`
	PID       string    `json:"pid"`
	Token     PushToken `json:"token"`
	UpdatedAt int64     `json:"updatedAt"`
}

func (m *memTunnel) toTunnelSnap() *tunnelSnap {
	m.tmu.RLock()
	defer m.tmu.RUnlock()
	if len(m.tHosts) == 0 && len(m.tRevoke) == 0 && len(m.tPush) == 0 {
		return nil
	}
	s := &tunnelSnap{Hosts: map[string]TunnelHostRecord{}}
	for id, h := range m.tHosts {
		s.Hosts[id] = *h
	}
	for k, exp := range m.tRevoke {
		s.Revocations = append(s.Revocations, tunnelRevocationSnap{Host: k.Host, PID: k.PID, Exp: exp})
	}
	for k, row := range m.tPush {
		s.PushTokens = append(s.PushTokens, tunnelPushSnap{Host: k.Host, PID: k.PID, Token: row.Tok, UpdatedAt: row.UpdatedAt})
	}
	return s
}

func (m *memTunnel) restoreTunnel(s *tunnelSnap) {
	m.tmu.Lock()
	defer m.tmu.Unlock()
	m.tHosts = map[string]*TunnelHostRecord{}
	m.tRevoke = map[tunnelPair]int64{}
	m.tPush = map[tunnelPair]tunnelPushRow{}
	if s == nil {
		return
	}
	for id, h := range s.Hosts {
		h := h
		m.tHosts[id] = &h
	}
	for _, r := range s.Revocations {
		m.tRevoke[tunnelPair{r.Host, r.PID}] = r.Exp
	}
	for _, p := range s.PushTokens {
		m.tPush[tunnelPair{p.Host, p.PID}] = tunnelPushRow{Tok: p.Token, UpdatedAt: p.UpdatedAt}
	}
}

// ── Postgres ─────────────────────────────────────────────────────────────────

const tunnelSchemaSQL = `
CREATE TABLE IF NOT EXISTS relay_tunnel_hosts (
  host_id    TEXT PRIMARY KEY,
  pub        BYTEA NOT NULL,
  created_at BIGINT NOT NULL,
  last_seen  BIGINT NOT NULL,
  active     BOOLEAN NOT NULL DEFAULT TRUE
);
CREATE TABLE IF NOT EXISTS relay_tunnel_revocations (
  host_id TEXT NOT NULL,
  pid     TEXT NOT NULL,
  exp     BIGINT NOT NULL,
  PRIMARY KEY (host_id, pid)
);
CREATE TABLE IF NOT EXISTS relay_tunnel_push_tokens (
  host_id    TEXT NOT NULL,
  pid        TEXT NOT NULL,
  token      TEXT NOT NULL,
  env        TEXT NOT NULL,
  updated_at BIGINT NOT NULL,
  PRIMARY KEY (host_id, pid)
);
`

func (s *postgresStore) TunnelHost(ctx context.Context, hostID string) (*TunnelHostRecord, error) {
	var r TunnelHostRecord
	err := s.pool.QueryRow(ctx,
		`SELECT host_id, pub, created_at, last_seen, active FROM relay_tunnel_hosts WHERE host_id = $1`, hostID).
		Scan(&r.HostID, &r.Pub, &r.CreatedAt, &r.LastSeen, &r.Active)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *postgresStore) UpsertTunnelHost(ctx context.Context, rec TunnelHostRecord) error {
	_, err := s.pool.Exec(ctx, `
INSERT INTO relay_tunnel_hosts (host_id, pub, created_at, last_seen, active) VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (host_id) DO UPDATE SET last_seen = EXCLUDED.last_seen, active = EXCLUDED.active`,
		rec.HostID, rec.Pub, rec.CreatedAt, rec.LastSeen, rec.Active)
	return err
}

func (s *postgresStore) DeleteTunnelHost(ctx context.Context, hostID string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for _, q := range []string{
		`DELETE FROM relay_tunnel_push_tokens WHERE host_id = $1`,
		`DELETE FROM relay_tunnel_revocations WHERE host_id = $1`,
		`DELETE FROM relay_tunnel_hosts WHERE host_id = $1`,
	} {
		if _, err := tx.Exec(ctx, q, hostID); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *postgresStore) RevokeTunnelPhone(ctx context.Context, hostID, pid string, exp int64) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `
INSERT INTO relay_tunnel_revocations (host_id, pid, exp) VALUES ($1, $2, $3)
ON CONFLICT (host_id, pid) DO UPDATE SET exp = GREATEST(relay_tunnel_revocations.exp, EXCLUDED.exp)`,
		hostID, pid, exp); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM relay_tunnel_push_tokens WHERE host_id = $1 AND pid = $2`, hostID, pid); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *postgresStore) TunnelPhoneRevoked(ctx context.Context, hostID, pid string, now int64) (bool, error) {
	var n int
	err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM relay_tunnel_revocations WHERE host_id = $1 AND pid = $2 AND exp > $3`,
		hostID, pid, now).Scan(&n)
	return n > 0, err
}

func (s *postgresStore) SetTunnelPushToken(ctx context.Context, hostID, pid string, tok *PushToken, now int64) error {
	if tok == nil {
		_, err := s.pool.Exec(ctx, `DELETE FROM relay_tunnel_push_tokens WHERE host_id = $1 AND pid = $2`, hostID, pid)
		return err
	}
	_, err := s.pool.Exec(ctx, `
INSERT INTO relay_tunnel_push_tokens (host_id, pid, token, env, updated_at) VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (host_id, pid) DO UPDATE SET token = EXCLUDED.token, env = EXCLUDED.env, updated_at = EXCLUDED.updated_at`,
		hostID, pid, tok.Token, tok.Env, now)
	return err
}

func (s *postgresStore) TunnelPushToken(ctx context.Context, hostID, pid string) (*PushToken, error) {
	var t PushToken
	err := s.pool.QueryRow(ctx,
		`SELECT token, env FROM relay_tunnel_push_tokens WHERE host_id = $1 AND pid = $2`, hostID, pid).
		Scan(&t.Token, &t.Env)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *postgresStore) PruneTunnel(ctx context.Context, now int64, pendingMaxAge time.Duration) (int64, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	var n int64
	tag, err := tx.Exec(ctx, `DELETE FROM relay_tunnel_revocations WHERE exp <= $1`, now)
	if err != nil {
		return 0, err
	}
	n += tag.RowsAffected()
	cutoff := now - int64(pendingMaxAge/time.Second)
	stale := `SELECT host_id FROM relay_tunnel_hosts WHERE NOT active AND last_seen < $1`
	for _, q := range []string{
		`DELETE FROM relay_tunnel_push_tokens WHERE host_id IN (` + stale + `)`,
		`DELETE FROM relay_tunnel_revocations WHERE host_id IN (` + stale + `)`,
	} {
		if _, err := tx.Exec(ctx, q, cutoff); err != nil {
			return 0, err
		}
	}
	tag, err = tx.Exec(ctx, `DELETE FROM relay_tunnel_hosts WHERE NOT active AND last_seen < $1`, cutoff)
	if err != nil {
		return 0, err
	}
	n += tag.RowsAffected()
	return n, tx.Commit(ctx)
}
