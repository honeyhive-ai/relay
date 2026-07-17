package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// memoryStore is the in-process Store: RWMutex-guarded maps plus an optional
// JSON snapshot (set persistPath). Zero external dependencies; the self-host
// default and what the tests run against. It does not share state across
// processes — that's postgresStore's job (selected by DATABASE_URL), which the
// Store seam lets drop in with no data migration.
type memoryStore struct {
	mu          sync.RWMutex
	workspaces  map[string]*memWorkspace
	directory   map[string]*DirAccount // keyed by lowercased login
	accounts    map[string]*memAccount
	loginIndex  map[string]string // lowercased login → account key
	friendReqs  map[string]*FriendRequest
	friendEdges map[[2]string]struct{}

	users     map[string]*UserRecord // user id → record
	tokens    map[string]*memToken   // token id → record
	tokenHash map[string]string      // token hash → token id
	nextIDSeq uint64                 // monotonic id source for users/tokens

	persistPath string // "" = in-memory only
}

type memToken struct {
	rec  TokenRecord
	hash string
}

type memWorkspace struct {
	envelopes  []Envelope
	nextSeq    uint64
	candidates map[string]json.RawMessage
	presence   map[string]json.RawMessage
	keyring    []json.RawMessage
}

type memDeviceReg struct {
	nodeID   *string
	label    *string
	lastSeen int64
}

type memAccount struct {
	login         string
	appearOffline bool
	inbox         []InboxRow
	nextSeq       uint64
	devices       map[string]memDeviceReg
}

func newMemoryStore() *memoryStore {
	return &memoryStore{
		workspaces:  map[string]*memWorkspace{},
		directory:   map[string]*DirAccount{},
		accounts:    map[string]*memAccount{},
		loginIndex:  map[string]string{},
		friendReqs:  map[string]*FriendRequest{},
		friendEdges: map[[2]string]struct{}{},
		users:       map[string]*UserRecord{},
		tokens:      map[string]*memToken{},
		tokenHash:   map[string]string{},
	}
}

func (s *memoryStore) workspace(id string) *memWorkspace {
	w := s.workspaces[id]
	if w == nil {
		w = &memWorkspace{
			candidates: map[string]json.RawMessage{},
			presence:   map[string]json.RawMessage{},
		}
		s.workspaces[id] = w
	}
	return w
}

func (s *memoryStore) account(key string) *memAccount {
	a := s.accounts[key]
	if a == nil {
		a = &memAccount{devices: map[string]memDeviceReg{}}
		s.accounts[key] = a
	}
	return a
}

// ── Workspace sync ───────────────────────────────────────────────────────────

func (s *memoryStore) AppendEnvelope(_ context.Context, workspace string, body json.RawMessage) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w := s.workspace(workspace)
	w.nextSeq++
	w.envelopes = append(w.envelopes, Envelope{Seq: w.nextSeq, Body: body})
	return w.nextSeq, nil
}

func (s *memoryStore) EnvelopesAfter(_ context.Context, workspace string, after uint64) ([]Envelope, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []Envelope{}
	if w := s.workspaces[workspace]; w != nil {
		for _, e := range w.envelopes {
			if e.Seq > after {
				out = append(out, e)
			}
		}
	}
	return out, nil
}

func (s *memoryStore) PutCandidate(_ context.Context, workspace, deviceID string, candidate json.RawMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.workspace(workspace).candidates[deviceID] = candidate
	return nil
}

func (s *memoryStore) Candidates(_ context.Context, workspace string) (map[string]json.RawMessage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := map[string]json.RawMessage{}
	if w := s.workspaces[workspace]; w != nil {
		for k, v := range w.candidates {
			out[k] = v
		}
	}
	return out, nil
}

func (s *memoryStore) PutPresence(_ context.Context, workspace, deviceID string, presence json.RawMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.workspace(workspace).presence[deviceID] = presence
	return nil
}

func (s *memoryStore) PresenceBlobs(_ context.Context, workspace string) (map[string]json.RawMessage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := map[string]json.RawMessage{}
	if w := s.workspaces[workspace]; w != nil {
		for k, v := range w.presence {
			out[k] = v
		}
	}
	return out, nil
}

func (s *memoryStore) AppendKeyRotation(_ context.Context, workspace string, blob json.RawMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	w := s.workspace(workspace)
	w.keyring = append(w.keyring, blob)
	return nil
}

func (s *memoryStore) KeyRotations(_ context.Context, workspace string) ([]json.RawMessage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []json.RawMessage{}
	if w := s.workspaces[workspace]; w != nil {
		out = append(out, w.keyring...)
	}
	return out, nil
}

// ── Identity directory ────────────────────────────────────────────────────────

func (s *memoryStore) UpsertDirDevice(_ context.Context, githubID uint64, login string, name *string, deviceID, kaPub string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := lower(login)
	e := s.directory[key]
	if e == nil {
		e = &DirAccount{Devices: map[string]string{}}
		s.directory[key] = e
	}
	e.GitHubID = githubID
	e.Login = login
	e.Name = name
	if kaPub != "" && deviceID != "" {
		e.Devices[deviceID] = kaPub
	}
	return nil
}

func (s *memoryStore) DirAccountByHandle(_ context.Context, handle string) (*DirAccount, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e := s.directory[normHandle(handle)]
	if e == nil {
		return nil, nil
	}
	devices := make(map[string]string, len(e.Devices))
	for k, v := range e.Devices {
		devices[k] = v
	}
	return &DirAccount{GitHubID: e.GitHubID, Login: e.Login, Name: e.Name, Devices: devices}, nil
}

// ── Account registry + inbox ──────────────────────────────────────────────────

func (s *memoryStore) RegisterAccountDevice(_ context.Context, githubID uint64, login, deviceID string, nodeID, label *string, now int64) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := accountKey(githubID)
	s.loginIndex[lower(login)] = key
	a := s.account(key)
	a.login = login
	a.devices[deviceID] = memDeviceReg{nodeID: nodeID, label: label, lastSeen: now}
	return key, nil
}

func (s *memoryStore) HeartbeatDevice(_ context.Context, githubID uint64, deviceID string, now int64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.accounts[accountKey(githubID)]
	if a == nil {
		return false, nil
	}
	d, ok := a.devices[deviceID]
	if !ok {
		return false, nil
	}
	d.lastSeen = now
	a.devices[deviceID] = d
	return true, nil
}

func (s *memoryStore) PushAccountEvent(_ context.Context, key string, body json.RawMessage) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.account(key)
	a.nextSeq++
	a.inbox = append(a.inbox, InboxRow{Seq: a.nextSeq, Body: body})
	return a.nextSeq, nil
}

func (s *memoryStore) AccountInboxAfter(_ context.Context, key string, after uint64) ([]InboxRow, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []InboxRow{}
	if a := s.accounts[key]; a != nil {
		for _, e := range a.inbox {
			if e.Seq > after {
				out = append(out, e)
			}
		}
	}
	return out, nil
}

func (s *memoryStore) AccountDevices(_ context.Context, key string) ([]DeviceRow, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.accountDevicesLocked(key), nil
}

func (s *memoryStore) accountDevicesLocked(key string) []DeviceRow {
	out := []DeviceRow{}
	if a := s.accounts[key]; a != nil {
		for id, d := range a.devices {
			out = append(out, DeviceRow{DeviceID: id, NodeID: d.nodeID, Label: d.label, LastSeen: d.lastSeen})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DeviceID < out[j].DeviceID })
	return out
}

func (s *memoryStore) AccountKeyForLogin(_ context.Context, login string) (string, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.loginIndex[normHandle(login)]
	return k, ok, nil
}

func (s *memoryStore) SetVisibility(_ context.Context, githubID uint64, appearOffline bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a := s.accounts[accountKey(githubID)]; a != nil {
		a.appearOffline = appearOffline
	}
	return nil
}

func (s *memoryStore) PresenceOf(_ context.Context, key string, now int64) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.presenceOfLocked(key, now), nil
}

func (s *memoryStore) presenceOfLocked(key string, now int64) string {
	a := s.accounts[key]
	if a == nil {
		return "offline"
	}
	if a.appearOffline {
		return "offline"
	}
	var latest int64
	for _, d := range a.devices {
		if d.lastSeen > latest {
			latest = d.lastSeen
		}
	}
	return presenceStr(latest, now)
}

// ── Friend graph ───────────────────────────────────────────────────────────────

func (s *memoryStore) AreFriends(_ context.Context, a, b string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.friendEdges[canonicalPair(a, b)]
	return ok, nil
}

func (s *memoryStore) friendCountLocked(account string) int {
	n := 0
	for pair := range s.friendEdges {
		if pair[0] == account || pair[1] == account {
			n++
		}
	}
	return n
}

func (s *memoryStore) capBlocksLocked(account string, friendCap *int) bool {
	return friendCap != nil && s.friendCountLocked(account) >= *friendCap
}

func (s *memoryStore) expirePendingLocked(now int64) {
	for _, r := range s.friendReqs {
		if r.State == StatePending && now-r.CreatedAt > requestTTLSecs {
			r.State = StateCancelled
		}
	}
}

func (s *memoryStore) CreateFriendRequest(_ context.Context, fromAccount, fromLogin, toAccount, toLogin string, now int64, friendCap *int) (FriendRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if fromAccount == toAccount {
		return FriendRequest{}, ErrSelfRequest
	}
	if _, ok := s.friendEdges[canonicalPair(fromAccount, toAccount)]; ok {
		return FriendRequest{}, ErrAlreadyFriends
	}
	if s.capBlocksLocked(fromAccount, friendCap) {
		return FriendRequest{}, ErrCapReached
	}
	s.expirePendingLocked(now)
	// Idempotent: a duplicate pending request returns the existing one.
	for _, r := range s.friendReqs {
		if r.State == StatePending && r.FromAccount == fromAccount && r.ToAccount == toAccount {
			return *r, nil
		}
	}
	// Abuse control: bound how many requests one account can have in flight.
	pendingOut := 0
	for _, r := range s.friendReqs {
		if r.State == StatePending && r.FromAccount == fromAccount {
			pendingOut++
		}
	}
	if pendingOut >= maxPendingOutbound {
		return FriendRequest{}, ErrTooManyPending
	}
	req := &FriendRequest{
		ID:          newRequestID(),
		FromAccount: fromAccount,
		FromLogin:   fromLogin,
		ToAccount:   toAccount,
		ToLogin:     toLogin,
		CreatedAt:   now,
		State:       StatePending,
	}
	s.friendReqs[req.ID] = req
	return *req, nil
}

func (s *memoryStore) AcceptFriendRequest(_ context.Context, requestID, acceptor string, friendCap *int) (FriendRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.friendReqs[requestID]
	if r == nil {
		return FriendRequest{}, ErrNotFound
	}
	if r.ToAccount != acceptor {
		return FriendRequest{}, ErrNotYours
	}
	if r.State != StatePending {
		return FriendRequest{}, ErrNotPending
	}
	if s.capBlocksLocked(r.FromAccount, friendCap) || s.capBlocksLocked(r.ToAccount, friendCap) {
		return FriendRequest{}, ErrCapReached
	}
	s.friendEdges[canonicalPair(r.FromAccount, r.ToAccount)] = struct{}{}
	r.State = StateAccepted
	return *r, nil
}

func (s *memoryStore) CloseFriendRequest(_ context.Context, requestID, actor string) (FriendRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.friendReqs[requestID]
	if r == nil {
		return FriendRequest{}, ErrNotFound
	}
	if r.State != StatePending {
		return FriendRequest{}, ErrNotPending
	}
	switch actor {
	case r.ToAccount:
		r.State = StateRejected
	case r.FromAccount:
		r.State = StateCancelled
	default:
		return FriendRequest{}, ErrNotYours
	}
	return *r, nil
}

func (s *memoryStore) RemoveFriend(_ context.Context, account, other string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pair := canonicalPair(account, other)
	if _, ok := s.friendEdges[pair]; !ok {
		return false, nil
	}
	delete(s.friendEdges, pair)
	return true, nil
}

func (s *memoryStore) listFriendsLocked(account string) []Friend {
	others := []string{}
	for pair := range s.friendEdges {
		switch account {
		case pair[0]:
			others = append(others, pair[1])
		case pair[1]:
			others = append(others, pair[0])
		}
	}
	sort.Strings(others)
	out := make([]Friend, 0, len(others))
	for _, k := range others {
		login := ""
		if a := s.accounts[k]; a != nil {
			login = a.login
		}
		out = append(out, Friend{AccountKey: k, Login: login})
	}
	return out
}

func (s *memoryStore) ListFriends(_ context.Context, account string) ([]Friend, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.listFriendsLocked(account), nil
}

func (s *memoryStore) IncomingRequests(_ context.Context, account string, now int64) ([]FriendRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expirePendingLocked(now)
	out := []FriendRequest{}
	for _, r := range s.friendReqs {
		if r.State == StatePending && r.ToAccount == account {
			out = append(out, *r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt < out[j].CreatedAt })
	return out, nil
}

func (s *memoryStore) FriendDevices(_ context.Context, caller, friend string) ([]DeviceRow, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.friendEdges[canonicalPair(caller, friend)]; !ok {
		return nil, false, nil
	}
	return s.accountDevicesLocked(friend), true, nil
}

func (s *memoryStore) FriendCount(_ context.Context, account string) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.friendCountLocked(account), nil
}

func (s *memoryStore) FriendPresence(_ context.Context, account string, now int64) ([]FriendPresence, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	friends := s.listFriendsLocked(account)
	out := make([]FriendPresence, 0, len(friends))
	for _, f := range friends {
		out = append(out, FriendPresence{
			AccountKey: f.AccountKey,
			Login:      f.Login,
			Presence:   s.presenceOfLocked(f.AccountKey, now),
		})
	}
	return out, nil
}

func (s *memoryStore) PersistenceEnabled() bool { return s.persistPath != "" }

func (s *memoryStore) Flush(_ context.Context) error { return s.flushSnapshot() }

func (s *memoryStore) Close() error { return nil }

// ── helpers ──────────────────────────────────────────────────────────────────

func lower(s string) string { return strings.ToLower(s) }

// normHandle strips a leading '@' and surrounding space, then lowercases — used
// for login-index and directory lookups.
func normHandle(s string) string {
	return strings.ToLower(strings.TrimPrefix(strings.TrimSpace(s), "@"))
}

// ── Users + access tokens ────────────────────────────────────────────────────

func (s *memoryStore) nextID(prefix string) string {
	s.nextIDSeq++
	return fmt.Sprintf("%s_%d", prefix, s.nextIDSeq)
}

func (s *memoryStore) CreateUser(_ context.Context, name, login string, now int64) (UserRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := UserRecord{ID: s.nextID("usr"), Name: name, Login: login, CreatedAt: now}
	s.users[u.ID] = &u
	return u, nil
}

func (s *memoryStore) ListUsers(_ context.Context) ([]UserRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]UserRecord, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, *u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt < out[j].CreatedAt })
	return out, nil
}

func (s *memoryStore) SetUserDisabled(_ context.Context, userID string, disabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[userID]
	if !ok {
		return ErrUserNotFound
	}
	u.Disabled = disabled
	return nil
}

func (s *memoryStore) IssueToken(_ context.Context, userID, label, tokenHash string, now int64) (TokenRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[userID]; !ok {
		return TokenRecord{}, ErrUserNotFound
	}
	rec := TokenRecord{ID: s.nextID("tok"), UserID: userID, Label: label, CreatedAt: now}
	s.tokens[rec.ID] = &memToken{rec: rec, hash: tokenHash}
	s.tokenHash[tokenHash] = rec.ID
	return rec, nil
}

func (s *memoryStore) ListTokens(_ context.Context) ([]TokenRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]TokenRecord, 0, len(s.tokens))
	for _, t := range s.tokens {
		out = append(out, t.rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt < out[j].CreatedAt })
	return out, nil
}

func (s *memoryStore) RevokeToken(_ context.Context, tokenID string, now int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[tokenID]
	if !ok {
		return ErrTokenNotFound
	}
	if t.rec.RevokedAt == nil {
		n := now
		t.rec.RevokedAt = &n
	}
	delete(s.tokenHash, t.hash) // no longer resolvable
	return nil
}

func (s *memoryStore) ResolveToken(_ context.Context, tokenHash string, now int64) (*TokenClaims, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.tokenHash[tokenHash]
	if !ok {
		return nil, false, nil
	}
	t := s.tokens[id]
	if t == nil || t.rec.RevokedAt != nil {
		return nil, false, nil
	}
	u := s.users[t.rec.UserID]
	if u == nil || u.Disabled {
		return nil, false, nil
	}
	t.rec.LastUsed = now
	sub := u.Login
	if sub == "" {
		sub = u.ID
	}
	return &TokenClaims{Sub: sub, Plan: "team"}, true, nil
}
