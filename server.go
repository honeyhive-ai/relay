package relay

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Pairing codes: confusion-free alphabet (no I/L/O/U), 6 chars → ~1e9 combos.
const (
	codeAlphabet   = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	codeLen        = 6
	defaultPairTTL = 600
	maxPairTTL     = 3600
	maxPairPayload = 8192
)

// Options configure a Server. Only Store is required; the rest default to the
// open-relay behavior. Downstream builds may inject implementations of the seams
// (see seams.go) here without touching this package.
type Options struct {
	Store       Store               // required
	Entitlement EntitlementVerifier // nil → EntitlementFromEnv()
	WriteGuard  WriteGuard          // nil → allow all writes (content-blind)
	Hooks       Hooks               // nil → no-op
	FriendCap   *int                // nil → unlimited
	AdminAuth   AdminAuthorizer     // nil → /v1/admin/* disabled (404)
}

// Server holds the durable Store plus the ephemeral, instance-local pieces
// (short pairing codes), the entitlement verifier, and the optional seams.
type Server struct {
	store       Store
	entitlement EntitlementVerifier
	guard       WriteGuard // nil = content-blind (no membership check)
	hooks       Hooks      // nil = no-op
	adminAuth   AdminAuthorizer // nil = admin API disabled
	friendCap   *int
	httpClient  *http.Client
	// verify authenticates a GitHub token → user. Defaults to verifyGitHub
	// (a live api.github.com call); tests override it.
	verify func(ctx context.Context, token string) (*githubUser, error)

	pairMu   sync.Mutex
	pairings map[string]pairing
}

type pairing struct {
	payload   string
	expiresAt time.Time
}

// New builds a Server from Options, filling in open-relay defaults.
func New(o Options) *Server {
	if o.Entitlement == nil {
		o.Entitlement = EntitlementFromEnv()
	}
	s := &Server{
		store:       o.Store,
		entitlement: o.Entitlement,
		guard:       o.WriteGuard,
		hooks:       o.Hooks,
		adminAuth:   o.AdminAuth,
		friendCap:   o.FriendCap,
		httpClient:  &http.Client{Timeout: 10 * time.Second},
		pairings:    map[string]pairing{},
	}
	s.verify = s.verifyGitHub
	return s
}

// claimsCtxKey carries the verified token claims from the gate to the handlers
// (so a WriteGuard can read plan/RBAC without re-verifying).
type claimsCtxKey struct{}

func claimsFrom(ctx context.Context) *TokenClaims {
	c, _ := ctx.Value(claimsCtxKey{}).(*TokenClaims)
	return c
}

func nowUnix() int64 { return time.Now().Unix() }

// Handler builds the /v1 router. Everything except /v1/health sits behind the
// entitlement gate (a no-op when the policy is Open, i.e. self-hosted).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Public landing page at the exact root, and the health check.
	mux.HandleFunc("GET /{$}", s.statusPage)
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("POST /v1/workspaces/{id}/envelopes", s.postEnvelope)
	mux.HandleFunc("GET /v1/workspaces/{id}/envelopes", s.listEnvelopes)
	mux.HandleFunc("POST /v1/workspaces/{id}/candidates", s.publishCandidates)
	mux.HandleFunc("GET /v1/workspaces/{id}/candidates", s.listCandidates)
	mux.HandleFunc("POST /v1/workspaces/{id}/presence", s.publishPresence)
	mux.HandleFunc("GET /v1/workspaces/{id}/presence", s.listPresence)
	mux.HandleFunc("POST /v1/workspaces/{id}/keyring", s.publishKeyring)
	mux.HandleFunc("GET /v1/workspaces/{id}/keyring", s.listKeyring)

	mux.HandleFunc("POST /v1/pair", s.createPairing)
	mux.HandleFunc("GET /v1/pair/{code}", s.resolvePairing)

	mux.HandleFunc("POST /v1/directory/register", s.directoryRegister)
	mux.HandleFunc("GET /v1/directory/{handle}", s.directoryLookup)

	mux.HandleFunc("POST /v1/account/register", s.accountRegister)
	mux.HandleFunc("POST /v1/account/heartbeat", s.accountHeartbeat)
	mux.HandleFunc("GET /v1/account/inbox", s.accountInbox)
	mux.HandleFunc("GET /v1/account/devices", s.accountDevices)
	mux.HandleFunc("POST /v1/account/visibility", s.accountVisibility)

	mux.HandleFunc("GET /v1/friends", s.friendsList)
	mux.HandleFunc("GET /v1/friends/presence", s.friendsPresence)
	mux.HandleFunc("GET /v1/friends/{account}/devices", s.friendDevicesList)
	mux.HandleFunc("DELETE /v1/friends/{account}", s.friendRemove)
	mux.HandleFunc("POST /v1/friends/requests", s.friendRequestCreate)
	mux.HandleFunc("GET /v1/friends/requests", s.friendRequestsList)
	mux.HandleFunc("POST /v1/friends/requests/{id}/accept", s.friendRequestAccept)
	mux.HandleFunc("POST /v1/friends/requests/{id}/reject", s.friendRequestReject)

	// User/token management — gated by the AdminAuthorizer seam (not the relay
	// entitlement token), so these bypass the entitlement gate below.
	mux.HandleFunc("POST /v1/admin/users", s.adminCreateUser)
	mux.HandleFunc("GET /v1/admin/users", s.adminListUsers)
	mux.HandleFunc("POST /v1/admin/users/{id}/tokens", s.adminIssueToken)
	mux.HandleFunc("POST /v1/admin/users/{id}/disabled", s.adminSetDisabled)
	mux.HandleFunc("DELETE /v1/admin/tokens/{id}", s.adminRevokeToken)

	return s.gate(mux)
}

// gate rejects /v1/* (except health) unless the caller is entitled, and stashes
// the verified claims in the request context for downstream enforcement.
func (s *Server) gate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "/v1/health" || strings.HasPrefix(r.URL.Path, "/v1/admin/") {
			// The status page + health are public; the admin API runs its own
			// AdminAuthorizer (an operator credential, not a relay token).
			next.ServeHTTP(w, r)
			return
		}
		claims, ok := s.entitlement.Allow(bearerToken(r), nowUnix())
		if !ok {
			http.Error(w, "relay requires a valid access token", http.StatusUnauthorized)
			return
		}
		if claims != nil {
			r = r.WithContext(context.WithValue(r.Context(), claimsCtxKey{}, claims))
		}
		next.ServeHTTP(w, r)
	})
}

// enforceWrite runs the optional WriteGuard before a workspace write. The open
// relay has no guard → always allowed (content-blind forwarding). Returns false
// (after writing 403) when the guard rejects.
func (s *Server) enforceWrite(w http.ResponseWriter, r *http.Request, workspace string) bool {
	if s.guard == nil {
		return true
	}
	if err := s.guard.CheckWrite(r.Context(), workspace, claimsFrom(r.Context()), r); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	return true
}

// afterWorkspaceWrite fires the optional metering/audit Hook.
func (s *Server) afterWorkspaceWrite(ctx context.Context, workspace string, seq uint64) {
	if s.hooks != nil {
		s.hooks.WorkspaceWritten(ctx, workspace, seq, claimsFrom(ctx))
	}
}

// ── Workspace sync handlers ───────────────────────────────────────────────────

func (s *Server) postEnvelope(w http.ResponseWriter, r *http.Request) {
	var body json.RawMessage
	if !readJSON(w, r, &body) {
		return
	}
	id := r.PathValue("id")
	if !s.enforceWrite(w, r, id) {
		return
	}
	seq, err := s.store.AppendEnvelope(r.Context(), id, body)
	if storeErr(w, err) {
		return
	}
	s.afterWorkspaceWrite(r.Context(), id, seq)
	writeJSON(w, http.StatusOK, map[string]uint64{"seq": seq})
}

func (s *Server) listEnvelopes(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.EnvelopesAfter(r.Context(), r.PathValue("id"), afterParam(r))
	if storeErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

type deviceBlobReq struct {
	DeviceID string          `json:"device_id"`
	Data     json.RawMessage `json:"data"`
}

func (s *Server) publishCandidates(w http.ResponseWriter, r *http.Request) {
	var b deviceBlobReq
	if !readJSON(w, r, &b) {
		return
	}
	id := r.PathValue("id")
	if !s.enforceWrite(w, r, id) {
		return
	}
	if storeErr(w, s.store.PutCandidate(r.Context(), id, b.DeviceID, b.Data)) {
		return
	}
	writeJSON(w, http.StatusOK, okResp())
}

func (s *Server) listCandidates(w http.ResponseWriter, r *http.Request) {
	m, err := s.store.Candidates(r.Context(), r.PathValue("id"))
	if storeErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, m)
}

func (s *Server) publishPresence(w http.ResponseWriter, r *http.Request) {
	var b deviceBlobReq
	if !readJSON(w, r, &b) {
		return
	}
	id := r.PathValue("id")
	if !s.enforceWrite(w, r, id) {
		return
	}
	if storeErr(w, s.store.PutPresence(r.Context(), id, b.DeviceID, b.Data)) {
		return
	}
	writeJSON(w, http.StatusOK, okResp())
}

func (s *Server) listPresence(w http.ResponseWriter, r *http.Request) {
	m, err := s.store.PresenceBlobs(r.Context(), r.PathValue("id"))
	if storeErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, m)
}

func (s *Server) publishKeyring(w http.ResponseWriter, r *http.Request) {
	var body json.RawMessage
	if !readJSON(w, r, &body) {
		return
	}
	id := r.PathValue("id")
	if !s.enforceWrite(w, r, id) {
		return
	}
	if storeErr(w, s.store.AppendKeyRotation(r.Context(), id, body)) {
		return
	}
	s.afterWorkspaceWrite(r.Context(), id, 0)
	writeJSON(w, http.StatusOK, okResp())
}

func (s *Server) listKeyring(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.KeyRotations(r.Context(), r.PathValue("id"))
	if storeErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

// ── Pairing handlers (ephemeral, instance-local) ──────────────────────────────

type pairReq struct {
	Payload string  `json:"payload"`
	TTLSecs *uint64 `json:"ttl_secs"`
}

func (s *Server) createPairing(w http.ResponseWriter, r *http.Request) {
	var req pairReq
	if !readJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Payload) == "" {
		http.Error(w, "empty payload", http.StatusBadRequest)
		return
	}
	if len(req.Payload) > maxPairPayload {
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	ttl := uint64(defaultPairTTL)
	if req.TTLSecs != nil {
		ttl = *req.TTLSecs
	}
	if ttl < 30 {
		ttl = 30
	}
	if ttl > maxPairTTL {
		ttl = maxPairTTL
	}

	s.pairMu.Lock()
	s.prunePairings()
	var code string
	for {
		code = randomPairCode()
		if _, exists := s.pairings[code]; !exists {
			break
		}
	}
	s.pairings[code] = pairing{payload: req.Payload, expiresAt: time.Now().Add(time.Duration(ttl) * time.Second)}
	s.pairMu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{"code": code, "expires_in": ttl})
}

func (s *Server) resolvePairing(w http.ResponseWriter, r *http.Request) {
	code := normalizePairCode(r.PathValue("code"))
	s.pairMu.Lock()
	s.prunePairings()
	p, ok := s.pairings[code]
	s.pairMu.Unlock()
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"payload": p.payload})
}

// prunePairings drops expired entries. Caller holds pairMu.
func (s *Server) prunePairings() {
	now := time.Now()
	for code, p := range s.pairings {
		if !p.expiresAt.After(now) {
			delete(s.pairings, code)
		}
	}
}

// ── Identity directory handlers ───────────────────────────────────────────────

type directoryRegisterReq struct {
	DeviceID string `json:"device_id"`
	KaPublic string `json:"ka_public"`
}

func (s *Server) directoryRegister(w http.ResponseWriter, r *http.Request) {
	var req directoryRegisterReq
	if !readJSON(w, r, &req) {
		return
	}
	user, ok := s.requireGitHub(w, r)
	if !ok {
		return
	}
	if storeErr(w, s.store.UpsertDirDevice(r.Context(), user.ID, user.Login, user.Name, strings.TrimSpace(req.DeviceID), strings.TrimSpace(req.KaPublic))) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"githubId": user.ID, "login": user.Login})
}

func (s *Server) directoryLookup(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireGitHub(w, r); !ok {
		return
	}
	acct, err := s.store.DirAccountByHandle(r.Context(), r.PathValue("handle"))
	if storeErr(w, err) {
		return
	}
	if acct == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	devices := make([]map[string]string, 0, len(acct.Devices))
	for id, pk := range acct.Devices {
		devices = append(devices, map[string]string{"deviceId": id, "kaPublic": pk})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"githubId": acct.GitHubID,
		"login":    acct.Login,
		"name":     acct.Name,
		"devices":  devices,
	})
}

// ── Account registry handlers ─────────────────────────────────────────────────

type accountRegisterReq struct {
	DeviceID string  `json:"deviceId"`
	NodeID   *string `json:"nodeId"`
	Label    *string `json:"label"`
}

func (s *Server) accountRegister(w http.ResponseWriter, r *http.Request) {
	var req accountRegisterReq
	if !readJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.DeviceID) == "" {
		http.Error(w, "device_id required", http.StatusBadRequest)
		return
	}
	user, ok := s.requireGitHub(w, r)
	if !ok {
		return
	}
	key, err := s.store.RegisterAccountDevice(r.Context(), user.ID, user.Login, strings.TrimSpace(req.DeviceID),
		nonEmpty(req.NodeID), nonEmpty(req.Label), nowUnix())
	if storeErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"accountId": key, "githubId": user.ID, "login": user.Login})
}

type accountHeartbeatReq struct {
	DeviceID string `json:"deviceId"`
}

func (s *Server) accountHeartbeat(w http.ResponseWriter, r *http.Request) {
	var req accountHeartbeatReq
	if !readJSON(w, r, &req) {
		return
	}
	user, ok := s.requireGitHub(w, r)
	if !ok {
		return
	}
	known, err := s.store.HeartbeatDevice(r.Context(), user.ID, strings.TrimSpace(req.DeviceID), nowUnix())
	if storeErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": known})
}

func (s *Server) accountInbox(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireGitHub(w, r)
	if !ok {
		return
	}
	rows, err := s.store.AccountInboxAfter(r.Context(), accountKey(user.ID), afterParam(r))
	if storeErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

func (s *Server) accountDevices(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireGitHub(w, r)
	if !ok {
		return
	}
	rows, err := s.store.AccountDevices(r.Context(), accountKey(user.ID))
	if storeErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

type visibilityBody struct {
	AppearOffline bool `json:"appearOffline"`
}

func (s *Server) accountVisibility(w http.ResponseWriter, r *http.Request) {
	var body visibilityBody
	if !readJSON(w, r, &body) {
		return
	}
	user, ok := s.requireGitHub(w, r)
	if !ok {
		return
	}
	if storeErr(w, s.store.SetVisibility(r.Context(), user.ID, body.AppearOffline)) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"appearOffline": body.AppearOffline})
}

// ── Friend handlers ───────────────────────────────────────────────────────────

type friendRequestBody struct {
	ToLogin string `json:"toLogin"`
}

func (s *Server) friendRequestCreate(w http.ResponseWriter, r *http.Request) {
	var body friendRequestBody
	if !readJSON(w, r, &body) {
		return
	}
	user, fromAccount, ok := s.callerAccount(w, r)
	if !ok {
		return
	}
	toLogin := strings.TrimPrefix(strings.TrimSpace(body.ToLogin), "@")
	toAccount, found, err := s.store.AccountKeyForLogin(r.Context(), toLogin)
	if storeErr(w, err) {
		return
	}
	if !found {
		http.Error(w, "user hasn't joined Hive", http.StatusNotFound)
		return
	}
	req, err := s.store.CreateFriendRequest(r.Context(), fromAccount, user.Login, toAccount, toLogin, nowUnix(), s.friendCap)
	if friendErr(w, err) {
		return
	}
	if _, err := s.store.PushAccountEvent(r.Context(), toAccount, req.requestEvent()); storeErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"requestId": req.ID, "state": "pending"})
}

func (s *Server) friendRequestAccept(w http.ResponseWriter, r *http.Request) {
	_, account, ok := s.callerAccount(w, r)
	if !ok {
		return
	}
	req, err := s.store.AcceptFriendRequest(r.Context(), r.PathValue("id"), account, s.friendCap)
	if friendErr(w, err) {
		return
	}
	ev := req.resolvedEvent()
	_, _ = s.store.PushAccountEvent(r.Context(), req.FromAccount, ev)
	_, _ = s.store.PushAccountEvent(r.Context(), req.ToAccount, ev)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "state": "accepted"})
}

func (s *Server) friendRequestReject(w http.ResponseWriter, r *http.Request) {
	_, account, ok := s.callerAccount(w, r)
	if !ok {
		return
	}
	req, err := s.store.CloseFriendRequest(r.Context(), r.PathValue("id"), account)
	if friendErr(w, err) {
		return
	}
	ev := req.resolvedEvent()
	_, _ = s.store.PushAccountEvent(r.Context(), req.FromAccount, ev)
	_, _ = s.store.PushAccountEvent(r.Context(), req.ToAccount, ev)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) friendsList(w http.ResponseWriter, r *http.Request) {
	_, account, ok := s.callerAccount(w, r)
	if !ok {
		return
	}
	friends, err := s.store.ListFriends(r.Context(), account)
	if storeErr(w, err) {
		return
	}
	out := make([]map[string]string, 0, len(friends))
	for _, f := range friends {
		out = append(out, map[string]string{"accountId": f.AccountKey, "login": f.Login})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) friendRequestsList(w http.ResponseWriter, r *http.Request) {
	_, account, ok := s.callerAccount(w, r)
	if !ok {
		return
	}
	reqs, err := s.store.IncomingRequests(r.Context(), account, nowUnix())
	if storeErr(w, err) {
		return
	}
	out := make([]map[string]any, 0, len(reqs))
	for _, rq := range reqs {
		out = append(out, map[string]any{
			"requestId":   rq.ID,
			"fromAccount": rq.FromAccount,
			"fromLogin":   rq.FromLogin,
			"createdAt":   rq.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) friendsPresence(w http.ResponseWriter, r *http.Request) {
	_, account, ok := s.callerAccount(w, r)
	if !ok {
		return
	}
	pres, err := s.store.FriendPresence(r.Context(), account, nowUnix())
	if storeErr(w, err) {
		return
	}
	out := make([]map[string]string, 0, len(pres))
	for _, p := range pres {
		out = append(out, map[string]string{"accountId": p.AccountKey, "login": p.Login, "presence": p.Presence})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) friendDevicesList(w http.ResponseWriter, r *http.Request) {
	_, account, ok := s.callerAccount(w, r)
	if !ok {
		return
	}
	rows, friends, err := s.store.FriendDevices(r.Context(), account, r.PathValue("account"))
	if storeErr(w, err) {
		return
	}
	if !friends {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

func (s *Server) friendRemove(w http.ResponseWriter, r *http.Request) {
	_, account, ok := s.callerAccount(w, r)
	if !ok {
		return
	}
	removed, err := s.store.RemoveFriend(r.Context(), account, r.PathValue("account"))
	if storeErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": removed})
}

// ── Auth + helpers ────────────────────────────────────────────────────────────

type githubUser struct {
	ID    uint64  `json:"id"`
	Login string  `json:"login"`
	Name  *string `json:"name"`
}

// requireGitHub verifies the caller's GitHub token and returns the user, or
// writes 401.
func (s *Server) requireGitHub(w http.ResponseWriter, r *http.Request) (*githubUser, bool) {
	token := githubTokenHeader(r)
	if token == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return nil, false
	}
	user, err := s.verify(r.Context(), token)
	if err != nil || user == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return nil, false
	}
	return user, true
}

// callerAccount resolves the authenticated caller's identity → account key.
func (s *Server) callerAccount(w http.ResponseWriter, r *http.Request) (*githubUser, string, bool) {
	user, ok := s.requireGitHub(w, r)
	if !ok {
		return nil, "", false
	}
	return user, accountKey(user.ID), true
}

// verifyGitHub authenticates a GitHub token by fetching the user it belongs to.
func (s *Server) verifyGitHub(ctx context.Context, token string) (*githubUser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "hive-relay")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, nil
	}
	var user githubUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, err
	}
	return &user, nil
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	t := strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	if h == t { // no "Bearer " prefix was present
		return ""
	}
	return t
}

func githubTokenHeader(r *http.Request) string {
	if t := strings.TrimSpace(r.Header.Get("x-hive-github-token")); t != "" {
		return t
	}
	return bearerToken(r)
}

func afterParam(r *http.Request) uint64 {
	n, _ := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
	return n
}

func nonEmpty(s *string) *string {
	if s == nil || strings.TrimSpace(*s) == "" {
		return nil
	}
	return s
}

func okResp() map[string]bool { return map[string]bool{"ok": true} }

// readJSON decodes the request body; on failure it writes 400 and returns false.
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// storeErr writes 500 and returns true if a backend error occurred.
func storeErr(w http.ResponseWriter, err error) bool {
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return true
	}
	return false
}

// friendErr maps a friend-graph refusal to an HTTP status (CapReached → 402 so
// the client can surface an upgrade prompt). Returns true if it handled an error.
func friendErr(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, ErrSelfRequest):
		status = http.StatusBadRequest
	case errors.Is(err, ErrAlreadyFriends), errors.Is(err, ErrNotPending):
		status = http.StatusConflict
	case errors.Is(err, ErrCapReached):
		status = http.StatusPaymentRequired
	case errors.Is(err, ErrNotFound):
		status = http.StatusNotFound
	case errors.Is(err, ErrNotYours):
		status = http.StatusForbidden
	case errors.Is(err, ErrTooManyPending):
		status = http.StatusTooManyRequests
	}
	http.Error(w, err.Error(), status)
	return true
}

func randomPairCode() string {
	var b [codeLen]byte
	randRead(b[:])
	out := make([]byte, codeLen)
	for i := range b {
		out[i] = codeAlphabet[int(b[i])%len(codeAlphabet)]
	}
	return string(out)
}

func normalizePairCode(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			b.WriteRune(r)
		}
	}
	return strings.ToUpper(b.String())
}
