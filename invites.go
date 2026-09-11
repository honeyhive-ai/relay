package relay

// Relay-issued workspace invites — revocable, expiring, use-capped self-enroll.
//
// Replaces the app's unbounded `hivews1:` shared secret for the *access* half of
// joining: an admin issues an invite (a random code; the relay stores only its
// SHA-256), shares the code out-of-band, and a joiner redeems it via POST
// /join. Redemption enrolls the joiner's *identified* token subject at the
// invite's role. The E2EE workspace key is still delivered separately (sealed to
// the joiner's device) — the relay never sees it. Invites are content-blind:
// the relay holds only a code hash + coarse role + counters.

import (
	"context"
	"net/http"
)

// InviteRow is invite metadata (never the code) returned to admins.
type InviteRow struct {
	ID        string `json:"id"`
	Role      string `json:"role"`
	CreatedBy string `json:"createdBy"`
	ExpiresAt int64  `json:"expiresAt"` // unix secs; 0 = never
	MaxUses   int    `json:"maxUses"`   // 0 = unlimited
	Uses      int    `json:"uses"`
	Revoked   bool   `json:"revoked"`
}

// memInvite is the in-memory invite (adds the code hash to InviteRow).
type memInvite struct {
	row      InviteRow
	codeHash string
}

// inviteValid reports whether an invite can still be redeemed at `now`.
func inviteValid(i *memInvite, now int64) bool {
	if i.row.Revoked {
		return false
	}
	if i.row.ExpiresAt > 0 && now >= i.row.ExpiresAt {
		return false
	}
	if i.row.MaxUses > 0 && i.row.Uses >= i.row.MaxUses {
		return false
	}
	return true
}

// ── memoryStore invites ──────────────────────────────────────────────────────

func (s *memoryStore) CreateInvite(_ context.Context, workspace, id, codeHash, role, createdBy string, expiresAt int64, maxUses int, _ int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	w := s.workspace(workspace)
	if w.invites == nil {
		w.invites = map[string]*memInvite{}
	}
	w.invites[id] = &memInvite{
		row:      InviteRow{ID: id, Role: role, CreatedBy: createdBy, ExpiresAt: expiresAt, MaxUses: maxUses},
		codeHash: codeHash,
	}
	return nil
}

func (s *memoryStore) ListInvites(_ context.Context, workspace string) ([]InviteRow, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []InviteRow{}
	if w := s.workspaces[workspace]; w != nil {
		for _, i := range w.invites {
			out = append(out, i.row)
		}
	}
	return out, nil
}

func (s *memoryStore) RevokeInvite(_ context.Context, workspace, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if w := s.workspaces[workspace]; w != nil {
		if i := w.invites[id]; i != nil {
			i.row.Revoked = true
		}
	}
	return nil
}

// RedeemInvite validates the code against a live invite, increments its use
// count, and returns the role to enroll the caller at. ok=false when no live
// invite matches (unknown/expired/revoked/exhausted).
func (s *memoryStore) RedeemInvite(_ context.Context, workspace, codeHash string, now int64) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w := s.workspaces[workspace]
	if w == nil {
		return "", false, nil
	}
	for _, i := range w.invites {
		if i.codeHash == codeHash && inviteValid(i, now) {
			i.row.Uses++
			return i.row.Role, true, nil
		}
	}
	return "", false, nil
}

// ── HTTP handlers ─────────────────────────────────────────────────────────────

// POST /v1/workspaces/{id}/invites — issue an invite. Admin+. Body:
// {role, ttlSecs?, maxUses?}. Returns {id, code, role, expiresAt, maxUses} — the
// code is shown ONCE (only its hash is stored).
func (s *Server) inviteCreate(w http.ResponseWriter, r *http.Request) {
	ws := r.PathValue("id")
	caller := callerAccount(claimsFrom(r.Context()))
	if caller == "" {
		http.Error(w, "requires an identified access token", http.StatusUnauthorized)
		return
	}
	if err := s.requireRole(r.Context(), ws, caller, rankAdmin); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var body struct {
		Role    string `json:"role"`
		TTLSecs int64  `json:"ttlSecs"`
		MaxUses int    `json:"maxUses"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if roleRank(body.Role) < 0 || body.Role == "owner" {
		// Owner can't be granted via a shareable code — too dangerous.
		http.Error(w, "role must be admin, contributor, or viewer", http.StatusBadRequest)
		return
	}
	code, err := GenerateToken()
	if err != nil {
		http.Error(w, "could not generate invite", http.StatusInternalServerError)
		return
	}
	id, err := GenerateToken()
	if err != nil {
		http.Error(w, "could not generate invite", http.StatusInternalServerError)
		return
	}
	id = id[:12]
	now := nowUnix()
	var expiresAt int64
	if body.TTLSecs > 0 {
		expiresAt = now + body.TTLSecs
	}
	if err := s.store.CreateInvite(r.Context(), ws, id, HashToken(code), body.Role, caller, expiresAt, body.MaxUses, now); storeErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": id, "code": code, "role": body.Role, "expiresAt": expiresAt, "maxUses": body.MaxUses,
	})
}

// GET /v1/workspaces/{id}/invites — list invite metadata (no codes). Admin+.
func (s *Server) invitesList(w http.ResponseWriter, r *http.Request) {
	ws := r.PathValue("id")
	caller := callerAccount(claimsFrom(r.Context()))
	if caller == "" {
		http.Error(w, "requires an identified access token", http.StatusUnauthorized)
		return
	}
	if err := s.requireRole(r.Context(), ws, caller, rankAdmin); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	rows, err := s.store.ListInvites(r.Context(), ws)
	if storeErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

// DELETE /v1/workspaces/{id}/invites/{inviteId} — revoke an invite. Admin+.
func (s *Server) inviteRevoke(w http.ResponseWriter, r *http.Request) {
	ws := r.PathValue("id")
	caller := callerAccount(claimsFrom(r.Context()))
	if caller == "" {
		http.Error(w, "requires an identified access token", http.StatusUnauthorized)
		return
	}
	if err := s.requireRole(r.Context(), ws, caller, rankAdmin); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := s.store.RevokeInvite(r.Context(), ws, r.PathValue("inviteId")); storeErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// POST /v1/workspaces/{id}/join — redeem an invite code to enroll the caller.
// Body: {code, login?}. The caller must present an identified token; they're
// enrolled at the invite's role. Returns {role}.
func (s *Server) workspaceJoin(w http.ResponseWriter, r *http.Request) {
	ws := r.PathValue("id")
	caller := callerAccount(claimsFrom(r.Context()))
	if caller == "" {
		http.Error(w, "requires an identified access token", http.StatusUnauthorized)
		return
	}
	var body struct {
		Code  string `json:"code"`
		Login string `json:"login"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	role, ok, err := s.store.RedeemInvite(r.Context(), ws, HashToken(body.Code), nowUnix())
	if storeErr(w, err) {
		return
	}
	if !ok {
		http.Error(w, "invite is invalid, expired, revoked, or used up", http.StatusForbidden)
		return
	}
	if err := s.store.UpsertMember(r.Context(), ws, caller, body.Login, role, "invite", nowUnix()); storeErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"role": role})
}
