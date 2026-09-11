package relay

// Relay-managed team membership.
//
// The relay stays content-blind: it never sees the workspace key or any
// plaintext. To *enforce* who may push/read a workspace, it must know the
// authorized accounts — so a roster of {account, role} is deliberate, bounded
// metadata (GitHub account ids + coarse roles), never content.
//
// Opt-in + fail-safe by construction: a workspace is "unclaimed" until someone
// POSTs /members/claim. An unclaimed workspace has an empty roster and the guard
// treats it exactly like the open relay (content-blind forwarding). Once
// claimed, the guard requires the caller's token subject to be a member with a
// sufficient role. The whole feature (routes + guard) only turns on when the
// operator sets HIVE_RELAY_MEMBERSHIP=1 (or Options.Membership), so the default
// self-host relay is byte-for-byte unchanged.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"sort"
	"strings"
)

// MemberRow is one roster entry. JSON matches the client's MemberEntry
// (camelCase): account, login, role, addedBy, addedAt.
type MemberRow struct {
	Account string `json:"account"`
	Login   string `json:"login"`
	Role    string `json:"role"`
	AddedBy string `json:"addedBy"`
	AddedAt int64  `json:"addedAt"`
}

// Role ranks: owner > admin > contributor > viewer. -1 = not a valid role.
func roleRank(role string) int {
	switch role {
	case "owner":
		return 3
	case "admin":
		return 2
	case "contributor":
		return 1
	case "viewer":
		return 0
	default:
		return -1
	}
}

const (
	rankViewer      = 0
	rankContributor = 1
	rankAdmin       = 2
)

// membershipFromEnv reports whether the membership feature is enabled.
func membershipFromEnv() bool {
	v := strings.TrimSpace(os.Getenv("HIVE_RELAY_MEMBERSHIP"))
	return v == "1" || strings.EqualFold(v, "true")
}

// callerAccount is the token subject the roster is keyed on. Empty when the
// entitlement carries no identity (open policy) — mutations then 401.
func callerAccount(claims *TokenClaims) string {
	if claims == nil {
		return ""
	}
	return strings.TrimSpace(claims.Sub)
}

// ── memoryStore membership ───────────────────────────────────────────────────

func (s *memoryStore) ClaimWorkspace(_ context.Context, workspace, account, login string, now int64) (bool, error) {
	if account == "" {
		return false, errors.New("claim requires an identified caller")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	w := s.workspace(workspace)
	if w.members == nil {
		w.members = map[string]*MemberRow{}
	}
	if len(w.members) > 0 {
		return false, nil // already claimed — no change
	}
	w.members[account] = &MemberRow{Account: account, Login: login, Role: "owner", AddedBy: account, AddedAt: now}
	return true, nil
}

func (s *memoryStore) WorkspaceMembers(_ context.Context, workspace string) ([]MemberRow, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []MemberRow{}
	if w := s.workspaces[workspace]; w != nil {
		for _, m := range w.members {
			out = append(out, *m)
		}
	}
	// Stable order (by rank desc, then account) so listings + tests are deterministic.
	sort.Slice(out, func(i, j int) bool {
		if roleRank(out[i].Role) != roleRank(out[j].Role) {
			return roleRank(out[i].Role) > roleRank(out[j].Role)
		}
		return out[i].Account < out[j].Account
	})
	return out, nil
}

func (s *memoryStore) UpsertMember(_ context.Context, workspace, account, login, role, addedBy string, now int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	w := s.workspace(workspace)
	if w.members == nil {
		w.members = map[string]*MemberRow{}
	}
	if existing := w.members[account]; existing != nil {
		existing.Login = login
		existing.Role = role
		return nil
	}
	w.members[account] = &MemberRow{Account: account, Login: login, Role: role, AddedBy: addedBy, AddedAt: now}
	return nil
}

func (s *memoryStore) RemoveMember(_ context.Context, workspace, account string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if w := s.workspaces[workspace]; w != nil {
		delete(w.members, account)
	}
	return nil
}

func (s *memoryStore) MemberRole(_ context.Context, workspace, account string) (string, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if w := s.workspaces[workspace]; w != nil {
		if m := w.members[account]; m != nil {
			return m.Role, true, nil
		}
	}
	return "", false, nil
}

// ── membership guard (WriteGuard + ReadGuard) ────────────────────────────────

// membershipGuard enforces the roster. It is content-blind: it reads only the
// roster + the token subject, never the body. An unclaimed workspace (empty
// roster) is allowed for everyone — so enabling the feature never breaks a
// workspace until it is explicitly claimed.
type membershipGuard struct{ store Store }

func (g membershipGuard) CheckWrite(ctx context.Context, workspace string, claims *TokenClaims, _ *http.Request) error {
	return g.check(ctx, workspace, claims, rankContributor)
}

func (g membershipGuard) CheckRead(ctx context.Context, workspace string, claims *TokenClaims, _ *http.Request) error {
	return g.check(ctx, workspace, claims, rankViewer)
}

func (g membershipGuard) check(ctx context.Context, workspace string, claims *TokenClaims, minRank int) error {
	members, err := g.store.WorkspaceMembers(ctx, workspace)
	if err != nil {
		return err
	}
	if len(members) == 0 {
		return nil // unclaimed → open, content-blind (default behavior)
	}
	account := callerAccount(claims)
	if account == "" {
		return errors.New("this workspace requires an identified access token")
	}
	role, ok, err := g.store.MemberRole(ctx, workspace, account)
	if err != nil {
		return err
	}
	if !ok || roleRank(role) < minRank {
		return errors.New("not authorized for this workspace")
	}
	return nil
}

// ── HTTP handlers ─────────────────────────────────────────────────────────────

// requireRole verifies the caller is a member of `workspace` with role >= min.
func (s *Server) requireRole(ctx context.Context, workspace, account string, min int) error {
	role, ok, err := s.store.MemberRole(ctx, workspace, account)
	if err != nil {
		return err
	}
	if !ok || roleRank(role) < min {
		return errors.New("forbidden")
	}
	return nil
}

// GET /v1/workspaces/{id}/members — the roster (entitlement-gated; a member set
// is metadata, and the client needs it to render + bootstrap).
func (s *Server) membersList(w http.ResponseWriter, r *http.Request) {
	members, err := s.store.WorkspaceMembers(r.Context(), r.PathValue("id"))
	if storeErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, members)
}

// POST /v1/workspaces/{id}/members — add or change a member's role. Caller must
// be Admin+ of the workspace (an identified token).
func (s *Server) memberUpsert(w http.ResponseWriter, r *http.Request) {
	ws := r.PathValue("id")
	caller := callerAccount(claimsFrom(r.Context()))
	if caller == "" {
		http.Error(w, "requires an identified access token", http.StatusUnauthorized)
		return
	}
	var body struct {
		Account string `json:"account"`
		Login   string `json:"login"`
		Role    string `json:"role"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	body.Account = strings.TrimSpace(body.Account)
	if body.Account == "" || roleRank(body.Role) < 0 {
		http.Error(w, "account and a valid role are required", http.StatusBadRequest)
		return
	}
	if err := s.requireRole(r.Context(), ws, caller, rankAdmin); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := s.store.UpsertMember(r.Context(), ws, body.Account, body.Login, body.Role, caller, nowUnix()); storeErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// DELETE /v1/workspaces/{id}/members/{account} — remove a member. Caller must be
// Admin+; the sole Owner can't be removed (mirrors the client's last-owner
// protection so the workspace can't be orphaned).
func (s *Server) memberRemove(w http.ResponseWriter, r *http.Request) {
	ws := r.PathValue("id")
	account := r.PathValue("account")
	caller := callerAccount(claimsFrom(r.Context()))
	if caller == "" {
		http.Error(w, "requires an identified access token", http.StatusUnauthorized)
		return
	}
	if err := s.requireRole(r.Context(), ws, caller, rankAdmin); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	members, err := s.store.WorkspaceMembers(r.Context(), ws)
	if storeErr(w, err) {
		return
	}
	if isLastOwner(members, account) {
		http.Error(w, "can't remove the workspace's last owner", http.StatusConflict)
		return
	}
	if err := s.store.RemoveMember(r.Context(), ws, account); storeErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// POST /v1/workspaces/{id}/members/claim — the first identified caller becomes
// Owner. 200 on a successful claim; 409 if already claimed (the client reads
// success=claimed).
func (s *Server) membershipClaim(w http.ResponseWriter, r *http.Request) {
	ws := r.PathValue("id")
	caller := callerAccount(claimsFrom(r.Context()))
	if caller == "" {
		http.Error(w, "requires an identified access token", http.StatusUnauthorized)
		return
	}
	// Optional {login} body; tolerate an empty/absent body.
	var body struct {
		Login string `json:"login"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	claimed, err := s.store.ClaimWorkspace(r.Context(), ws, caller, body.Login, nowUnix())
	if storeErr(w, err) {
		return
	}
	if !claimed {
		http.Error(w, "workspace already claimed", http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"claimed": true})
}

// isLastOwner reports whether `account` is the only Owner in the roster.
func isLastOwner(members []MemberRow, account string) bool {
	owners := 0
	targetIsOwner := false
	for _, m := range members {
		if m.Role == "owner" {
			owners++
			if m.Account == account {
				targetIsOwner = true
			}
		}
	}
	return targetIsOwner && owners <= 1
}
