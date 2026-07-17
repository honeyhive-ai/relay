package relay

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

// Durable relay users + access tokens.
//
// This replaces the env-var token allowlist (HIVE_RELAY_USER_TOKENS) with a
// store-backed model an operator manages over an admin API: create a user,
// issue them a token (shown once), list, revoke — no redeploy, and it survives
// restarts. Tokens are stored only as SHA-256 hashes; the raw token is returned
// exactly once at issue time and never persisted. A StoreEntitlementVerifier
// turns the store into the relay's EntitlementVerifier, so tokens managed here
// gate access the same way env tokens did.
//
// The admin API itself is gated by the AdminAuthorizer seam (see seams.go) —
// the open build leaves it unset (admin API disabled); a downstream build
// (e.g. hive-relay-enterprise) supplies a GitHub-admin-allowlist authorizer.

// UserRecord is a person who may hold relay access tokens.
type UserRecord struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Login     string `json:"login,omitempty"` // optional GitHub handle
	Disabled  bool   `json:"disabled"`
	CreatedAt int64  `json:"createdAt"`
}

// TokenRecord is one issued access token (hash only; never the raw value).
type TokenRecord struct {
	ID        string `json:"id"`
	UserID    string `json:"userId"`
	Label     string `json:"label,omitempty"`
	CreatedAt int64  `json:"createdAt"`
	LastUsed  int64  `json:"lastUsed,omitempty"`
	RevokedAt *int64 `json:"revokedAt,omitempty"`
}

// Errors surfaced by the user/token store.
var (
	ErrUserNotFound  = errors.New("user not found")
	ErrTokenNotFound = errors.New("token not found")
)

// GenerateToken returns a fresh random access token (48 hex chars = 24 bytes of
// entropy). Hand it to the user once; store only HashToken(it).
func GenerateToken() (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// HashToken is the at-rest representation of a raw token: SHA-256 hex. Deterministic
// so a presented token can be looked up by hashing it and matching.
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(raw)))
	return hex.EncodeToString(sum[:])
}

// constantTimeEq compares two hex hashes without leaking timing.
func constantTimeEq(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// StoreEntitlementVerifier admits a bearer token iff it hashes to a live
// (non-revoked, enabled-user) token in the store. Claims carry the owning
// user as Sub and "team" as the plan, so a WriteGuard / Hooks can attribute
// activity to a person — the same shape the per-person env tokens produced.
type StoreEntitlementVerifier struct {
	Store Store
	// Now overrides the clock in tests; nil = time.Now.
	Now func() int64
}

func (v StoreEntitlementVerifier) now() int64 {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now().Unix()
}

// Allow implements EntitlementVerifier.
func (v StoreEntitlementVerifier) Allow(token string, nowUnix int64) (*TokenClaims, bool) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, false
	}
	claims, ok, err := v.Store.ResolveToken(context.Background(), HashToken(token), nowUnix)
	if err != nil || !ok {
		return nil, false
	}
	return claims, true
}

// ── Admin API ────────────────────────────────────────────────────────────────
//
// Routes (registered by Handler when an AdminAuthorizer is configured):
//
//	POST   /v1/admin/users                 {name, login?} → {user, token}  (raw token, once)
//	GET    /v1/admin/users                 → [{user, tokens:[…]}]           (hashes never returned)
//	POST   /v1/admin/users/{id}/tokens     {label?}      → {token}          (raw token, once)
//	POST   /v1/admin/users/{id}/disabled   {disabled}    → {user}
//	DELETE /v1/admin/tokens/{id}           → 204
//
// Every handler first calls the AdminAuthorizer; a nil authorizer means the
// admin API is disabled (404).

func (s *Server) adminEnabled() bool { return s.adminAuth != nil }

// requireAdmin authorizes the caller or writes the appropriate status and
// returns false.
func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if s.adminAuth == nil {
		http.Error(w, "admin API not enabled", http.StatusNotFound)
		return false
	}
	if _, ok := s.adminAuth.AuthorizeAdmin(r); !ok {
		http.Error(w, "admin authorization required", http.StatusUnauthorized)
		return false
	}
	return true
}

type createUserReq struct {
	Name  string `json:"name"`
	Login string `json:"login"`
	Label string `json:"label"`
}

type issuedTokenResp struct {
	User  UserRecord  `json:"user"`
	Token TokenRecord `json:"token"`
	// Raw is the plaintext token — returned ONCE, never stored or retrievable again.
	Raw string `json:"raw"`
}

func (s *Server) adminCreateUser(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	var req createUserReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Name) == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	now := nowUnix()
	user, err := s.store.CreateUser(r.Context(), strings.TrimSpace(req.Name), strings.TrimSpace(req.Login), now)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	raw, tok, err := s.issueToken(r.Context(), user.ID, req.Label, now)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, issuedTokenResp{User: user, Token: tok, Raw: raw})
}

// UserWithTokens is a user plus their token metadata (never the raw/hash).
type UserWithTokens struct {
	UserRecord
	Tokens []TokenRecord `json:"tokens"`
}

func (s *Server) adminListUsers(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tokens, err := s.store.ListTokens(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	byUser := map[string][]TokenRecord{}
	for _, t := range tokens {
		byUser[t.UserID] = append(byUser[t.UserID], t)
	}
	out := make([]UserWithTokens, 0, len(users))
	for _, u := range users {
		out = append(out, UserWithTokens{UserRecord: u, Tokens: byUser[u.ID]})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) adminIssueToken(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	userID := r.PathValue("id")
	var req createUserReq
	_ = json.NewDecoder(r.Body).Decode(&req) // label is optional
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var user *UserRecord
	for i := range users {
		if users[i].ID == userID {
			user = &users[i]
			break
		}
	}
	if user == nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	raw, tok, err := s.issueToken(r.Context(), userID, req.Label, nowUnix())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, issuedTokenResp{User: *user, Token: tok, Raw: raw})
}

type setDisabledReq struct {
	Disabled bool `json:"disabled"`
}

func (s *Server) adminSetDisabled(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	var req setDisabledReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	if err := s.store.SetUserDisabled(r.Context(), r.PathValue("id"), req.Disabled); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, ErrUserNotFound) {
			status = http.StatusNotFound
		}
		http.Error(w, err.Error(), status)
		return
	}
	writeJSON(w, http.StatusOK, okResp())
}

func (s *Server) adminRevokeToken(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if err := s.store.RevokeToken(r.Context(), r.PathValue("id"), nowUnix()); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, ErrTokenNotFound) {
			status = http.StatusNotFound
		}
		http.Error(w, err.Error(), status)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// issueToken generates a raw token, stores its hash, and returns both the raw
// value (to show once) and the record.
func (s *Server) issueToken(ctx context.Context, userID, label string, now int64) (string, TokenRecord, error) {
	raw, err := GenerateToken()
	if err != nil {
		return "", TokenRecord{}, err
	}
	tok, err := s.store.IssueToken(ctx, userID, strings.TrimSpace(label), HashToken(raw), now)
	if err != nil {
		return "", TokenRecord{}, err
	}
	return raw, tok, nil
}
