package relay

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Operator subcommands. The serving relay only ever *verifies* tokens (with the
// public key); these mint them and live on the issuer backend. Keep the
// private key off the relay host entirely — only the public key ships to it as
// HIVE_RELAY_TOKEN_PUBKEY.

func printUsage() {
	fmt.Fprint(os.Stderr, `hive-relay — hosted rendezvous + forwarding relay

Run the server (default):   hive-relay
Generate an issuer keypair: hive-relay keygen
Mint an entitlement token:  hive-relay issue --key <priv-hex> --sub <id> \
                              [--plan team] [--exp-days 365] [--max-members 50] \
                              [--turn] [--cap remove_member --cap rotate_key]
Bootstrap a remote agent:   hive-relay bootstrap-agent --key <priv-hex> \
                              --relay <url> --room <room> --ws-key <passphrase> \
                              --sub github:<agent-id> --admin-sub github:<owner-id> \
                              [--role contributor] [--label agent] [--exp-days 365]
                            → prints one copy-paste line the dev runs on the box.

Set the relay's HIVE_RELAY_TOKEN_PUBKEY to the keygen public key; keep the
private key with your issuer backend only.
`)
}

// cmdKeygen prints a fresh Ed25519 issuer keypair (32-byte seed as hex, matching
// the format `issue --key` and HIVE_RELAY_TOKEN_PUBKEY expect).
func cmdKeygen() error {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	seed := priv.Seed()
	pub := priv.Public().(ed25519.PublicKey)
	fmt.Println("# Ed25519 issuer keypair")
	fmt.Printf("private_key=%s   # SECRET — keep on the issuer only (never on the relay)\n", hex.EncodeToString(seed))
	fmt.Printf("public_key=%s    # set as HIVE_RELAY_TOKEN_PUBKEY on the relay\n", hex.EncodeToString(pub))
	return nil
}

// cmdIssue signs an entitlement token for a customer.
func cmdIssue(args []string) error {
	var (
		keyHex  string
		claims        = TokenClaims{Caps: []string{}}
		expDays int64 = -1
	)
	for i := 0; i < len(args); i++ {
		next := func() string {
			if i+1 < len(args) {
				i++
				return args[i]
			}
			return ""
		}
		switch args[i] {
		case "--key":
			keyHex = next()
		case "--sub":
			claims.Sub = next()
		case "--plan":
			claims.Plan = next()
		case "--exp-days":
			expDays, _ = strconv.ParseInt(next(), 10, 64)
		case "--max-members":
			if n, err := strconv.ParseUint(next(), 10, 32); err == nil {
				v := uint32(n)
				claims.MaxMembers = &v
			}
		case "--retention-days":
			if n, err := strconv.ParseUint(next(), 10, 32); err == nil {
				v := uint32(n)
				claims.RetentionDays = &v
			}
		case "--turn":
			claims.Turn = true
		case "--cap":
			claims.Caps = append(claims.Caps, next())
		default:
			return fmt.Errorf("unknown flag %s (try `hive-relay help`)", args[i])
		}
	}

	priv, ok := parseSigningKey(keyHex)
	if !ok {
		return fmt.Errorf("--key must be a 64-char hex Ed25519 seed (from `keygen`)")
	}
	if strings.TrimSpace(claims.Sub) == "" {
		return fmt.Errorf("--sub <account-or-org-id> is required")
	}
	if expDays >= 0 {
		claims.Exp = uint64(time.Now().Unix()) + uint64(expDays)*86_400
	}
	fmt.Println(issueToken(priv, claims))
	return nil
}

// cmdBootstrapAgent generates a single copy-paste command that stands up a
// headless agent on a remote box. It mints the agent's identity token, best-
// effort enrolls it in the workspace roster (with --admin-sub), and assembles
// the `hivews1:` connection invite — then prints one `brew … && hive enroll …
// && hive worker …` line the developer runs verbatim. The issuer private key
// stays here (the issuer backend); only the minted agent token leaves.
func cmdBootstrapAgent(args []string) error {
	var keyHex, relay, room, wsKey, sub, adminSub, label string
	role := "contributor"
	var expDays int64 = 365
	for i := 0; i < len(args); i++ {
		next := func() string {
			if i+1 < len(args) {
				i++
				return args[i]
			}
			return ""
		}
		switch args[i] {
		case "--key":
			keyHex = next()
		case "--relay":
			relay = next()
		case "--room":
			room = next()
		case "--ws-key":
			wsKey = next()
		case "--sub":
			sub = next()
		case "--admin-sub":
			adminSub = next()
		case "--role":
			role = next()
		case "--label":
			label = next()
		case "--exp-days":
			expDays, _ = strconv.ParseInt(next(), 10, 64)
		default:
			return fmt.Errorf("unknown flag %s (try `hive-relay help`)", args[i])
		}
	}
	priv, ok := parseSigningKey(keyHex)
	if !ok {
		return fmt.Errorf("--key must be a 64-char hex Ed25519 seed (from `keygen`)")
	}
	if relay == "" || room == "" || sub == "" {
		return fmt.Errorf("--relay, --room, and --sub are required")
	}
	if label == "" {
		label = strings.NewReplacer(":", "-", "/", "-").Replace(sub)
	}
	now := time.Now().Unix()
	relay = strings.TrimRight(relay, "/")

	// Best-effort: enroll the agent in the roster via a transient admin token.
	enrolled := false
	if adminSub != "" {
		adminTok := issueToken(priv, TokenClaims{Sub: adminSub, Exp: uint64(now) + 3600})
		body, _ := json.Marshal(map[string]string{"account": sub, "login": "", "role": role})
		req, _ := http.NewRequest(http.MethodPost, relay+"/v1/workspaces/"+room+"/members", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+adminTok)
		req.Header.Set("Content-Type", "application/json")
		if resp, err := http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
			enrolled = resp.StatusCode == http.StatusOK
		}
	}

	// Mint the agent's identity token.
	claims := TokenClaims{Sub: sub, Plan: "agent", Caps: []string{}}
	if expDays >= 0 {
		claims.Exp = uint64(now) + uint64(expDays)*86_400
	}
	tok := issueToken(priv, claims)

	// Assemble the hivews1 connection invite (snake_case, matching the app).
	conn := map[string]string{"relay_url": relay, "room": room}
	if wsKey != "" {
		conn["key"] = wsKey
	}
	cj, _ := json.Marshal(conn)
	invite := "hivews1:" + base64.RawURLEncoding.EncodeToString(cj)

	// The one line the developer pastes on the remote box.
	fmt.Println("# Run on the remote agent box:")
	fmt.Printf("brew install honeyhive-ai/hive/hive-cli && \\\n")
	fmt.Printf("  hive enroll %q --token %q && \\\n", invite, tok)
	fmt.Printf("  hive worker --label %s\n", label)

	switch {
	case adminSub != "" && enrolled:
		fmt.Fprintf(os.Stderr, "\n# Enrolled %s as %s in %s.\n", sub, role, room)
	case adminSub != "":
		fmt.Fprintf(os.Stderr, "\n# NOTE: roster enrollment failed — is --admin-sub an owner/admin and the workspace claimed? Add %s via the People pane, or run `hive join <code>` on the box.\n", sub)
	default:
		fmt.Fprintf(os.Stderr, "\n# NOTE: pass --admin-sub <owner-id> to auto-enroll, or add %s via the People pane. Without roster membership, writes to a claimed workspace are refused.\n", sub)
	}
	return nil
}

// parseSigningKey parses a 64-char-hex Ed25519 seed into a private key.
func parseSigningKey(h string) (ed25519.PrivateKey, bool) {
	h = strings.TrimSpace(h)
	if len(h) != 64 || !isHex(h) {
		return nil, false
	}
	seed, err := hex.DecodeString(h)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, false
	}
	return ed25519.NewKeyFromSeed(seed), true
}

// issueToken mints a compact hrt1 token (the inverse of verifyToken).
func issueToken(priv ed25519.PrivateKey, claims TokenClaims) string {
	body := tokenPrefix + "." + base64.RawURLEncoding.EncodeToString(mustJSON(claims))
	sig := ed25519.Sign(priv, []byte(body))
	return body + "." + base64.RawURLEncoding.EncodeToString(sig)
}
