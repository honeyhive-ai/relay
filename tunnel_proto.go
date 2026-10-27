package relay

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// hive-tunnel/1 wire primitives: identifiers, domain separation, the hpc1 phone
// credential and the relay close codes. See README "Relay tunnel" and the
// protocol spec (hive repo, docs/relay-tunnel.md). Nothing in this file touches
// end-to-end content: the relay verifies who may connect and forwards bytes.

const (
	tunnelSubprotocol = "hive-tunnel.1"
	tunnelVersion     = 1
	tunnelLabel       = "hive-tunnel/1"
	credPrefix        = "hpc1"

	// tunnelIDLen is the length of a b64u-encoded 16-byte id (host_id, pid,
	// sid, eid).
	tunnelIDLen = 22
)

// tunnelCode is a relay close code plus its wire `code` string (spec §12).
type tunnelCode struct {
	Close int
	Code  string
}

var (
	tcProtocol           = tunnelCode{4000, "protocol"}
	tcUnauthorized       = tunnelCode{4001, "unauthorized"}
	tcCredentialExpired  = tunnelCode{4002, "credential_expired"}
	tcRevoked            = tunnelCode{4003, "revoked"}
	tcHostUnknown        = tunnelCode{4004, "host_unknown"}
	tcNotEntitled        = tunnelCode{4006, "not_entitled"}
	tcHostOffline        = tunnelCode{4008, "host_offline"}
	tcSuperseded         = tunnelCode{4009, "superseded"}
	tcHostRejected       = tunnelCode{4010, "host_rejected"}
	tcShuttingDown       = tunnelCode{4011, "shutting_down"}
	tcTimeout            = tunnelCode{4012, "timeout"}
	tcUnsupportedVersion = tunnelCode{4026, "unsupported_version"}
	tcRateLimited        = tunnelCode{4029, "rate_limited"}
	// tcInternal is WebSocket 1011: a relay-side failure (e.g. the store is
	// unreachable). Not in the spec's table; clients treat it like 4011.
	tcInternal = tunnelCode{1011, "internal"}
)

// tunnelError is a relay-layer failure carrying the close code to send.
type tunnelError struct {
	tc  tunnelCode
	msg string
}

func (e *tunnelError) Error() string { return e.tc.Code + ": " + e.msg }

func terr(tc tunnelCode, format string, a ...any) *tunnelError {
	return &tunnelError{tc: tc, msg: fmt.Sprintf(format, a...)}
}

// b64uDecode decodes base64url WITHOUT padding, strictly: padding, whitespace
// (which encoding/base64 would silently skip), any non-alphabet character and
// non-canonical trailing bits are all rejected (spec §2).
func b64uDecode(s string) ([]byte, error) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return nil, errors.New("invalid base64url character")
		}
	}
	return base64.RawURLEncoding.Strict().DecodeString(s)
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// b64uFixed decodes s and requires exactly n bytes.
func b64uFixed(s string, n int) ([]byte, bool) {
	b, err := b64uDecode(s)
	if err != nil || len(b) != n {
		return nil, false
	}
	return b, true
}

// validTunnelID reports whether s is a well-formed 16-byte b64u id.
func validTunnelID(s string) bool {
	if len(s) != tunnelIDLen {
		return false
	}
	_, ok := b64uFixed(s, 16)
	return ok
}

// tunnelCtx builds the domain-separation input
// ASCII("hive-tunnel/1 " + label) ‖ 0x00 ‖ p1 ‖ p2 ‖ … (spec §2).
func tunnelCtx(label string, parts ...[]byte) []byte {
	out := append([]byte(tunnelLabel+" "+label), 0x00)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// TunnelHostID derives the self-certifying host id from a host signing key:
// b64u(SHA256(ctx("host-id", host_sign_pub))[0..16]) (spec §3).
func TunnelHostID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(tunnelCtx("host-id", pub))
	return b64u(sum[:16])
}

// PhoneCredential is a verified hpc1 credential.
type PhoneCredential struct {
	HostID   string
	PID      string
	PhoneKey ed25519.PublicKey
	IssuedAt int64
	Expires  int64
}

const (
	tunnelSkewSecs      = 300
	credMaxLifetimeSecs = 400 * 24 * 60 * 60
)

// verifyPhoneCredential checks an hpc1 credential in the order of spec §5,
// steps 1–5 (revocation, step 6, is the caller's store lookup). hostKey returns
// the registered signing key of a host, or ok=false when the host is unknown.
func verifyPhoneCredential(tok, hostQuery string, hostKey func(hostID string) (ed25519.PublicKey, bool, error), now int64) (PhoneCredential, *tunnelError) {
	// 1. Shape: three parts, hpc1 prefix, 64-byte signature.
	parts := strings.Split(tok, ".")
	if len(parts) != 3 || parts[0] != credPrefix {
		return PhoneCredential{}, terr(tcUnauthorized, "malformed credential")
	}
	sig, ok := b64uFixed(parts[2], ed25519.SignatureSize)
	if !ok {
		return PhoneCredential{}, terr(tcUnauthorized, "malformed credential signature")
	}
	claimsJSON, err := b64uDecode(parts[1])
	if err != nil {
		return PhoneCredential{}, terr(tcUnauthorized, "malformed credential claims")
	}
	// 2. hid must name the host being connected to, and that host must exist.
	// (A lenient read only to find the key; the claims are parsed strictly in
	// step 4, after the signature is known to be good.)
	var peek struct {
		Hid string `json:"hid"`
	}
	if json.Unmarshal(claimsJSON, &peek) != nil || peek.Hid == "" || peek.Hid != hostQuery {
		return PhoneCredential{}, terr(tcUnauthorized, "credential is for another host")
	}
	pub, known, err := hostKey(hostQuery)
	if err != nil {
		return PhoneCredential{}, terr(tcInternal, "host lookup failed")
	}
	if !known {
		return PhoneCredential{}, terr(tcHostUnknown, "no such registered host")
	}
	// 3. Signature over the exact transmitted bytes.
	if !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		return PhoneCredential{}, terr(tcUnauthorized, "bad credential signature")
	}
	// 4. Strict claims.
	if err := jsonNoDuplicateKeys(claimsJSON); err != nil {
		return PhoneCredential{}, terr(tcUnauthorized, "credential claims: %v", err)
	}
	var c struct {
		Hid *string      `json:"hid"`
		Pid *string      `json:"pid"`
		Pk  *string      `json:"pk"`
		Iat *json.Number `json:"iat"`
		Exp *json.Number `json:"exp"`
	}
	dec := json.NewDecoder(bytes.NewReader(claimsJSON))
	dec.UseNumber()
	if err := dec.Decode(&c); err != nil {
		return PhoneCredential{}, terr(tcUnauthorized, "credential claims do not parse")
	}
	if c.Hid == nil || c.Pid == nil || c.Pk == nil || c.Iat == nil || c.Exp == nil {
		return PhoneCredential{}, terr(tcUnauthorized, "credential claims incomplete")
	}
	if !validTunnelID(*c.Hid) || *c.Hid != hostQuery || !validTunnelID(*c.Pid) {
		return PhoneCredential{}, terr(tcUnauthorized, "credential ids malformed")
	}
	pk, ok := b64uFixed(*c.Pk, ed25519.PublicKeySize)
	if !ok {
		return PhoneCredential{}, terr(tcUnauthorized, "credential pk malformed")
	}
	iat, err1 := strconv.ParseInt(c.Iat.String(), 10, 64)
	exp, err2 := strconv.ParseInt(c.Exp.String(), 10, 64)
	if err1 != nil || err2 != nil {
		return PhoneCredential{}, terr(tcUnauthorized, "credential times malformed")
	}
	// 5. Times.
	if iat > now+tunnelSkewSecs {
		return PhoneCredential{}, terr(tcUnauthorized, "credential issued in the future")
	}
	if exp <= now {
		return PhoneCredential{}, terr(tcCredentialExpired, "credential expired")
	}
	if exp-iat > credMaxLifetimeSecs || exp <= iat {
		return PhoneCredential{}, terr(tcUnauthorized, "credential lifetime exceeds the relay cap")
	}
	return PhoneCredential{HostID: *c.Hid, PID: *c.Pid, PhoneKey: ed25519.PublicKey(pk), IssuedAt: iat, Expires: exp}, nil
}

// jsonNoDuplicateKeys rejects a JSON document that is not a single value or
// that repeats a key in any object (spec §2: verifiers of signed JSON MUST
// reject duplicates).
func jsonNoDuplicateKeys(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := walkJSONValue(dec, 0); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data")
	}
	return nil
}

func walkJSONValue(dec *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("too deeply nested")
	}
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil // scalar
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return err
			}
			k, _ := kt.(string)
			if _, dup := seen[k]; dup {
				return fmt.Errorf("duplicate key %q", k)
			}
			seen[k] = struct{}{}
			if err := walkJSONValue(dec, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := walkJSONValue(dec, depth+1); err != nil {
				return err
			}
		}
	}
	_, err = dec.Token() // closing delimiter
	return err
}
