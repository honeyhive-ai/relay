// Package apns sends token-authenticated (.p8) HTTP/2 pushes to the Apple
// Push Notification service.
//
// Hive pushes are content-blind (hive-tunnel/1 §14): the payload carries only
// the opaque ciphertext the user's host produced (ChaCha20-Poly1305 under a
// key the host and phone derived at enrollment) plus a generic fallback alert,
// with mutable-content: 1 so the app's Notification Service Extension decrypts
// and rewrites the alert on the device. The sender never sees plaintext. The
// body is exactly the spec's:
//
//	{"aps":{"alert":{"title":"Hive","body":"New activity on your host"},"mutable-content":1},
//	 "hive":{"v":1,"hid":"<host_id>","pid":"<pid>","ct":"<b64u(nonce ‖ ciphertext)>"}}
//
// APNs only accepts a push signed with a key from the Apple developer team
// that publishes the app (Topic = its bundle id). A relay can therefore push
// only to builds of the app its operator publishes.
package apns

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// APNs endpoints.
const (
	ProductionURL = "https://api.push.apple.com"
	SandboxURL    = "https://api.sandbox.push.apple.com"
)

// MaxPayloadBytes is APNs' limit for a regular (non-VoIP) push.
const MaxPayloadBytes = 4096

// Apple requires refreshing the provider token between 20 and 60 minutes.
const tokenLifetime = 50 * time.Minute

var b64 = base64.RawURLEncoding

// Message is one push to one device.
type Message struct {
	DeviceToken string    // hex
	Sandbox     bool      // the token belongs to the development (sandbox) environment
	HostID      string    // spec host_id, so the extension picks the right push key
	PID         string    // spec pid
	Ciphertext  []byte    // opaque E2E payload from the host: nonce ‖ AEAD ciphertext
	CollapseID  string    // optional, ≤ 64 bytes (opaque, host-chosen)
	Priority    int       // 10 (immediate) or 5 (power-considerate); anything else = 10
	Expiration  time.Time // zero = no apns-expiration header
}

// Result is APNs' answer.
type Result struct {
	Status int
	APNsID string
	Reason string
}

// OK reports a 200.
func (r Result) OK() bool { return r.Status == http.StatusOK }

// DeviceGone reports that the device token should be forgotten: 410
// Unregistered, or a token APNs calls malformed or not for this topic.
func (r Result) DeviceGone() bool {
	return r.Status == http.StatusGone || r.Reason == "BadDeviceToken" ||
		r.Reason == "DeviceTokenNotForTopic" || r.Reason == "Unregistered"
}

// Client is an APNs provider using token-based (.p8) authentication.
type Client struct {
	KeyID  string
	TeamID string
	Topic  string // the app's bundle id
	Key    *ecdsa.PrivateKey

	// AlertTitle/AlertBody are the generic fallback shown when the extension
	// can't decrypt. They must never carry user content.
	AlertTitle string
	AlertBody  string

	HTTP          *http.Client // must speak HTTP/2 (the default transport does over TLS)
	ProductionURL string       // overrides, for tests
	SandboxURL    string
	Now           func() time.Time

	mu        sync.Mutex
	token     string
	tokenTime time.Time
}

// New builds a client with an HTTP/2-capable transport.
func New(keyID, teamID, topic string, key *ecdsa.PrivateKey) *Client {
	return &Client{
		KeyID: keyID, TeamID: teamID, Topic: topic, Key: key,
		HTTP: &http.Client{
			Timeout:   15 * time.Second,
			Transport: &http.Transport{ForceAttemptHTTP2: true, MaxIdleConnsPerHost: 4, IdleConnTimeout: 5 * time.Minute},
		},
	}
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// providerToken returns a cached provider JWT, minting a new one when stale
// or when forced (after APNs rejected the cached one).
func (c *Client) providerToken(force bool) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if !force && c.token != "" && now.Sub(c.tokenTime) < tokenLifetime {
		return c.token, nil
	}
	tok, err := signJWT(c.Key, c.KeyID, c.TeamID, now.Unix())
	if err != nil {
		return "", err
	}
	c.token, c.tokenTime = tok, now
	return tok, nil
}

type payload struct {
	APS struct {
		Alert          map[string]string `json:"alert"`
		MutableContent int               `json:"mutable-content"`
	} `json:"aps"`
	Hive struct {
		V   int    `json:"v"`
		HID string `json:"hid"`
		PID string `json:"pid"`
		CT  string `json:"ct"` // base64url, no padding
	} `json:"hive"`
}

// BuildPayload returns the JSON body for m.
func (c *Client) BuildPayload(m Message) ([]byte, error) {
	if len(m.Ciphertext) == 0 {
		return nil, errors.New("apns: empty ciphertext")
	}
	title, body := c.AlertTitle, c.AlertBody
	if title == "" {
		title = "Hive"
	}
	if body == "" {
		body = "New activity on your host"
	}
	var p payload
	p.APS.Alert = map[string]string{"title": title, "body": body}
	p.APS.MutableContent = 1
	p.Hive.V, p.Hive.HID, p.Hive.PID, p.Hive.CT = 1, m.HostID, m.PID, b64.EncodeToString(m.Ciphertext)
	b, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxPayloadBytes {
		return nil, fmt.Errorf("apns: payload %d bytes exceeds %d", len(b), MaxPayloadBytes)
	}
	return b, nil
}

// ValidDeviceToken reports whether s looks like an APNs device token (hex).
func ValidDeviceToken(s string) bool {
	if len(s) < 64 || len(s) > 200 || len(s)%2 != 0 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// Send delivers one message. A 403 ExpiredProviderToken/InvalidProviderToken
// is retried once with a fresh provider token. A transport error is returned
// as err; an APNs rejection is a Result with !OK().
func (c *Client) Send(ctx context.Context, m Message) (Result, error) {
	if c.Key == nil || c.KeyID == "" || c.TeamID == "" || c.Topic == "" {
		return Result{}, errors.New("apns: not configured")
	}
	if !ValidDeviceToken(m.DeviceToken) {
		return Result{Status: http.StatusBadRequest, Reason: "BadDeviceToken"}, nil
	}
	body, err := c.BuildPayload(m)
	if err != nil {
		return Result{}, err
	}
	res, err := c.send(ctx, m, body, false)
	if err == nil && res.Status == http.StatusForbidden && (res.Reason == "ExpiredProviderToken" || res.Reason == "InvalidProviderToken") {
		res, err = c.send(ctx, m, body, true)
	}
	return res, err
}

func (c *Client) send(ctx context.Context, m Message, body []byte, freshToken bool) (Result, error) {
	tok, err := c.providerToken(freshToken)
	if err != nil {
		return Result{}, err
	}
	base := c.ProductionURL
	if base == "" {
		base = ProductionURL
	}
	if m.Sandbox {
		base = c.SandboxURL
		if base == "" {
			base = SandboxURL
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(base, "/")+"/3/device/"+strings.ToLower(m.DeviceToken), bytes.NewReader(body))
	if err != nil {
		return Result{}, err
	}
	prio := m.Priority
	if prio != 5 {
		prio = 10
	}
	req.Header.Set("authorization", "bearer "+tok)
	req.Header.Set("apns-topic", c.Topic)
	req.Header.Set("apns-push-type", "alert")
	req.Header.Set("apns-priority", strconv.Itoa(prio))
	req.Header.Set("content-type", "application/json")
	if !m.Expiration.IsZero() {
		req.Header.Set("apns-expiration", strconv.FormatInt(m.Expiration.Unix(), 10))
	}
	if m.CollapseID != "" {
		req.Header.Set("apns-collapse-id", m.CollapseID)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()
	res := Result{Status: resp.StatusCode, APNsID: resp.Header.Get("apns-id")}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Reason string `json:"reason"`
		}
		_ = json.Unmarshal(b, &e)
		res.Reason = e.Reason
	}
	return res, nil
}

// ── Keys and provider tokens ──

// ParseP8 parses an Apple-issued .p8 key (a PKCS#8 PEM holding a P-256 key).
// A SEC1 "EC PRIVATE KEY" PEM is accepted too.
func ParseP8(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("apns: no PEM block in key")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		ec, err2 := x509.ParseECPrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("apns: parse key: %w", err)
		}
		k = ec
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("apns: key is not an ECDSA P-256 key")
	}
	return ec, nil
}

// signJWT mints the provider token: {"alg":"ES256","kid":keyID}.{"iss":teamID,"iat":iat},
// signed with the JOSE raw r‖s form (not ASN.1 DER).
func signJWT(key *ecdsa.PrivateKey, keyID, teamID string, iat int64) (string, error) {
	hb, err := json.Marshal(map[string]any{"alg": "ES256", "kid": keyID})
	if err != nil {
		return "", err
	}
	cb, err := json.Marshal(map[string]any{"iss": teamID, "iat": iat})
	if err != nil {
		return "", err
	}
	signing := b64.EncodeToString(hb) + "." + b64.EncodeToString(cb)
	d := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, key, d[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signing + "." + b64.EncodeToString(sig), nil
}
