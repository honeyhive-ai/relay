package relay

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/honeyhive-ai/relay/apns"
)

// Built-in APNs PushSender (spec §14) for a relay run by the app's publisher.
//
// APNs accepts a push only when it's signed with a key from the Apple
// developer team that publishes the app, so this is useful only to someone
// who builds and signs the iPhone app under their own team (and points
// HIVE_RELAY_APNS_TOPIC at that build's bundle id). It's off unless
// configured; then GET /v1/tunnel/info and the host's welcome report
// "push": true. The relay only ever forwards the host's ciphertext.
//
//	HIVE_RELAY_APNS_KEY_FILE  path to the AuthKey_<KEYID>.p8 file (or HIVE_RELAY_APNS_KEY: the PEM inline, "\n" escapes allowed)
//	HIVE_RELAY_APNS_KEY_ID    the key's 10-character Key ID
//	HIVE_RELAY_APNS_TEAM_ID   the Apple developer Team ID
//	HIVE_RELAY_APNS_TOPIC     the app's bundle id
//	HIVE_RELAY_APNS_ENV       auto (default: the environment the phone reports with its token) | sandbox | production

// ErrPushTokenGone is returned (wrapped) by a PushSender when the push
// service says the device token is no longer valid. The relay then forgets
// the phone's token; the phone re-registers on its next connect.
var ErrPushTokenGone = errors.New("push: device token is gone")

// APNs environment selection for HIVE_RELAY_APNS_ENV.
const (
	APNsEnvAuto       = "auto"
	APNsEnvSandbox    = "sandbox"
	APNsEnvProduction = "production"
)

// APNsPushSender forwards an encrypted push to APNs.
type APNsPushSender struct {
	Client *apns.Client
	// Env is auto (use the token's reported env), sandbox or production.
	Env string
	// TTL becomes apns-expiration (spec: now + 1 h). Zero = 1 h.
	TTL time.Duration
}

// Send implements PushSender.
func (s *APNsPushSender) Send(ctx context.Context, hostID, pid string, tok PushToken, ct []byte, prio, collapse string) error {
	sandbox := tok.Env == "development"
	switch s.Env {
	case APNsEnvSandbox:
		sandbox = true
	case APNsEnvProduction:
		sandbox = false
	}
	ttl := s.TTL
	if ttl <= 0 {
		ttl = time.Hour
	}
	p := 10
	if prio == "normal" {
		p = 5
	}
	now := time.Now()
	if s.Client.Now != nil {
		now = s.Client.Now()
	}
	res, err := s.Client.Send(ctx, apns.Message{
		DeviceToken: tok.Token, Sandbox: sandbox, HostID: hostID, PID: pid,
		Ciphertext: ct, CollapseID: collapse, Priority: p, Expiration: now.Add(ttl),
	})
	if err != nil {
		return err
	}
	if res.DeviceGone() {
		return fmt.Errorf("%w (%d %s)", ErrPushTokenGone, res.Status, res.Reason)
	}
	if !res.OK() {
		return fmt.Errorf("apns: %d %s", res.Status, res.Reason)
	}
	return nil
}

// APNsPushSenderFromEnv builds the built-in sender from HIVE_RELAY_APNS_*.
// It returns (nil, nil) when none of them is set, and an error when the
// configuration is incomplete or the key doesn't parse (push then stays off).
func APNsPushSenderFromEnv() (*APNsPushSender, error) {
	return apnsPushSenderFrom(os.Getenv)
}

func apnsPushSenderFrom(getenv func(string) string) (*APNsPushSender, error) {
	get := func(k string) string { return strings.TrimSpace(getenv(k)) }
	keyFile, keyPEM := get("HIVE_RELAY_APNS_KEY_FILE"), get("HIVE_RELAY_APNS_KEY")
	keyID, teamID, topic, env := get("HIVE_RELAY_APNS_KEY_ID"), get("HIVE_RELAY_APNS_TEAM_ID"), get("HIVE_RELAY_APNS_TOPIC"), strings.ToLower(get("HIVE_RELAY_APNS_ENV"))
	if keyFile == "" && keyPEM == "" && keyID == "" && teamID == "" && topic == "" {
		return nil, nil
	}
	var missing []string
	if keyFile == "" && keyPEM == "" {
		missing = append(missing, "HIVE_RELAY_APNS_KEY_FILE")
	}
	for _, kv := range [][2]string{{"HIVE_RELAY_APNS_KEY_ID", keyID}, {"HIVE_RELAY_APNS_TEAM_ID", teamID}, {"HIVE_RELAY_APNS_TOPIC", topic}} {
		if kv[1] == "" {
			missing = append(missing, kv[0])
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("APNs push is partly configured; missing %s", strings.Join(missing, ", "))
	}
	switch env {
	case "":
		env = APNsEnvAuto
	case APNsEnvAuto, APNsEnvSandbox, APNsEnvProduction:
	case "development":
		env = APNsEnvSandbox
	default:
		return nil, fmt.Errorf("HIVE_RELAY_APNS_ENV=%q is not auto|sandbox|production", env)
	}
	var pemBytes []byte
	if keyPEM != "" {
		pemBytes = []byte(strings.ReplaceAll(keyPEM, `\n`, "\n"))
	} else {
		b, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("HIVE_RELAY_APNS_KEY_FILE: %w", err)
		}
		pemBytes = b
	}
	key, err := apns.ParseP8(pemBytes)
	if err != nil {
		// Never echo the key material.
		return nil, errors.New("APNs key doesn't parse as a .p8 (PKCS#8 P-256) key")
	}
	return &APNsPushSender{Client: apns.New(keyID, teamID, topic, key), Env: env}, nil
}

// pushSenderFromEnv is New's fallback when Options.PushSender is nil and the
// tunnel is on. A misconfiguration is logged and leaves push off.
func pushSenderFromEnv() PushSender {
	s, err := APNsPushSenderFromEnv()
	if err != nil {
		fmt.Fprintf(os.Stderr, "hive-relay: %v; tunnel push stays off\n", err)
		return nil
	}
	if s == nil {
		return nil
	}
	fmt.Fprintf(os.Stderr, "hive-relay: tunnel push via APNs (topic %s, env %s)\n", s.Client.Topic, s.Env)
	return s
}
