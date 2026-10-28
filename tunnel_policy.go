package relay

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Tunnel seams (spec §15.1). The open build wires TunnelPolicyFromEnv and, when
// HIVE_RELAY_APNS_* is configured, the built-in APNs PushSender (push_apns.go);
// a hosted downstream build injects its own through Options.

// HostStatus is a registered host's entitlement. !Active means "pending": the
// host may hold its control connection and enroll phones, but phone sessions
// are refused with not_entitled (4006).
type HostStatus struct {
	Active bool
	// MaxSessions caps concurrent phone sessions for the host (0 = relay default).
	MaxSessions int
}

// TunnelPolicy admits host registrations and reports entitlement. The relay
// caches Status results for at most 60 s.
type TunnelPolicy interface {
	// Register runs the first time a host_id completes the control handshake.
	// A non-nil error refuses the registration (unauthorized, 4001).
	Register(ctx context.Context, hostID string, hostPub ed25519.PublicKey, regToken string) error
	// Status reports the host's entitlement. An error refuses the host outright
	// (control: 4001; phone connect: 4006).
	Status(ctx context.Context, hostID string) (HostStatus, error)
}

// PushToken is a phone's APNs device token, stored per (host_id, pid).
type PushToken struct {
	Token string `json:"token"` // hex
	Env   string `json:"env"`   // "production" | "development"
}

// PushSender delivers an already-encrypted push (spec §14). nil = push
// unavailable: the relay acks host pushes with ok:false "push_unavailable".
type PushSender interface {
	Send(ctx context.Context, hostID, pid string, token PushToken, ct []byte, prio, collapse string) error
}

// ErrTunnelHostNotAllowed is returned by the env policy for a host that isn't
// on the HIVE_RELAY_TUNNEL_HOSTS allowlist.
var ErrTunnelHostNotAllowed = errors.New("tunnel: host is not on the allowlist")

// ErrTunnelRegistrationToken is returned when the relay's entitlement gate is
// configured and the hello's registration token doesn't pass it.
var ErrTunnelRegistrationToken = errors.New("tunnel: registration token rejected")

// Tunnel modes for HIVE_RELAY_TUNNEL.
const (
	TunnelOff       = "off"
	TunnelOpen      = "open"
	TunnelAllowlist = "allowlist"
)

// envTunnelPolicy is the open build's policy: every admitted host is active.
type envTunnelPolicy struct {
	mode  string
	hosts map[string]bool // allowlist mode
	// ent, when non-nil, must admit the hello's registration token (reuses the
	// relay's hrt1 / access-token gate). The open entitlement admits anything.
	ent EntitlementVerifier
}

// TunnelPolicyFromEnv returns the open build's policy from HIVE_RELAY_TUNNEL
// (off|open|allowlist, default off) and HIVE_RELAY_TUNNEL_HOSTS, with the
// registration token checked against EntitlementFromEnv(). It returns nil when
// the tunnel is off: /v1/tunnel/* then answers 404.
func TunnelPolicyFromEnv() TunnelPolicy { return tunnelPolicyFromEnv(EntitlementFromEnv()) }

func tunnelPolicyFromEnv(ent EntitlementVerifier) TunnelPolicy {
	p, err := newEnvTunnelPolicy(os.Getenv("HIVE_RELAY_TUNNEL"), os.Getenv("HIVE_RELAY_TUNNEL_HOSTS"), ent)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hive-relay: %v; the tunnel stays off\n", err)
		return nil
	}
	if p == nil {
		return nil
	}
	return p
}

// newEnvTunnelPolicy parses the mode; (nil, nil) means off.
func newEnvTunnelPolicy(mode, hostList string, ent EntitlementVerifier) (*envTunnelPolicy, error) {
	switch m := strings.ToLower(strings.TrimSpace(mode)); m {
	case "", TunnelOff:
		return nil, nil
	case TunnelOpen:
		return &envTunnelPolicy{mode: m, ent: ent}, nil
	case TunnelAllowlist:
		hosts := map[string]bool{}
		for _, h := range strings.Split(hostList, ",") {
			if h = strings.TrimSpace(h); h != "" {
				if !validTunnelID(h) {
					return nil, fmt.Errorf("HIVE_RELAY_TUNNEL_HOSTS: %q is not a host_id", h)
				}
				hosts[h] = true
			}
		}
		if len(hosts) == 0 {
			return nil, errors.New("HIVE_RELAY_TUNNEL=allowlist but HIVE_RELAY_TUNNEL_HOSTS is empty")
		}
		return &envTunnelPolicy{mode: m, hosts: hosts, ent: ent}, nil
	default:
		return nil, fmt.Errorf("HIVE_RELAY_TUNNEL=%q is not off|open|allowlist", mode)
	}
}

func (p *envTunnelPolicy) allowed(hostID string) bool {
	return p.mode == TunnelOpen || p.hosts[hostID]
}

func (p *envTunnelPolicy) Register(_ context.Context, hostID string, _ ed25519.PublicKey, regToken string) error {
	if !p.allowed(hostID) {
		return ErrTunnelHostNotAllowed
	}
	if p.ent != nil {
		if _, ok := p.ent.Allow(regToken, nowUnix()); !ok {
			return ErrTunnelRegistrationToken
		}
	}
	return nil
}

func (p *envTunnelPolicy) Status(_ context.Context, hostID string) (HostStatus, error) {
	if !p.allowed(hostID) {
		return HostStatus{}, ErrTunnelHostNotAllowed
	}
	return HostStatus{Active: true}, nil
}
