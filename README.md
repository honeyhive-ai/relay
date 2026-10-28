# hive-relay

A small, **content-blind** rendezvous + envelope-forwarding server for Hive.
Clients post opaque (end-to-end encrypted) event envelopes keyed by workspace
and fetch everything after a cursor; the relay also brokers short pairing codes,
an identity directory, a poll-based account inbox, the friend graph, and
presence. **It never sees plaintext.**

This is the production relay (Go). It speaks the same JSON `/v1` contract and
`hrt1` entitlement-token format as the original Rust reference relay
(`crates/hive-relay`), which is now kept only as an in-process test fixture for
the Rust client.

## Run

```sh
go run ./cmd/hive-relay            # serves on :8443 (in-memory)
# or build:
go build -o hive-relay ./cmd/hive-relay && ./hive-relay
```

Operator commands (mint/verify signed entitlement tokens — the serving relay
only ever *verifies*):

```sh
hive-relay keygen                  # prints an Ed25519 issuer keypair
hive-relay issue --key <priv-hex> --sub <id> --plan team --exp-days 365 \
  --max-members 50 --turn --cap remove_member
```

## Configuration (env)

| Var | Meaning |
|---|---|
| `PORT` / `HIVE_RELAY_ADDR` | bind address (`$PORT` wins; default `0.0.0.0:8443`) |
| `DATABASE_URL` | shared **Postgres** store → horizontal scaling / HA (no data migration) |
| `HIVE_RELAY_DATA_DIR` | in-memory store + JSON snapshot here (single instance). Ignored if `DATABASE_URL` is set |
| `HIVE_RELAY_TOKEN_PUBKEY` | Ed25519 public key → require **signed** entitlement tokens |
| `HIVE_RELAY_ACCESS_TOKENS` | comma-separated static allowlist (coarse gate) |
| `HIVE_RELAY_FRIEND_CAP` | max accepted friends per account |
| `HIVE_RELAY_MAX_ENVELOPES` | per-workspace retained-envelope cap for the memory store (default `50000`; `0` = unbounded) |
| `HIVE_RELAY_RETENTION_DAYS` | prune memory-store envelopes older than N days (default `0` = age pruning off) |
| `HIVE_RELAY_MAX_BODY_BYTES` | max JSON request-body size in bytes (default `4194304` = 4 MiB) |
| `HIVE_RELAY_TUNNEL` | relay tunnel (phone ↔ home host): `off` (**default**, `/v1/tunnel/*` → 404), `open` (any host may register), `allowlist` (only `HIVE_RELAY_TUNNEL_HOSTS`). See [Relay tunnel](#relay-tunnel-hive-tunnel1) |
| `HIVE_RELAY_TUNNEL_HOSTS` | comma-separated `host_id`s admitted when `HIVE_RELAY_TUNNEL=allowlist` |
| `HIVE_RELAY_APNS_KEY_FILE` | APNs auth key (`AuthKey_<KEYID>.p8`) for the built-in push sender; or `HIVE_RELAY_APNS_KEY` with the PEM inline (`\n` escapes allowed). Push is **off** unless the key and the three vars below are all set. See [Push from your own relay](#push-from-your-own-relay) |
| `HIVE_RELAY_APNS_KEY_ID` / `HIVE_RELAY_APNS_TEAM_ID` | the key's Key ID and your Apple developer Team ID |
| `HIVE_RELAY_APNS_TOPIC` | bundle id of the iPhone app build you publish (the APNs topic) |
| `HIVE_RELAY_APNS_ENV` | `auto` (**default**: the environment each phone reports with its token: `development` → sandbox, `production` → production), `sandbox` or `production` |

Storage selection: `DATABASE_URL` → Postgres; else `HIVE_RELAY_DATA_DIR` →
memory+snapshot; else in-memory only.

## Test

```sh
go test ./...                                  # unit + HTTP + snapshot + seams
TEST_DATABASE_URL=postgres://… go test ./...   # also runs Postgres integration
```

## Deploy

A tiny static binary in a ~10 MB Alpine image — any container host works.
Clients require `https://`, so terminate TLS at the platform edge or a reverse
proxy.

### Docker (anywhere)

```sh
docker build -t hive-relay .            # or straight from GitHub:
# docker build -t hive-relay https://github.com/honeyhive-ai/relay.git
docker run -d -p 8443:8443 -v hive-data:/data -e HIVE_RELAY_DATA_DIR=/data hive-relay
curl localhost:8443/v1/health           # → ok
```

### Managed platforms

No lock-in — it's a standard container. The binary honors `$PORT` (else
`$HIVE_RELAY_ADDR`, else `0.0.0.0:8443`), so most PaaS work with zero config:
point Render / Railway / Cloud Run / Kubernetes / a VM at the image (or the
Dockerfile), attach a disk at `/data`, and set `HIVE_RELAY_DATA_DIR=/data`.

A sample **`deploy/fly.toml`** is included as one worked example (`fly launch
--copy-config --no-deploy` → `fly volumes create hive_data …` → `fly deploy`) —
adapt it, or use your platform's equivalent.

### TLS

Clients need `https://` — either let your platform terminate TLS at its edge, or
run any reverse proxy (Caddy example):

```caddyfile
relay.example.com {
    reverse_proxy localhost:8443
}
```

### Persistence & scaling

- **Single instance:** mount a volume at `/data` and set `HIVE_RELAY_DATA_DIR=/data`
  (JSON snapshot store; survives restarts). Nothing to back up but that volume.
- **HA / multiple instances:** set `DATABASE_URL` to a shared Postgres — it takes
  precedence over the snapshot dir, so every instance shares state (no migration).

#### Envelope retention (memory store)

The in-memory / snapshot store bounds how many envelopes it keeps per workspace
so a long-running self-host doesn't grow without limit and eventually OOM. By
default each workspace retains its newest `HIVE_RELAY_MAX_ENVELOPES` (50 000)
envelopes; set `HIVE_RELAY_RETENTION_DAYS` to also drop envelopes older than N
days. Set either to `0` to disable that bound (`0` for both = unbounded, the old
behavior).

**Tradeoff (vs. offline catch-up):** clients sync by fetching everything after a
cursor (`?after=seq`). The relay is a cache of *recent* E2EE traffic, not the
source of truth — pruning below a cursor means a device offline longer than the
retention window can't replay the gap from the relay and must re-sync from a peer
that still holds history. Size the bounds above your expected offline window. For
unbounded, always-catch-up history, use the Postgres backend (disk-bound, not
retained in RAM) instead.

### Live push (Server-Sent Events)

`GET /v1/workspaces/{id}/events` (`Content-Type: text/event-stream`) lets a
client wake instantly on new traffic instead of polling on a timer. It is a
content-blind **nudge** channel — never envelope bodies:

- on connect: `: connected` (a comment), then optionally `data: {"seq":<head>}`;
- on every new envelope appended to the workspace: `data: {"seq":<newSeq>}` —
  the client pulls with its own `?after=` cursor over `GET /envelopes`;
- every ~25s idle: a `: keep-alive` comment to survive proxy idle timeouts.

Read-authorized exactly like the other workspace reads (`enforceRead`). Fan-out
is **single-instance / in-process** today; cross-instance push (Postgres
`LISTEN/NOTIFY`) is tracked as a follow-up, and multi-instance deployments keep
the `?after=` poll as the backstop.

### Optional access gating

Open by default (self-host — the URL isn't a secret). To gate:

- **Allowlist:** `HIVE_RELAY_ACCESS_TOKENS=tokA,tokB` (opaque bearer tokens).
- **Signed tokens:** set `HIVE_RELAY_TOKEN_PUBKEY=<hex>` and mint per-subject
  tokens with `hive-relay keygen` / `hive-relay issue` — keep the issuer private
  key off the relay host (the relay only ever verifies).
- **Durable users + tokens:** manage per-person access over the admin API
  (below) instead of an env list — no redeploy, survives restarts, instant
  revocation. Pair it with `StoreEntitlementVerifier` to make the store the
  access gate.

Gating applies symmetrically to **reads and writes**: both `GET`
(envelopes / keyring / presence / candidates) and `POST` on a workspace require
the same entitlement (`enforceRead` mirrors `enforceWrite`). Under a token-gated
policy an unauthenticated read is `401`; under the open policy reads stay open,
just like writes. This is a coarse, content-blind token gate — it checks the
presented entitlement, never the body — so workspace ciphertext + keyring are no
longer readable by anyone who merely learns a workspace id. Clients already send
their access token on every request, so no client change is needed.

**Deferred (known, needs a product decision — not implemented here):**

- *Per-member read authorization.* The token gate is coarse: any entitled caller
  may read any workspace. Restricting *which member* may read *which workspace*
  needs the enterprise membership seam (the read-side analogue of `WriteGuard`)
  and is out of scope for the coarse gate.
- *High-entropy workspace ids.* Clients today derive a workspace id from a
  possibly-guessable room *name*. Making ids high-entropy (so an id can't be
  guessed at all) is a client-side + invite-model change, not a relay change.

### User/token admin API (`/v1/admin/*`)

The relay has a durable user + token store (both backends implement it) and a
management API, gated by the `AdminAuthorizer` seam. It's **disabled by
default** (no authorizer → `404`); supply one via `Options{AdminAuth: …}` to
enable it. Tokens are stored only as SHA-256 hashes; the raw value is returned
once at creation.

- `POST /v1/admin/users` `{name, login?}` → create user + first token (raw once)
- `GET /v1/admin/users` → users + their tokens (no hashes)
- `POST /v1/admin/users/{id}/tokens` `{label?}` → another token (raw once)
- `POST /v1/admin/users/{id}/disabled` `{disabled}` → enable/disable a user
- `DELETE /v1/admin/tokens/{id}` → revoke a token

### Status page

`GET /` serves a small public HTML status page ("Hive relay · online") so a
human who opens the URL sees an intentional page rather than a `401`. `GET
/v1/health` round-trips the store and returns `200 ok`, or `503` if the backend
is unreachable — wire it to your orchestrator's liveness/readiness probe.
Everything else is token-gated.

### Relay tunnel (`hive-tunnel/1`)

Lets the Hive iPhone app reach a `hive serve` home host through the relay —
no VPN, no inbound port on the host. The relay checks **who may connect** and
then forwards opaque bytes: phone and host run a Noise IK session end to end
through it, so the relay can't read, alter or forge traffic, and can't
impersonate either side. The protocol is open; the spec lives in the Hive repo
(`docs/relay-tunnel.md`, with golden vectors in `docs/relay-tunnel/`).

**Off by default.** A relay upgraded to this version does not become a public
tunnel provider. Enable it with `HIVE_RELAY_TUNNEL=open` (any host may
register) or `HIVE_RELAY_TUNNEL=allowlist` + `HIVE_RELAY_TUNNEL_HOSTS=<host_id>,…`.
When the relay's entitlement gate is configured (`HIVE_RELAY_TOKEN_PUBKEY` /
`HIVE_RELAY_ACCESS_TOKENS`), a host's first registration must also present a
token that passes it (`hive remote enable --reg-token …`).

Endpoints (WebSockets require the subprotocol `hive-tunnel.1`, else `426`;
they authenticate themselves, so they bypass the bearer-token gate):

| Route | Who | What |
|---|---|---|
| `GET /v1/tunnel/info` | anyone | `{"versions":[1],"push":bool,"billing":"none"}` (`404` when off) |
| `GET /v1/tunnel/host` | host | control socket: Ed25519-signed challenge; `host_id = H(host key)`, registered implicitly on first connect |
| `GET /v1/tunnel/accept?sid=…` | host | one data socket per phone session (`sid` is single-use, valid 10 s) |
| `GET /v1/tunnel/connect?host=…` | phone | host-signed `hpc1` credential + proof-of-possession signature (or a pairing-window tag to enroll), then a 1:1 splice to the host |

What the relay stores (both backends; part of the snapshot / database):
registered hosts `(host_id, pub, created_at, last_seen)`, revoked phones
`(host_id, pid, exp)` until their credentials would have expired, and APNs push
tokens. It never holds a key that opens session traffic.

Limits (spec defaults): 8 KiB text / 65 535 B binary messages; 8 concurrent
sessions per host and 3 per phone; 60 sessions opened per host per minute; 30
connects per IP per minute, and 10 failed auths per minute blocks the IP for
5 minutes; 2 enrollment windows per host (≤ 15 min, 5 attempts each);
enrollment sessions capped at 5 min / 4 MiB; 20 control messages per second.
Every tunnel socket is pinged every 20 s and closed after 60 s of silence; the
`http.Server` read/write timeouts are cleared on upgrade. On shutdown every
tunnel socket is closed with `4011 shutting_down` (wired via
`http.Server.RegisterOnShutdown(srv.ShutdownTunnels)`).

**One instance per host.** Live control connections are kept in process: run a
single relay instance for the tunnel, or route `/v1/tunnel/connect?host=H` and
`/v1/tunnel/accept` to the instance holding H's control connection.

**Self-hosting the tunnel.** `HIVE_RELAY_TUNNEL=open` gives your own relay the
same remote access the paid hosted relay offers, for free: every registered
host is `active`. `GET /v1/tunnel/info` then reports `"billing":"none"`, and
the Hive app uses that to skip its subscription paywall (it shows "ask the
relay operator" on `4006` instead). Only the hosted build reports
`"billing":"appstore"`.

**Push on a self-hosted relay.** Without a `PushSender` host pushes are acked
`push_unavailable`, and `hive serve` falls back to ntfy when it's configured.
APNs only accepts a push signed with a key from the Apple developer team that
publishes the app, so a relay can push only to builds of the Hive app its
operator publishes (see below). It can't push to someone else's App Store
build. Proposed (not built): an optional push gateway run by the app's
publisher that accepts the same end-to-end encrypted `ct` from a self-hosted
relay and forwards it to APNs, so the gateway sees only ciphertext plus the
device token. It would need its own abuse controls (a per-relay key and rate
limits).

### Push from your own relay

If you build and sign the iPhone app under your own Apple developer account,
your relay can push to it with the built-in APNs sender:

1. In the Apple developer portal (Certificates, Identifiers & Profiles → Keys)
   create a key with **Apple Push Notifications service (APNs)** enabled.
   Download the `.p8` once and keep it secret; note its Key ID and your Team ID.
2. Run the relay with the tunnel on and the key configured:

   ```sh
   HIVE_RELAY_TUNNEL=open \
   HIVE_RELAY_APNS_KEY_FILE=/secrets/AuthKey_ABC123DEFG.p8 \
   HIVE_RELAY_APNS_KEY_ID=ABC123DEFG \
   HIVE_RELAY_APNS_TEAM_ID=<your team id> \
   HIVE_RELAY_APNS_TOPIC=<your app's bundle id> \
   hive-relay
   ```

   The relay logs `tunnel push via APNs (topic …, env auto)`, and
   `GET /v1/tunnel/info` and the host's `welcome` report `"push": true`. An
   incomplete configuration or a key that doesn't parse is logged and leaves
   push off; the relay still starts.
3. Build the app with push enabled (the iOS repo's docs), pair the phone with a
   host that uses this relay, and allow notifications.

The relay forwards the host's ciphertext untouched in the spec §14 payload
(`{"aps":{"alert":{"title":"Hive","body":"New activity on your host"},"mutable-content":1},"hive":{…,"ct":…}}`)
with `apns-push-type: alert`, priority 10 (`high`) or 5 (`normal`),
`apns-expiration` now + 1 h and the host's opaque collapse id. When APNs says
a device token is dead (`410 Unregistered`, `BadDeviceToken`,
`DeviceTokenNotForTopic`) the relay forgets it; the phone sends a fresh one
on its next connect. One relay serves one topic, so point
`HIVE_RELAY_APNS_TOPIC` at the build you use (a dev build and an App Store
build have different bundle ids). With `HIVE_RELAY_APNS_ENV=auto` a debug
build from Xcode (sandbox token) and a TestFlight/App Store build
(production token) both work.

Hosted deployments inject their own `TunnelPolicy` (entitlement: hosts can be
`pending` — enrollment works, sessions get `4006`; pending hosts unseen for 30
days are forgotten) and an APNs `PushSender`, through `MainWith` (below).

## Extending (seams)

This package is a complete relay on its own. It also exposes extension points
(see `seams.go`) so a downstream build can add custom behavior via
`New(Options{...})` without forking.

A downstream binary that must behave exactly like `cmd/hive-relay` plus a few
additions (for example a hosted build that shares an app with the open relay)
calls `relay.MainWith(relay.Extension{...})` instead of `relay.Main()`.
Storage, env, the entitlement gate, every open route, subcommands and shutdown
are the open binary's; the extension can only set the tunnel seams, serve extra
routes under `/v1/<name>/` prefixes the relay doesn't use, and add
subcommands. If its setup fails, the relay logs it and serves as the open
binary. `relay.Assemble` builds the same handler without a listener, for
side-by-side tests.

Seams:

- **`Store`** — durable backend (in-memory/snapshot or Postgres built in);
  includes the user/token store behind the admin API.
- **`EntitlementVerifier`** — admission policy (open / allowlist / signed from
  env, `StoreEntitlementVerifier` for managed tokens, or your own).
- **`AdminAuthorizer`** — gates `/v1/admin/*` user management (`nil` = disabled).
- **`WriteGuard`** — optional pre-write authorization hook (`nil` = content-blind).
- **`Hooks`** — optional lifecycle observers (e.g. audit / accounting; no-op by
  default).
- **`TunnelPolicy`** / **`PushSender`** — relay-tunnel host admission and
  entitlement (`nil` = `HIVE_RELAY_TUNNEL` env policy), and end-to-end
  encrypted push delivery (`nil` = the built-in APNs sender when
  `HIVE_RELAY_APNS_*` is set, else unavailable). The sender itself is the
  importable `github.com/honeyhive-ai/relay/apns` package; a sender that wraps
  `relay.ErrPushTokenGone` makes the relay forget that phone's token. A `Store` that also implements
  `TunnelStore` keeps tunnel state durable (both built-in backends do).

## License

MIT — see `LICENSE`.
