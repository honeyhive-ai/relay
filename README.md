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

## Extending (seams)

This package is a complete relay on its own. It also exposes extension points
(see `seams.go`) so a downstream build can add custom behavior via
`New(Options{...})` without forking:

- **`Store`** — durable backend (in-memory/snapshot or Postgres built in);
  includes the user/token store behind the admin API.
- **`EntitlementVerifier`** — admission policy (open / allowlist / signed from
  env, `StoreEntitlementVerifier` for managed tokens, or your own).
- **`AdminAuthorizer`** — gates `/v1/admin/*` user management (`nil` = disabled).
- **`WriteGuard`** — optional pre-write authorization hook (`nil` = content-blind).
- **`Hooks`** — optional lifecycle observers (e.g. audit / accounting; no-op by
  default).

## License

MIT — see `LICENSE`.
