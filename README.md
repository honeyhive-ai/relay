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

### Fly.io (always-on, free-tier friendly)

`deploy/fly.toml` is ready to go:

```sh
fly launch --copy-config --no-deploy    # pick an app name + region
fly volumes create hive_data --size 1 --region <region>
fly deploy
fly status                              # → https://<app>.fly.dev
```

Fly terminates TLS at its edge, so clients get an `https://` URL for free.

### TLS on a plain VM (Caddy example)

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

### Optional access gating

Open by default (self-host — the URL isn't a secret). To gate:

- **Allowlist:** `HIVE_RELAY_ACCESS_TOKENS=tokA,tokB` (opaque bearer tokens).
- **Signed tokens:** set `HIVE_RELAY_TOKEN_PUBKEY=<hex>` and mint per-subject
  tokens with `hive-relay keygen` / `hive-relay issue` — keep the issuer private
  key off the relay host (the relay only ever verifies).

## Extending (seams)

This package is a complete relay on its own. It also exposes extension points
(see `seams.go`) so a downstream build can add custom behavior via
`New(Options{...})` without forking:

- **`Store`** — durable backend (in-memory/snapshot or Postgres built in).
- **`EntitlementVerifier`** — admission policy (open / allowlist / signed from
  env, or your own).
- **`WriteGuard`** — optional pre-write authorization hook (`nil` = content-blind).
- **`Hooks`** — optional lifecycle observers (e.g. audit / accounting; no-op by
  default).

## License

MIT — see `LICENSE`.
