# Running poolgate

This documents the CLI walking skeleton plus the Stage 4 wiring: a
**manually-imported** encrypted account pool, a policy group with one of three
routing **strategies** (`fallback` / `best-quota` / `load-balance`), one `sk-`
inbound key, one endpoint, the translation-gateway proxy for
`POST /e/<endpoint>/v1/responses`, and an active **health probe engine** that
keeps the pool's per-account state fresh and auto-recovers accounts. No admin UI,
passkey, or notifications yet (those are later phases). See
[`DESIGN.md`](DESIGN.md) §0 for the authoritative decisions.

## Prerequisites

- Go 1.25+ (module `github.com/go2-im/poolgate`; pure-Go SQLite, no CGO).

## Build

```sh
go build -o ./poolgate ./cmd/poolgate
```

## 1. Initialize

Creates the data dir, generates a `master.key` keyfile (`0600`), runs SQLite
migrations, and prints a short-TTL single-use admin bootstrap token. It does
**not** import any account.

```sh
export POOLGATE_DATA_DIR=./poolgate-data   # optional; defaults to ./poolgate-data
./poolgate init
```

`init` is idempotent — safe to re-run. The default `master_key_source` is
`keyfile`. To use an env-var key instead, set `master_key_source: env` in
`config.yaml` and provide `POOLGATE_MASTER_KEY` (base64 of 32 raw bytes).

## 2. Import an account (explicit — never automatic)

Import a Codex `auth.json` (the file with a `tokens` object holding
`access_token` / `refresh_token` / `account_id` / `id_token`). The access/refresh
tokens are field-encrypted (`nacl/secretbox`) before they hit the DB.

```sh
./poolgate import ~/.codex/auth.json
```

On the first import (when no endpoint exists yet) this also creates a default
policy group over the imported account, a `default` endpoint, and one `sk-`
inbound key. **The key is printed once — store it now.**

Pick the group's routing **strategy** with `--strategy` (default `fallback`):

```sh
./poolgate import ~/.codex/auth.json --strategy best-quota
```

- `fallback` — first healthy member in stored order; on failure advance to the
  next and cool the failed one down.
- `best-quota` — route to the account with the most remaining headroom (min over
  its usage windows of `100 − used_percent`); deterministic tie-break = lowest
  account id. Headroom comes from the latest usage snapshot the health engine
  records (missing snapshot = unconstrained).
- `load-balance` — round-robin across the healthy members (one persistent cursor
  per group).

Subsequent imports add the account to the pool only (the existing endpoint/group
is reused; the strategy is set once at group-creation time).

## 3. Serve

Starts the proxy listener (loopback `127.0.0.1:8787` by default) with the
translation gateway plus `/healthz` and `/readyz`, and launches the **health
scheduler loop** alongside it (a thin goroutine driven by the real clock; it
stops when the process receives SIGTERM/interrupt and the context is cancelled).

```sh
./poolgate serve
```

Health checks (unauthenticated, secret-free):

```sh
curl -s http://127.0.0.1:8787/healthz        # {"status":"ok"}
curl -s http://127.0.0.1:8787/readyz         # {"status":"ready"} once ≥1 endpoint has an eligible account
```

### Routing, failover & passive health hooks

Each inbound request resolves `endpoint → group → members`, then the policy
engine selects an account per the group's strategy over a health/usage view.
Failover is strictly **pre-first-byte** (DESIGN.md §19.2): if the upstream errors
before any byte reaches the client, the gateway records the failure and
re-selects the next candidate; once streaming starts the response is committed
and never switched. Pre-stream failures drive the health state machine:

- **401** → shared single-flight token refresh; on success the rotated token is
  retried against the same account, on failure the account is marked `expired`.
- **429** → `cooldown`, gated on the upstream `Retry-After`.
- **5xx** → `cooldown` with a conservative default delay.

When every candidate is exhausted the gateway returns
`poolgate_all_exhausted` (502); when no member was healthy to begin with it
returns `poolgate_no_healthy_account` (503).

### Health probe engine

The scheduler probes each non-terminal account on a per-state cadence (short,
backing-off intervals for degraded accounts; longer for healthy ones; terminal
`revoked`/`dead` are never probed) and **auto-recovers** an account once its
rate-limit/quota clears. Probe kinds:

- **usage-poll** (default, zero token spend) — `GET /backend-api/wham/usage` for
  quota level and reset detection.
- **auth-check** (zero token spend) — `GET {base}/models` to confirm an expired
  account's token became valid again.
- **small-live-request** (minimal spend) — opt-in only.

The global cost policy is the `health_probe_mode` config knob:

- `usage-poll-only` (default) — zero-spend probes only.
- `allow-live` — additionally permit the small-live-request for
  degraded/recovery checks, bounded by a per-account daily budget.

## 4. Send a request through the gateway

Point an OpenAI-compatible client at the endpoint URL and use the `sk-` key as
the bearer token:

```sh
curl -N http://127.0.0.1:8787/e/default/v1/responses \
  -H "Authorization: Bearer sk-...your-key..." \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-5","input":"hello"}'
```

What the gateway does on the upstream leg (translation gateway, not a transparent
proxy — DESIGN.md §0 D1 / §6):

- rewrites `Authorization: Bearer <account access_token>` **and**
  `ChatGPT-Account-ID` **together** for the chosen pooled account;
- preserves/synthesizes Codex identity headers (`originator` default
  `codex_cli_rs`, `User-Agent`, `OpenAI-Beta`);
- forces `stream:true` + `Accept: text/event-stream`;
- targets the pinned upstream `https://chatgpt.com/backend-api/codex/responses`
  (egress allowlist: `chatgpt.com` / `api.openai.com`);
- relays the SSE stream with per-chunk flush.

WebSocket upgrades are not accepted in v1 (Codex falls back to HTTP POST+SSE).

## Configuration

`config.yaml` is optional and lives in the data dir; missing keys fall back to
loopback defaults. Sketch:

```yaml
server:
  admin: { host: 127.0.0.1, port: 7070 }
  proxy: { host: 127.0.0.1, port: 8787 }
data_dir: ./poolgate-data
master_key_source: keyfile          # keyfile | env
upstream_allowlist: ["chatgpt.com", "api.openai.com"]
issuer: "https://auth.openai.com/oauth/token"   # OAuth refresh, pinned
health_probe_mode: usage-poll-only  # usage-poll-only (default) | allow-live
```

Environment overrides:

- `POOLGATE_DATA_DIR` — data directory for all subcommands.
- `POOLGATE_MASTER_KEY` — base64 master key when `master_key_source: env`.

## Test

```sh
go build ./...
go test ./...
go test -race ./internal/oauth ./internal/gateway ./cmd/poolgate
```

The `cmd/poolgate` integration test (`main_test.go`) exercises the full
init → import → serve-wiring → proxy path against an in-process fake upstream,
asserting the header rewrite, forced streaming, and SSE relay.
