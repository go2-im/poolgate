# Running poolgate (Phase 2a walking skeleton)

This is the Phase 2a walking skeleton: one **manually-imported** encrypted account,
a single `fallback` policy, one `sk-` inbound key, one endpoint, and the
translation-gateway proxy for `POST /e/<endpoint>/v1/responses`. No admin UI,
passkey, health engine, or notifications yet (those are later phases). See
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
`fallback` policy group over the imported account, a `default` endpoint, and one
`sk-` inbound key. **The key is printed once — store it now.**

## 3. Serve

Starts the proxy listener (loopback `127.0.0.1:8787` by default) with the
translation gateway plus `/healthz` and `/readyz`.

```sh
./poolgate serve
```

Health checks (unauthenticated, secret-free):

```sh
curl -s http://127.0.0.1:8787/healthz        # {"status":"ok"}
curl -s http://127.0.0.1:8787/readyz         # {"status":"ready"} once ≥1 endpoint has an eligible account
```

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
