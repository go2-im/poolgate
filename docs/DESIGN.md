# poolgate — Design

> Living design doc. Reflects decisions made during planning; expect it to evolve before/while scaffolding.

## 1. Goal & scope

A **single-user**, self-hostable tool that:

1. Manages a **pool of Codex/ChatGPT accounts** (import via OAuth or `~/.codex/auth.json`, view usage, refresh tokens).
2. Exposes them as **OpenAI-compatible `/v1`** endpoints.
3. Routes each request through a **composable policy engine** (Surge-style) so the caller can choose a strategy by hitting a specific proxy URL.
4. Is managed through a **web admin UI** protected by **passkey** login.

**Non-goals:** multi-tenant/team accounts, reselling access, an outbound public tunnel (removed by decision — remote access is via the operator's own reverse proxy).

## 2. Deployment modes (both supported from day one)

| Mode | Bind | Admin auth | TLS |
|------|------|-----------|-----|
| **Local** | `127.0.0.1` | passkey (RP ID `localhost`; WebAuthn treats `http://localhost` as a secure context, so no TLS needed) | none |
| **Remote (self-hosted)** | `127.0.0.1`, fronted by **your** reverse proxy (Caddy/nginx) | passkey (RP ID = your domain) | terminated at the reverse proxy |

The binary itself never opens outbound tunnels. "Remote" = you put it behind your own TLS reverse proxy.

> WebAuthn passkeys are bound to the RP ID (domain). A passkey registered on `localhost` will not work on `your.domain` and vice-versa — register one per environment (or one hardware key registered in each). RP ID / origin are config.

## 3. Architecture — one Go binary, two listeners

```
┌──────────────────────────────────────────────────────────────┐
│ poolgate (single Go binary, embeds the built web UI)          │
│                                                                │
│  Admin server   default 127.0.0.1:7070   (never auto-exposed) │
│    • WebUI static assets (go:embed of web/dist)                │
│    • Management REST API (accounts / groups / endpoints /      │
│      keys / usage / settings)                                  │
│    • Auth: passkey (WebAuthn) -> session cookie + CSRF         │
│                                                                │
│  Proxy server   default 127.0.0.1:8787   (may be bound wider,  │
│    • OpenAI-compatible /e/<endpoint>/v1/*   explicitly + warned)│
│    • Inbound auth: sk- API keys (constant-time), key->endpoint │
│      scoping                                                   │
│    • Runs each request through the policy engine               │
│                                                                │
│  Shared core packages:                                         │
│    config · store(SQLite, encrypted secrets) · oauth · usage · │
│    policy(engine) · proxy(forwarder) · auth(webauthn+keys)     │
└──────────────────────────────────────────────────────────────┘
```

Splitting Admin and Proxy into separate listeners lets you expose the proxy to your LAN/reverse-proxy while keeping the admin surface loopback-only.

## 4. Policy engine (Surge-inspired)

Three entities:

- **Account** — a pooled Codex/ChatGPT credential (the leaf "proxy"). Carries health state (`ok` / `cooldown` / `expired`), last usage snapshot (5h / 1week windows, plan), and optional measured latency.
- **PolicyGroup** — named, has a `type` (strategy) and an **ordered member list**; each member is an Account **or another PolicyGroup** (nesting → a DAG; cycles rejected). Strategies:
  - `select` — manually pinned member.
  - `fallback` — first healthy in order; on 401/429/5xx/timeout advance + cooldown the failed member.
  - `round-robin` — rotate across healthy members.
  - `load-balance` — distribute (round-robin or weighted).
  - `url-test` — periodic health/latency probe; route to lowest-latency healthy member (interval configurable).
  - `best-quota` — route to the member with the most remaining usage (≈ codex-tools `switch --best`).
- **Endpoint** — a named inbound route bound to one PolicyGroup, surfaced as a distinct URL: `/e/<endpoint>/v1/...`. The caller picks a strategy by choosing the URL. API keys can be scoped to specific endpoints.

Composition example:
```
endpoint "prod"  -> group "balanced" (load-balance)
                       ├─ group "teamA" (fallback): acct1 -> acct2
                       └─ group "teamB" (fallback): acct3 -> acct4
endpoint "fast"  -> group "low-latency" (url-test): acct1, acct3, acct5
```

Request flow: inbound key auth → resolve endpoint → group → engine selects an Account (skipping unhealthy) → attach `Authorization: Bearer <access_token>` + `ChatGPT-Account-Id` → forward to the pinned upstream (see §6) → on failure, engine may re-select per strategy. SSE/streaming responses are relayed with per-chunk flush.

## 5. Storage — SQLite (pure-Go), encrypted secrets

- **Engine:** `modernc.org/sqlite` (pure Go, no CGO) → trivial cross-compilation, single binary. WAL mode, `busy_timeout`.
- **Why a DB, not just JSON:** config data (accounts/groups/endpoints/keys/passkeys) is small, but **request/usage logs + per-key/per-account stats grow** and need indexed aggregation for the UI; the policy engine's health updates and admin edits need transactional consistency under concurrent proxy load.
- **Encryption at rest:** secret columns (access/refresh tokens, etc.) are **field-encrypted** with `nacl/secretbox` (or `age`) before insert — SQLCipher would require CGO, so we do app-level field encryption instead. Master key from **OS keychain** (macOS Keychain / Windows DPAPI) preferred, else keyfile / env; never stored in plaintext next to the DB.
- **Retention:** request/usage log tables are periodically pruned; keeps the DB small even under heavy use.
- **Tables (initial):** `accounts`, `policy_groups`, `group_members`, `endpoints`, `api_keys`, `key_scopes`, `webauthn_credentials`, `usage_snapshots`, `request_logs`, `audit_log`, `settings`.

## 6. Egress hardening

- **Upstream pinned** to `chatgpt.com` / `api.openai.com` by default; any override is an explicit poolgate config value validated against a **host allowlist** (never read silently from an external file).
- **OAuth issuer pinned** to `https://auth.openai.com`; the `iss` claim inside imported tokens is **ignored** for building the refresh URL.
- Any outbound request carrying `Authorization` whose host is not on the allowlist is refused.

## 7. Config (YAML) — seed & export

The UI is the source of truth (writes to SQLite); YAML is used to seed on first run and to export/back up. Sketch:

```yaml
server:
  admin: { host: 127.0.0.1, port: 7070, rp_id: localhost, rp_origin: "http://localhost:7070" }
  proxy: { host: 127.0.0.1, port: 8787 }
security:
  master_key_source: keychain   # keychain | keyfile | env
  upstream_allowlist: ["chatgpt.com", "api.openai.com"]
groups:
  teamA: { type: fallback, members: [acct_1, acct_2] }
  balanced: { type: load-balance, members: [teamA, teamB] }
  fast: { type: url-test, members: [acct_1, acct_3], interval: 300 }
endpoints:
  prod: { group: balanced }
  fast: { group: fast }
# accounts and api keys are managed in the UI / store, not usually in YAML
```

## 8. Tech choices

- Backend: **Go 1.23**, `net/http` (Go 1.22 mux) or `chi`.
- SQLite: `modernc.org/sqlite`.
- WebAuthn: `github.com/go-webauthn/webauthn`.
- Crypto: `nacl/secretbox` (field encryption), `argon2id` (only if a password fallback is ever added — default is passkey-only + recovery codes).
- Reverse proxy: `net/http/httputil.ReverseProxy` (FlushInterval=-1 for SSE) or manual relay.
- Frontend: **React** (Vite), built to static assets, embedded via `go:embed`.
- Config: **YAML**.

## 9. Build phases

1. **Core:** `config`, `store` (SQLite + field encryption; encrypt/decrypt round-trip test), `oauth` (login/import/refresh, issuer pinned).
2. **Policy + proxy:** `policy` engine (strategies + nesting + cycle check + health), `proxy` server (`/e/<ep>/v1`, sk- auth, SSE, egress allowlist).
3. **Admin API + passkey:** WebAuthn register/login (bootstrap token, multiple passkeys, recovery codes, `admin reset-auth` CLI), session + CSRF, CRUD for accounts/groups/endpoints/keys.
4. **Web UI:** React pages (login, dashboard/usage, accounts, policy groups w/ composition view, endpoints, keys, settings), `go:embed`.
5. **Release:** cross-compiled single binary, SHA256SUMS + signature, SLSA provenance, SHA-pinned CI, no silent auto-update, `docs/BUILD.md`.
6. **Optional:** usage charts, account cooldown tuning, weighted load-balance.

## 10. Development model

Bare-repo + git worktrees: `poolgate/.bare` is the hub; `poolgate/main` is the main worktree; feature work happens in sibling worktrees (e.g. `poolgate/scaffold` on branch `feat/scaffold`). Remote will be added to `.bare` later.
