# Running poolgate

This documents the CLI walking skeleton plus the Stage 4/5 wiring: a
**manually-imported** encrypted account pool, a policy group with one of three
routing **strategies** (`fallback` / `best-quota` / `load-balance`), one `sk-`
inbound key, one endpoint, the translation-gateway proxy for
`POST /e/<endpoint>/v1/responses`, an active **health probe engine** that keeps
the pool's per-account state fresh and auto-recovers accounts, and — new in
Stage 5 — a **loopback admin API** (passkey/WebAuthn login, session + CSRF,
account/key/endpoint/policy CRUD, usage/health read views) served on its own
listener, separate from the proxy. There is no React frontend yet; the admin
surface is JSON-only but ships the strict security headers + CSP a later SPA
will rely on. See [`DESIGN.md`](DESIGN.md) §0 for the authoritative decisions.

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

The bootstrap token is **persisted as a SHA-256 hash only** (never the
plaintext) with a ~15-minute TTL, and is **single-use** — the plaintext is
printed to the console once so a later passkey-registration flow can consume it.
It is never written to durable logs.

## Reset admin login (lockout escape hatch)

If you lose every passkey (and your recovery codes), `admin reset-auth` fully
resets admin login from local shell access:

```sh
./poolgate admin reset-auth
```

It removes **all** registered passkeys, invalidates all recovery codes, revokes
all active sessions, clears any stale bootstrap tokens, and prints one fresh
short-TTL single-use bootstrap token (hashed at rest, plaintext to the console
only — never to durable logs). Register a new passkey with that token; consuming
it invalidates it.

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

## 2b. Add an account by signing in (OAuth + PKCE)

Instead of pasting an `auth.json`, sign in interactively through the browser:

```sh
./poolgate login                       # or: --strategy best-quota
```

This runs an OAuth **authorization-code + PKCE** flow (S256 challenge, single-use
`state`): it prints an `auth.openai.com` URL, waits for you to complete sign-in
(including MFA), and receives the result on a **loopback callback**
(`http://localhost:1455/auth/callback`, fallback `1457`). On success it stores the
account exactly like `import` — creating the default group/endpoint/`sk-` key on
the first account.

Because the callback lands on a loopback port, run `login` **on the poolgate host**
(at its console, or over `ssh -L 1455:127.0.0.1:1455 <host>` so a remote browser's
redirect reaches it). This is why login is a CLI command rather than an admin-UI
button — the redirect_uri is a fixed loopback port that must be co-located with
whatever finishes the sign-in. The token endpoint and client id are the same
pinned values the refresh path uses.

Subsequent imports add the account to the pool only (the existing endpoint/group
is reused; the strategy is set once at group-creation time).

## 3. Serve

Starts **both listeners** — the proxy (loopback `127.0.0.1:8787` by default)
with the translation gateway plus `/healthz` and `/readyz`, and the **admin API**
(loopback `127.0.0.1:7070` by default) — and launches the **health scheduler
loop** alongside them. On `SIGTERM`/interrupt the root context is cancelled and
**both** servers drain and shut down gracefully (5s deadline).

```sh
./poolgate serve
```

The admin listener is bound separately from the proxy so you can front the proxy
to your LAN/reverse-proxy while keeping the admin surface loopback-only
(DESIGN.md §3). A non-loopback admin bind emits a warning but is not refused. The
WebAuthn RP ID/origin are resolved **once at startup** from the static
`server.admin` config (`external_origin` / `rp_id`), never from request headers.

Health checks (unauthenticated, secret-free, on the proxy listener):

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

## 5. Admin API (passkey login + management)

The admin listener (loopback `127.0.0.1:7070` by default) exposes a JSON REST API
under `/admin/*`. Every response carries strict security headers + a locked-down
CSP, and cross-origin requests are rejected (same-origin only). State-changing
requests on session-guarded routes require the `X-CSRF-Token` header. All
management routes (accounts / api_keys / endpoints / policy_groups / usage /
health / status) sit behind a valid passkey session cookie.

The examples below use a cookie jar (`-c/-b cookies.txt`) so the session cookie
set by login/registration is reused. A real browser flow drives the WebAuthn
ceremonies via the platform authenticator / a QR-linked phone; the raw JSON is
shown here for reference.

### 5a. Register the first passkey with the bootstrap token

The single-use bootstrap token printed by `init` (or `admin reset-auth`) gates
the **first** passkey. Registration is a two-step WebAuthn ceremony; the token is
consumed only at `finish`, after the attestation verifies, so a malformed
attempt never burns it.

```sh
# begin — returns {publicKey:{...creation options...}, challenge_id}
curl -s http://127.0.0.1:7070/admin/register/begin \
  -c cookies.txt -H 'Content-Type: application/json' \
  -d '{"bootstrap_token":"pgbt_...from init...","label":"primary"}'

# finish — send the authenticator's attestation back with the same challenge_id.
# On success: {"authenticated":true,"recovery_codes":[...]} (codes shown ONCE)
# and a session cookie is set. The bootstrap token is now consumed.
curl -s http://127.0.0.1:7070/admin/register/finish \
  -c cookies.txt -b cookies.txt -H 'Content-Type: application/json' \
  -d '{"bootstrap_token":"pgbt_...","challenge_id":"<from begin>","credential":{...}}'
```

Store the returned recovery codes now — they are shown only once. Register
**additional** passkeys later from a signed-in session (send the session cookie +
`X-CSRF-Token` instead of a bootstrap token).

### 5b. Log in with a registered passkey

```sh
# begin — returns {publicKey:{...assertion options...}, challenge_id}
curl -s http://127.0.0.1:7070/admin/login/begin -c cookies.txt \
  -H 'Content-Type: application/json' -d '{}'

# finish — {"authenticated":true} + session cookie on success.
curl -s http://127.0.0.1:7070/admin/login/finish -c cookies.txt -b cookies.txt \
  -H 'Content-Type: application/json' \
  -d '{"challenge_id":"<from begin>","credential":{...}}'
```

Lost every passkey? Log in with a one-time recovery code
(`POST /admin/login/recovery` with `{"code":"..."}`), or run
`poolgate admin reset-auth` locally to re-issue a bootstrap token.

### 5c. Manage the pool from an authenticated session

CSRF-protected mutations need a token from `GET /admin/csrf` (returns
`{"csrf_token":"..."}`), sent back in the `X-CSRF-Token` header:

```sh
CSRF=$(curl -s http://127.0.0.1:7070/admin/csrf -b cookies.txt | jq -r .csrf_token)

# Import an account via the admin API (same core import routine as the CLI):
# paste the auth.json contents, or point at a path on the host.
curl -s http://127.0.0.1:7070/admin/api/accounts/import \
  -b cookies.txt -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' \
  -d '{"content":"{\"tokens\":{\"access_token\":\"...\",\"refresh_token\":\"...\",\"account_id\":\"...\"}}"}'

# List accounts / usage / health (read views; GET needs no CSRF token):
curl -s http://127.0.0.1:7070/admin/api/accounts -b cookies.txt
curl -s http://127.0.0.1:7070/admin/api/usage    -b cookies.txt
curl -s http://127.0.0.1:7070/admin/api/health   -b cookies.txt
curl -s http://127.0.0.1:7070/admin/api/status   -b cookies.txt

# Revoke every session (e.g. after suspected compromise):
curl -s http://127.0.0.1:7070/admin/sessions/revoke-all \
  -b cookies.txt -H "X-CSRF-Token: $CSRF" -X POST
```

`GET /admin/api/status` also reports `clock_skew_seconds` (host clock minus the
upstream usage endpoint's clock) plus `clock_skew_measured_at` once a usage poll
has measured it (DESIGN.md §21.4). Usage windows are anchored to the upstream
absolute `reset_at`; a large reported skew means the host clock has drifted (fix
NTP). The health engine also logs a warning past a threshold (default 2m).

## Configuration

`config.yaml` is optional and lives in the data dir; missing keys fall back to
loopback defaults. Sketch:

```yaml
server:
  admin:
    host: 127.0.0.1
    port: 7070
    # WebAuthn RP inputs for admin passkeys — resolved ONCE at startup from this
    # static config, never from forwarded request headers (DESIGN.md §16). Both
    # optional; when omitted the RP origin is derived as http://host:port and the
    # RP ID as that origin's hostname (fine for loopback dev).
    external_origin: "https://admin.example.com"   # browser-facing origin
    rp_id: "example.com"                            # WebAuthn Relying Party ID
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
asserting the header rewrite, forced streaming, and SSE relay. The Stage 5 test
(`stage5_test.go`) additionally drives the bootstrap-token → first-passkey
registration → login flow through the real admin HTTP API with a software
authenticator, and starts both listeners together (proxy + admin) with a clean
graceful shutdown.
