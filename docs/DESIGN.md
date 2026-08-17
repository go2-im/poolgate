# poolgate — Design

> Living design doc. Reflects decisions made during planning; expect it to evolve before/while scaffolding.

## 0. Authoritative decisions (v3) — supersede conflicting text below

Sections 1–27 grew incrementally; where they conflict with this ledger, **this ledger wins**. Rationale + citations in [`REVIEW.md`](REVIEW.md).

**Codex 0.147.0 reality (verified vs `openai/codex@rust-v0.147.0`):**

- **D1 — Translation gateway, not transparent proxy.** Upstream is `https://chatgpt.com/backend-api/codex/responses` with `stream:true` + forced `Accept: text/event-stream`. poolgate rewrites `Authorization` **and** `ChatGPT-Account-ID` **together** (never one alone), and preserves Codex identity headers (`originator` default `codex_cli_rs`, `User-Agent`, `OpenAI-Beta`, `x-codex-turn-state`). (Supersedes the "reverse proxy" framing in §6/§8/§23.5.)
- **D2 — Transport: WS-first client, HTTP-only default server.** Codex tries a WebSocket `/responses` upgrade first (`supports_websockets:true`, warmup `response.create generate=false`, connection-scoped `previous_response_id`). v1 originally deferred WS (HTTP POST+SSE fallback only); **post-v1 (PR #46/#50) the WS upgrade CAN be accepted and proxied**, configurable via `server.transport` (`http-only` **default** | `both` | `ws-only`). The **default is `http-only`** (audit P2#10): HTTP POST+SSE is stateless — full inline `input`, no `previous_response_id` — so it needs no affinity and is always correct, whereas WS turn affinity across RECONNECTS depends on an `x-codex-turn-state` **upgrade header current Codex clients do not send** (they carry turn-state inside WS messages), so a reconnected turn could mis-route and lose server-side state. Accepting the WS upgrade is therefore an explicit opt-in (`both`/`ws-only`). (Supersedes §14/§23.5 "POST+SSE only" and §19.1's stateful framing.)
- **D3 — Session affinity is turn-scoped correctness, keyed on `x-codex-turn-state` — and is N/A in v1.** Because v1 forces the stateless HTTP path, **no affinity is needed in v1**. When WS is added later, affinity MUST pin a turn to one backend keyed on the `x-codex-turn-state` token (not the §15 monitoring session id). (Corrects §19.1: not a best-effort-session-id optimization.)
- **D4 — Usage is generic percent windows + `plan_type`.** Model `GET /backend-api/wham/usage` → `plan_type` + N `rate_limit` windows each `{used_percent, window_seconds, resets_at}`. No fixed "5h/1week token" columns. (Supersedes §5/§12/§13/§24.2 hardcoding.)
- **D5 — Cheap auth-check probe = the real `/models`.** Use authenticated `GET {base}/models?client_version=<v>` (200 valid / 401·403 invalid) as the zero-spend token check. (Supersedes §12's `/v1/models` note.)
- **D6 — Refresh single-flight + atomic persistence is P1.** OAuth rotates `refresh_token`; a reused one permanently bricks the account. One per-account single-flight shared by probe **and** hot path; write via temp+rename (atomic), interprocess-safe. (Elevates §19.3 to cover the hot path + probe together.)

**Scope trims (single-user; see REVIEW.md §3):**

- **D7 — 4 strategies:** `fallback`, `best-quota`, `load-balance` (round-robin = its default mode; `select` = single-member group), and `weighted` (implemented — proportional distribution). Define `best-quota` = max over accounts of `min` window `used_percent` headroom vs that plan's caps, deterministic tie-break.
- **D8 — Flat policy groups in v1** (Endpoint → PolicyGroup → Accounts; no nesting/DAG/cycle-check/tree-UI). Keep polymorphic `group_members` schema for later nesting.
- **D9 — Trim:** 4 install channels (Release binaries + `install.sh` + Docker + Homebrew tap; Scoop/winget/deb-rpm deferred); append-only audit log (hash-chain re-added post-v1 — see §22.5); no per-key spend budgets (keep rate-limit + scoping); no dual-key grace (multiple keys + manual rotate); keep SHA256SUMS+cosign, drop full SLSA + reproducible-build CI gate; on-demand export (no scheduler); drop `/metrics` from v1 (slog JSON + in-app monitor); single UI language + dark mode (no i18n framework / a11y / mobile program); charts = 3–4 headline counters (no chart suite/rollup); defer match-rule engine AND per-key model allow-deny (v1 per-key controls = endpoint scoping + IP allowlist), subpath hosting.
- **D10 — Personal-use priority + credential-generation model (see §1, §19.3a/b, §20.3).** poolgate is a single-operator tool; when goals conflict the order is (1) **normal-operation correctness** (never brick the refresh-token family / serve wrong data), (2) **stop→restart with seamless automatic state recovery**. Credential ordering is authoritative via a **monotonic `accounts.credential_version`** (version CAS on refresh; login = unconditional new generation; version-tagged recovery journal applied by version, fail-closed on ambiguity), under a **cross-process credential lock**. **Non-goals:** hot/online backup and automatic/scheduled backup (cold CLI backup only, `serve` stopped — §20.3). **De-prioritized / best-effort — but only the *runtime operations* of a deployed instance** (never regressing (1)/(2)): large-scale operability & metrics, host **migration** portability, and **crash-rebuild** DR automation (`restore --recover` / generation-manifest). **NOT de-prioritized:** product build/release engineering (reproducible frontend build + CI frontend-build + embedded-`dist` consistency check) and basic app correctness/robustness (`/readyz` semantics, bounded admin rate-limiter memory) stay first-class.

**Correctness/robustness fixes (see REVIEW.md §2):** config/policy **hot-reload** via atomic snapshot on admin commit; **auto-recovery gated by `Retry-After`**; **bootstrap token** short-TTL + single-use, not in durable logs; **account-state enum** adds terminal `revoked`/`dead` (no auto-recovery); **WebAuthn RP origin** resolved once at startup from static config only (never per-request forwarded headers); **PKCE** loopback callback with single-use `state` + S256; **memory hygiene** (disable core dumps, mlock master key); **sanitize** client-supplied fields into logs/monitor; **`/readyz`** = migrations applied + ≥1 endpoint has a reachable healthy account; **backup restorability** check (integrity_check + sample decrypt + schema version).

**Phase split:** **2a = walking skeleton** (config + store + one **manually-imported** encrypted account (explicit `poolgate import`, never auto on first-run) + on-path single-flight refresh + one `sk-` key + one endpoint + `fallback` + translation gateway forcing HTTP+SSE → one account end-to-end); **2b** = remaining strategies + health engine + generic usage model; **later** = WS proxying + `x-codex-turn-state` affinity. §20 backup + §21.4 clock-align move out of Phase 1.

## 1. Goal & scope

A **single-user**, self-hostable tool that:

1. Manages a **pool of Codex/ChatGPT accounts** (import via OAuth or `~/.codex/auth.json`, view usage, refresh tokens).
2. Exposes them as **OpenAI-compatible `/v1`** endpoints.
3. Routes each request through a **composable policy engine** (Surge-style) so the caller can choose a strategy by hitting a specific proxy URL.
4. Is managed through a **web admin UI** protected by **passkey** login.

**Non-goals:** multi-tenant/team accounts, reselling access, an outbound public tunnel (removed by decision — remote access is via the operator's own reverse proxy).

**Scale & priority stance (personal-use tool):** poolgate is for **one operator's own machine**, not a commercial/large-scale service. When goals conflict, priority is:

1. **Correctness of normal operation** — never brick an account (esp. the OAuth refresh-token family), never serve wrong data.
2. **Stop → restart with seamless automatic state recovery** — after a clean stop or a crash, the next `poolgate serve` reconciles any in-flight credential state (pending token rotations) automatically and keeps running, with no operator action in the common case.

Explicitly **lower-priority / best-effort** (may be simpler, may require manual steps, may be deferred) — these are **post-deployment *runtime* operations** of a deployed instance: large-scale operability & metrics, host-to-host **migration** portability, and **crash-*rebuild*** disaster-recovery automation (rebuilding a destroyed install from a backup). These matter, but not at the cost of (1)/(2), and their tooling can stay minimal. Cold CLI backup exists as a safety net (§20), but automatic/scheduled and hot/online backup are **non-goals** (§20.3).

**Not lowered** (this de-prioritization is about *running* a deployed instance, not about the product): **product build/release engineering** — reproducible frontend build + CI that builds the frontend and verifies the embedded `internal/webui/dist` matches source — and **basic app correctness/robustness** — a correct `/readyz` readiness semantics and bounded memory (e.g. the admin failed-auth limiter) — remain first-class requirements.

## 2. Deployment modes (both supported from day one)

| Mode | Bind | Admin auth | TLS |
|------|------|-----------|-----|
| **Local** | `127.0.0.1` | passkey (RP ID `localhost`; WebAuthn treats `http://localhost` as a secure context, so no TLS needed) | none |
| **Remote (self-hosted)** | `127.0.0.1`, fronted by **your** reverse proxy (Caddy/nginx) | passkey (RP ID = your domain) | terminated at the reverse proxy |
| **Intranet / LAN** | LAN addr or `0.0.0.0` (supported); **reverse-proxy fronting recommended** over direct port access | passkey / `sk-` key | via reverse proxy if used |

**All listener ports are configurable** (admin + proxy), defaults are just defaults.

**Bind policy:** loopback (`127.0.0.1`) is the default. Binding to a LAN address or `0.0.0.0` **is a supported, first-class option** — other machines on your intranet may use poolgate. But the **recommended** way for other machines to reach it is **through a reverse proxy** (one TLS-terminating, access-controlled ingress), not by hitting the raw proxy/admin port directly. A non-loopback bind emits an informational **startup notice** (not a scary warning) that it is network-reachable and suggests reverse-proxy fronting; access stays gated by the `sk-` key (proxy) / passkey (admin) regardless of bind address.

The binary **never launches or manages a tunnel itself** — but it is built to run **smoothly behind whatever you put in front of it**: a reverse proxy (Caddy/nginx) *or* an external tunnel you run (cloudflared, ngrok, etc.). See §14 for how (trusted-proxy headers, external origin, streaming pass-through). So "remote" = you front the loopback listener with your own TLS reverse proxy or tunnel.

> WebAuthn passkeys are bound to the RP ID (domain). A passkey registered on `localhost` will not work on `your.domain` and vice-versa — register one per environment (or one roaming/phone passkey usable across them). RP ID / origin are config, **resolved once at startup from static config only** (`external_origin` / `rp_id`); they are **never derived from per-request forwarded headers** (see §14, §0 fixes). **Cross-device / QR sign-in is supported** — the WebAuthn config allows platform, cross-platform, and hybrid (caBLE) authenticators, so the browser can show a QR code to authenticate with a passkey on your phone (§16).

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
│    health(probe + account state machine) ·                     │
│    policy(engine) · proxy(forwarder) · auth(webauthn+keys) ·   │
│    notify(dingtalk / wecom / webhook)                          │
└──────────────────────────────────────────────────────────────┘
```

Splitting Admin and Proxy into separate listeners lets you expose the proxy to your LAN/reverse-proxy while keeping the admin surface loopback-only.

The `proxy` package is a **translation gateway, not a transparent reverse proxy** (§0 D1): the OpenAI-compatible surface is **inbound only**, while upstream it rewrites `Authorization` **and** `ChatGPT-Account-ID` **together** per pooled account, preserves Codex identity headers (`originator` default `codex_cli_rs`, `User-Agent`, `OpenAI-Beta`, `x-codex-turn-state`), and forces streaming (see §6).

**Config/policy hot-reload:** admin edits are persisted to SQLite and then published to the running proxy as an **atomic in-memory snapshot rebuilt on each admin commit** (§7) — routing, keys and policies update without a restart and without stale-routing / key-revocation lag.

## 4. Policy engine (Surge-inspired)

Three entities:

- **Account** — a pooled Codex/ChatGPT credential (the leaf "proxy"). Carries a **state** (`ok` / `cooldown` / `quota_exhausted` / `expired` / `unknown`, plus terminal `revoked` / `dead` which are **not** auto-recovered — see §12/§23.6), last usage snapshot (generic percent-usage windows + `plan_type`; e.g. a 5h and a weekly window shown as display labels — see §0 D4), and measured latency. State is maintained both passively (from real proxy traffic) and actively by the **health probe engine** (§12), which auto-recovers accounts when their quota/rate-limit clears. Also carries **management metadata** — **subscription type** (Free / Plus / Pro / Team / Enterprise / …, auto-detected from the plan endpoint where possible, editable), **subscription region/zone**, a human **label**, and free-form **tags/category** — used by the admin UI for grouping, search and sort (§13), and usable as account selectors when composing policies (e.g. "a policy over all Pro accounts in region US"). **v1 scope:** the *implemented* account model carries only a `label` and `concurrency_cap` (alongside state / usage snapshot / timing); **subscription type, region/zone, and tags/category are deferred** — not yet in the schema, admin API, or UI.
- **PolicyGroup** — named, has a `type` (strategy) and an **ordered member list**. **v1 is flat** (Endpoint → PolicyGroup → Accounts): members are Accounts. The polymorphic `group_members` schema still permits a member to be another PolicyGroup, but **nesting / DAG / cycle-check / composition-tree UI are deferred** (v1: deferred — see §0 D8). Strategies (**4 in v1** — see §0 D7):
  - `fallback` — first healthy in order; on 401/429/5xx/timeout advance + cooldown the failed member.
  - `best-quota` — route to the account with the most remaining headroom. **Metric:** the `max` over accounts of that account's headroom, where an account's headroom = the `min` over its usage windows of `(100 − used_percent)`; **deterministic tie-break = lowest account id** (≈ codex-tools `switch --best`).
  - `load-balance` — distribute across healthy members; **round-robin is its default mode**. `select` (a manually pinned member) is expressed as a **single-member group**.
  - `weighted` — distribute across healthy members proportionally to each member's configured weight (implemented).
  - `url-test` *(optional, low-priority)* — periodic health/latency probe; route to lowest-latency healthy member (interval configurable). Kept but **coupled to the health engine** (§12) — see §0 D7. **Deferred — not implemented in v1; the v1 strategies are `fallback` / `best-quota` / `load-balance` / `weighted`.**
- **Endpoint** — a named inbound route bound to one PolicyGroup, surfaced as a distinct URL: `/e/<endpoint>/v1/...`. The caller picks a strategy by choosing the URL. API keys can be scoped to specific endpoints.

**A PolicyGroup _is_ your custom named strategy** — you bind an explicit subset of accounts to a strategy type, and reuse it. This is the primary, flexible/controllable model:

- `policy-1` = `load-balance` (round-robin mode) over **{A, B, C}**
- `policy-2` = `fallback` over **{A, C}**

Each named policy is independent and reusable; the **same account may appear in multiple policies**, and a policy contains only the accounts you choose (not the whole pool). In v1 a policy is a **flat** set of accounts; group nesting for advanced composition is deferred (v1: deferred — see §0 D8). Each endpoint URL binds to one such policy, so different URLs = different account-set + strategy combinations.

Composition example (**nesting is deferred — v1 is flat, see §0 D8**; the nested form below illustrates the later-phase model):
```
# v1 (flat): endpoint -> one policy group -> accounts
endpoint "prod"  -> group "balanced"    (load-balance): acct1, acct2, acct3
endpoint "fast"  -> group "low-latency" (url-test):     acct1, acct3, acct5

# later phase (nested groups):
endpoint "prod"  -> group "balanced" (load-balance)
                       ├─ group "teamA" (fallback): acct1 -> acct2
                       └─ group "teamB" (fallback): acct3 -> acct4
```

Request flow: inbound key auth → resolve endpoint → group → engine selects an Account (skipping unhealthy) → the **translation gateway** rewrites `Authorization: Bearer <access_token>` **and** `ChatGPT-Account-ID` **together** for that pooled account (never one alone) and preserves Codex identity headers (`originator` default `codex_cli_rs`, `User-Agent`, `OpenAI-Beta`, `x-codex-turn-state`) → forward to the pinned upstream with **streaming forced** (see §6) → on failure, engine may re-select per strategy. SSE/streaming responses are relayed with per-chunk flush.

## 5. Storage — SQLite (pure-Go), encrypted secrets

- **Engine:** `modernc.org/sqlite` (pure Go, no CGO) → trivial cross-compilation, single binary. WAL mode, `busy_timeout`.
- **Why a DB, not just JSON:** config data (accounts/groups/endpoints/keys/passkeys) is small, but **request/usage logs + per-key/per-account stats grow** and need indexed aggregation for the UI; the policy engine's health updates and admin edits need transactional consistency under concurrent proxy load.
- **Encryption at rest:** secret columns (access/refresh tokens, etc.) are **field-encrypted** with `nacl/secretbox` (or `age`) before insert — SQLCipher would require CGO, so we do app-level field encryption instead. Master key from **OS keychain** (macOS Keychain / Windows DPAPI) preferred, else keyfile / env; never stored in plaintext next to the DB.
- **Retention:** request/usage log tables are periodically pruned; keeps the DB small even under heavy use.
- **Tables (initial):** `accounts` (incl. `subscription_type`, `region`/`zone`, `tags`, `label`, state, usage snapshot, latency), `policy_groups`, `group_members`, `endpoints`, `api_keys`, `key_scopes`, `webauthn_credentials`, `usage_snapshots` (generic percent-usage windows: `plan_type` + N rows each `{used_percent, window_seconds, resets_at}` — **not** fixed 5h/1week token columns; see §0 D4), `health_checks`, `request_logs` (time, api_key_id, session_id, endpoint, policy, account_id, model, status, latency_ms, tokens_in/out), `audit_log`, `settings`.

## 6. Egress hardening

- **Translation gateway, not a transparent reverse proxy** (§0 D1). The OpenAI-compatible surface is **inbound only**; the upstream leg is non-transparent — per pooled account poolgate rewrites `Authorization` **and** `ChatGPT-Account-ID` **together** (never one alone), preserves Codex identity headers (`originator` default `codex_cli_rs`, `User-Agent`, `OpenAI-Beta`, `x-codex-turn-state`), and forces streaming (`stream:true` + `Accept: text/event-stream`).
- **Upstream pinned** to `chatgpt.com` / `api.openai.com` by default; any override is an explicit poolgate config value validated against a **host allowlist** (never read silently from an external file).
- **OAuth issuer pinned** to `https://auth.openai.com`; the `iss` claim inside imported tokens is **ignored** for building the refresh URL.
- Any outbound request carrying `Authorization` whose host is not on the allowlist is refused.

## 7. Config (YAML) — seed & export

The UI is the source of truth (writes to SQLite); YAML is used to seed on first run and to export/back up. **Config/policy changes hot-reload** into the running proxy via an **atomic in-memory snapshot rebuilt on each admin commit** (§3) — no restart, no stale routing or key-revocation lag. Sketch:

```yaml
server:
  admin: { host: 127.0.0.1, port: 7070, rp_id: localhost, rp_origin: "http://localhost:7070" }
  proxy: { host: 127.0.0.1, port: 8787 }
  external_origin: ""            # e.g. https://poolgate.example.com when behind a tunnel/proxy
  trusted_proxies: []            # CIDRs allowed to set X-Forwarded-* (e.g. 127.0.0.1/32)
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
- WebAuthn: `github.com/go-webauthn/webauthn` (allow platform + cross-platform + hybrid/caBLE authenticators → QR / phone cross-device sign-in).
- Crypto: `nacl/secretbox` (field encryption), `argon2id` (only if a password fallback is ever added — default is passkey-only + recovery codes).
- Translation gateway (not a transparent reverse proxy): `net/http/httputil.ReverseProxy` (FlushInterval=-1 for SSE) or manual relay — rewriting `Authorization` + `ChatGPT-Account-ID` together and preserving Codex identity headers (see §0 D1 / §6).
- Frontend: **React** (Vite), built to static assets, embedded via `go:embed`.
- Config: **YAML**.
- Release/dist: **GoReleaser** — v1 ships **4 channels** (GitHub Release binaries + `install.sh` + Docker + Homebrew tap; Scoop/winget/deb-rpm deferred — see §0 D9 / §18), **`SHA256SUMS` + cosign** (keyless OIDC signing); **full SLSA provenance + reproducible-build CI gate are deferred**. **Dependabot/Renovate** + `govulncheck` for dependency automation.

## 9. Build phases

1. **Core:** `config`, `store` (SQLite + field encryption; encrypt/decrypt round-trip test), `oauth` (login/import/refresh, issuer pinned). Plus **`poolgate init`** auto-provisioning + startup migrations (§17).
2. **Policy + proxy:** `policy` engine (the **4 v1 strategies** + health; **nesting / cycle-check deferred** — v1 flat, see §0 D8), `proxy` server (`/e/<ep>/v1`, sk- auth, SSE, egress allowlist), **trusted-proxy header handling + streaming pass-through for tunnels/reverse-proxies (§14)**, per-request logging with session/model/tokens (§15).
   - **`health`**: probe engine + account state machine (usage-poll / auth-check / small live request), adaptive per-state scheduling, auto-recovery, feeds `url-test`/`best-quota` (see §12).
3. **Admin API + passkey:** WebAuthn register/login (bootstrap token, multiple passkeys, recovery codes, `admin reset-auth` CLI), session + CSRF, CRUD for accounts/groups/endpoints/keys. Accounts list API supports metadata (subscription type / region / tags), filter / search / sort / paginate in SQL (§13).
   - **`notify`**: channel CRUD (DingTalk / WeCom / custom webhook) + a "test" button; alert rules wired to policy/proxy events (see §11).
4. **Web UI:** React pages (login, dashboard/usage, accounts w/ categorize·search·sort, policy groups w/ composition view, endpoints, keys, **real-time monitor** — live scrolling logs + charts filterable by session/api-key/model (§15), settings), `go:embed`. Admin server exposes an SSE/WS live-events stream.
5. **Release:** GoReleaser-driven — cross-compiled single binary, `SHA256SUMS` + cosign signature, **4 channels** (GitHub Release binaries / verified `install.sh` / Docker / Homebrew tap; Scoop/deb-rpm deferred — see §0 D9), SHA-pinned CI, Dependabot, no silent auto-update, `docs/BUILD.md` (§18). Full SLSA provenance + reproducible-build gate deferred.
6. **Optional / later (post-v1):** account cooldown tuning, expanded usage charts beyond the 3–4 headline counters (see §0 D7/D9), and WS proxying with `x-codex-turn-state` affinity (§0 D2/D3).

## 10. Development model

Bare-repo + git worktrees: `poolgate/.bare` is the hub; `poolgate/main` is the main worktree; feature work happens in sibling worktrees (e.g. `poolgate/scaffold` on branch `feat/scaffold`). Remote: `git@github.com:go2-im/poolgate.git` (origin on `.bare`).

## 11. Notifications & alerting

A `notify` module delivers alerts to user-configured channels. **Channels:**

- **DingTalk robot** (custom-robot webhook; supports secret/keyword signing).
- **WeCom / 企业微信 robot** (group-robot webhook key).
- **Custom webhook** (arbitrary HTTPS endpoint; configurable method/headers/JSON template).

Multiple channels can be enabled at once; each channel has a "send test" action in the UI.

**Alert triggers (events emitted by policy/proxy/oauth):**

| Event | Example |
|-------|---------|
| Account expired / refresh failed | a pooled account's token can no longer refresh |
| Account entered cooldown | repeated 401/429/5xx from an account |
| **Account recovered** | a degraded account passed a health probe and returned to `ok` (§12) |
| Policy has no healthy member | every account in a group is down → that endpoint is failing |
| Quota low / exhausted | remaining usage in any window below threshold (e.g. the 5h / weekly example windows) |
| Auth anomalies | repeated invalid proxy-key attempts (possible probing) |
| Startup binding warning | proxy bound to a non-loopback host |

Rules are configurable (which events → which channels, thresholds, dedup/rate-limit window so one flapping account doesn't spam).

**Security rules for notifications (see `docs/SECURITY.md`):**

- **Never include secrets/PII in alert payloads** — no tokens, no `sk-` keys, no `access_token`; reference accounts by label/id only.
- Notification egress is a **separate, explicitly user-configured outbound channel**, kept distinct from the credential-egress allowlist — credentials are never sent to a notification endpoint, and the credential allowlist is never widened by adding a channel.
- Webhook URLs must be **HTTPS**; validated on save; delivery has timeout + bounded retries; failures are logged (without payload secrets) and surfaced in the UI.

## 12. Health probing & account-state monitoring

An active **`health`** engine periodically probes each account so the pool reflects real state — and, importantly, **auto-recovers** accounts once their quota/rate-limit clears (e.g. after you manually reset an account's quota, or a usage window rolls over, a probe discovers it and flips the account back to `ok` without manual intervention).

**Probe kinds (cheapest that answers the question):**

1. **Usage poll (zero token spend)** — `GET /backend-api/wham/usage` → `plan_type` + N generic rate-limit windows each `{used_percent, window_seconds, resets_at}` (the 5h / weekly windows are just example display labels — see §0 D4). Primary signal for quota level and for detecting a reset. Default cadence for all accounts.
2. **Auth check (zero token spend)** — authenticated `GET {base}/models?client_version=<v>` (**200 = valid, 401/403 = invalid**) to confirm the token is still valid (catches `expired`) — see §0 D5.
3. **Small live request (minimal spend)** — a tiny real completion (e.g. `max_tokens: 1`) to confirm the account actually serves traffic (catches rate-limit/quota state the usage endpoint may not reflect, and confirms recovery). Used mainly to re-test degraded accounts and to confirm recovery; opt-in cadence for healthy accounts to keep spend near zero.

**Account state machine:**

```
        probe ok / small-req ok
   ┌───────────────◄───────────────┐
   │                                │
[cooldown]  [quota_exhausted]   [expired]           [unknown]
   ▲   │          ▲   │             ▲                    │
   │   │ 429/5xx  │   │ quota=0     │ 401 & refresh fail │ first seen
   │   └──────────┘   └─────────────┘                    ▼
   └──────────────── [ok] ◄──────────────────────────────┘
```

- Real proxy traffic transitions passively (401/403→try refresh→retry same account→`expired` if it recurs; 429/5xx→`cooldown`; quota=0→`quota_exhausted`).
- **401/403 convergence (passive):** a real-traffic **401 and 403 are treated identically** as a rejected credential (consistent with the §0 D5 auth-check, where GET /models 401/403 both = invalid). On the first occurrence the gateway refreshes once via the shared single-flight and retries the SAME account with the rotated token. If it 401/403s **again** after that refresh, the fresh token cannot fix it (the credential is revoked, or the account lacks entitlement/region access), so the account is **converged to `expired`** — it leaves the hot pool and is handed to the rare auth-check re-probe cadence, instead of being re-selected and re-failing on **every** request. Without this, a 403 (which drove no state transition) or a persistently-401ing account stayed `ok` and was hammered indefinitely (audit P2#9).
- The probe engine transitions actively **and drives recovery**: degraded accounts (`cooldown` / `quota_exhausted`) are re-probed on a **shorter, backing-off interval** so recovery is discovered quickly; `ok` accounts are polled on a longer interval. On a successful probe, the account returns to `ok` and re-enters policy rotation automatically.
- **Terminal states** `revoked` / `dead` (§23.6) are **never auto-recovered** by the probe engine — they require re-import / re-auth and are excluded from probing.

**Scheduling & cost control (all configurable):**

- Per-state intervals: e.g. `ok` usage-poll every N min; `cooldown`/`quota_exhausted` re-probe every M min with exponential backoff up to a cap, but **never before the upstream `Retry-After` (or a conservative default) elapses** — auto-recovery is gated on `Retry-After`; `expired` retried rarely (needs re-auth); terminal `revoked`/`dead` are not probed.
- Global mode switch: **usage-poll-only (zero token spend — the default)** vs **allow small live requests** for degraded/recovery checks, bounded by a **per-account daily live-probe budget**. Per-account override.
- Jittered schedules to avoid synchronized bursts; one **per-account single-flight primitive shared with the proxy hot path** (§19.3) — no overlapping probes and no concurrent token refresh, with atomic (temp+rename), interprocess-safe persistence of any rotated `refresh_token` (see §0 D6); probe results also feed the `url-test` (latency) and `best-quota` (remaining quota) policy strategies.

**Persistence & UI:** latest state + usage + latency per account in `accounts`; probe history in a `health_checks` table (pruned). The admin UI shows live per-account state, remaining quota bars, last-probe time, and a manual "probe now" button.

**Notifications:** state transitions fire alerts via `notify` (§11) — including a **recovered** event (`cooldown`/`quota_exhausted` → `ok`), plus degraded/expired/quota-low. Recovery notifications must reference the account by label/id only.

## 13. Account management (metadata, categorize, search, sort)

Each account carries management metadata (see §4): **subscription type**, **region/zone**, **label**, **tags/category**. The admin UI's Accounts view is built for a pool that may grow to dozens/hundreds:

- **Categorize / group by:** subscription type, region/zone, tag/category, or state.
- **Search / filter:** free-text over label/tags + faceted filters (type, region, state, quota range, "in policy X", "healthy only").
- **Sort:** by label, subscription type, region, state, remaining quota (min headroom across windows; the 5h/weekly windows are example labels — see §0 D4), latency, last-probe time, created/updated.
- **Bulk actions:** tag, set region/type, enable/disable, "probe now", add-to-policy.
- Subscription type is auto-detected from the plan endpoint where possible and stays editable; region/zone is a user-selected value (dropdown, config-defined list) — since it may not be reliably detectable.

Backed by indexed columns in `accounts`; the list API takes `filter` / `q` / `sort` / `page` params so filtering and sorting happen in SQL, not in the browser.

## 14. Ports, reverse-proxy & tunnel compatibility

Ports are fully configurable, and poolgate is designed to sit behind whatever fronting you choose (you run it; poolgate does not).

- **Configurable listeners:** `server.admin.{host,port}` and `server.proxy.{host,port}`; both default to loopback and can be changed freely.
- **Trusted proxies:** `server.trusted_proxies` (CIDR list). Only when the peer is a trusted proxy does poolgate honor `X-Forwarded-For` / `-Proto` / `-Host` (real client IP for logs/rate-limit, external scheme/host for the proxy URLs shown in the UI). Untrusted peers' forwarded headers are ignored → no IP/host spoofing. **The WebAuthn RP origin is NOT taken from forwarded headers** — it is resolved **once at startup from static config** (`external_origin` / `rp_id`) only (see §2, §0 fixes).
- **External origin:** `server.external_origin` (e.g. `https://poolgate.example.com`) sets the canonical scheme+host used for WebAuthn RP origin, cookie flags, and the proxy URLs shown in the UI to copy into Codex/Cursor — so behind a cloudflared/ngrok URL the UI shows the *public* endpoint, not `127.0.0.1`.
- **Transport (WS-first):** Codex 0.147.0 first attempts a **WebSocket `/responses` upgrade** (`supports_websockets`, warmup `response.create generate=false`, `OpenAI-Beta: responses_websockets`), with **HTTP POST+SSE as the fallback**. v1 deferred WS; **post-v1 (PR #46/#50) the WS upgrade is accepted and proxied**, configurable via `server.transport` (see §0 D2). HTTP POST+SSE remains the stateless fallback (full inline `input`, no `previous_response_id`).
- **Streaming through tunnels:** SSE streams pass through with immediate per-chunk flush, `Cache-Control: no-transform`, no response buffering, and keep-alives tuned so cloudflared/ngrok/nginx don't buffer or drop long-lived streams. Idle/read timeouts are generous for streaming routes. (When WS proxying lands, the same buffer-free pass-through applies to the WS upgrade.)
- **Loopback default, LAN allowed:** the tunnel/reverse-proxy connects to the loopback listener, so you don't *have* to bind wider. Binding a LAN addr / `0.0.0.0` is supported for direct intranet use, but fronting with a reverse proxy is recommended even on a LAN (§2 bind policy).

> Security: since a tunnel makes the proxy effectively public, the `sk-` key remains the gate (constant-time). Do **not** expose the *admin* listener through a tunnel unless you intend to — and even then it is passkey-gated. Trusted-proxy parsing is strict to prevent spoofed client IPs. (See `docs/SECURITY.md`.)

## 15. Real-time request monitoring

A live observability view in the admin UI, backed by the proxy's per-request records.

- **Live log stream:** the admin server pushes new request records over SSE/WebSocket; the UI shows a **real-time scrolling log** (auto-scroll, pause, tail). Each row: time, endpoint, policy, chosen account (label), model, api-key (label), session, status, latency, tokens (in/out).
- **Counters / volume:** v1 shows **3–4 headline counters** (e.g. request rate, success vs error, token throughput) with live update; the full chart suite (latency percentiles, per-account/key/model breakdowns) and rollup tables are **deferred** (see §0 D9).
- **Filters:** by **session**, **api-key**, and **model** (composable), plus endpoint/account/status/time-range. Filtering runs in SQL over `request_logs` for history and is also applied to the live stream.
- **Session definition:** best-effort grouping — a client-supplied conversation/session id header if present, else derived per (api-key + client) connection; documented so it's predictable. **This session id is for logging/monitoring grouping ONLY — it is never used for routing or affinity** (turn affinity, when WS lands, keys on `x-codex-turn-state`; see §0 D3 / §19.1).
- **Storage/retention:** `request_logs` (indexed on time, api_key_id, model, session_id, account_id, status) with configurable retention/prune; aggregates can be rolled up to keep charts fast. No secrets in logs.

## 16. Admin auth details (passkey, QR/cross-device, CLI reset)

- **Passkey primary, no password.** Registration allows **platform** (Touch ID / Windows Hello), **cross-platform** (security keys), and **hybrid/caBLE** authenticators → the browser offers **QR-code sign-in with your phone**. Multiple passkeys can be registered (recommend a phone passkey + a hardware key backup).
- **Recovery:** one-time recovery codes generated at setup (shown once).
- **CLI full reset (always available locally):** `poolgate admin reset-auth` **completely resets admin login** — removes **all** registered passkeys, invalidates recovery codes and active sessions, and re-issues a **short-TTL, single-use** bootstrap registration token (printed to the local console, **never written to durable logs** — see §0 fixes). This is the guaranteed lockout escape hatch; it requires local shell access to the host (which already implies full control), never a network path.

## 17. First-run initialization (auto-provisioning)

Zero-to-running should be one step; setup is guided and idempotent.

- **`poolgate init`** (CLI): creates the config dir + data dir, generates the **master key** into the OS keychain (fallback `master.key`, `0600`), runs SQLite **schema migrations**, writes a default `config.yaml` (loopback defaults), and prints a **short-TTL, single-use admin bootstrap URL/token** (never written to durable logs — see §0 fixes) to register the first passkey. **`init` does NOT read or import `~/.codex/auth.json`** — no account is imported automatically. Idempotent — safe to re-run; missing pieces are filled in.
- **Account import is always explicit (never automatic), and available from BOTH the CLI and the admin UI.** Two triggers call the **same** import routine: `poolgate import <path>` (CLI; a path is always required — `~/.codex/auth.json` is never scanned implicitly) and an **"Import account"** action in the admin UI (upload/paste the auth JSON, or point at a path). The CLI trigger + core import logic ship in **Phase 2a**; the admin-UI trigger lands with the admin API/UI (**Phase 3+**). Neither `init` nor first launch ever imports on its own.
- **Auto-migrate on startup:** every launch runs pending DB migrations, so upgrades need no manual DB steps.
- **Web first-run wizard:** if no passkey is registered, the admin UI opens a setup wizard — register first passkey (QR or platform), set `external_origin`/`rp_id`, then **offer** (not auto-run) account import + creating a starter policy + endpoint; import happens only on the user's explicit click.
- **Docker/headless:** env-var-driven init (`POOLGATE_*`), data on a mounted volume; the short-TTL single-use bootstrap token is surfaced once in container stdout (rotate/re-issue via `reset-auth` if exposed).

## 18. Distribution, packaging & release automation

Driven by **GoReleaser** + **GitHub Actions**; every channel ships verifiable artifacts.

**Install channels (v1 = 4; see §0 D9):**

- **Homebrew tap** — `brew install go2-im/tap/poolgate` (macOS + Linux; formula auto-updated by GoReleaser on release). Primary path for the operator's own machine.
- **GitHub Release binaries** — cross-compiled archives (darwin/linux/windows × amd64/arm64) with `SHA256SUMS` + cosign signature attached to each release.
- **One-line install script** — `install.sh` detects OS/arch, downloads the matching archive from the latest GitHub Release, **verifies `SHA256SUMS` + the cosign signature before installing** (never a blind `curl | sh`). This directly addresses the audited "unverifiable binary / curl-pipe-sh" risk.
- **Docker image** — `ghcr.io/go2-im/poolgate` (self-host).
- *Deferred (v1: not shipped — see §0 D9):* Scoop / winget, deb/rpm via `nfpm`.

**Release CI (`release.yml`, on tag `v*`):** GoReleaser cross-compiles (darwin/linux/windows × amd64/arm64), builds archives + `SHA256SUMS`, **signs with cosign (keyless via GitHub OIDC)**, publishes the GitHub Release, updates the Homebrew tap, and pushes the Docker image (**full SLSA provenance + reproducible-build gate deferred** — see §0 D9; Scoop/deb-rpm not published in v1). All third-party Actions are **SHA-pinned**, `permissions` least-privileged, `id-token: write` only where needed — no long-lived signing key or registry token in the job env.

**CI (`ci.yml`, on PR/push):** two jobs. **go:** `go build ./...`, `go vet`, `staticcheck`, **`go test -race ./...` + coverage gate (≥80% `internal/*` — see §25)**, `govulncheck`, and the suspicious-domain lint. **frontend:** rebuilds the admin SPA and verifies the embedded bundle — the frontend **lockfile IS committed** (generated against the public npm registry `https://registry.npmjs.org`; this repo-specific decision overrides the general "don't commit lockfiles" convention), and CI (SHA-pinned `setup-node`, Node 22) runs `npm ci` + `npm run build` + `git diff --exit-code internal/webui/dist` so a stale/hand-edited embedded `dist` fails the build. Both jobs green required to merge.

**Dependency automation:** **Dependabot** (or Renovate) for `gomod`, `github-actions`, and the frontend `npm` ecosystem — grouped, scheduled PRs, gated by `ci.yml` + `govulncheck`.

**App self-update policy:** consistent with §Security — **no silent auto-update**. `poolgate` may *check* and report a newer version, but upgrading is an explicit `brew upgrade` / re-run of the verified installer.

---

# Accepted requirements (v2) — Tiers 1–5

## 19. Correctness rules (routing & upstream) — MUST

- **19.1 Turn affinity (N/A in v1):** v1 forces the **stateless HTTP POST+SSE** path (poolgate does not accept the WS upgrade — §0 D2 / §14), so each request carries its full inline `input` and **no session affinity is needed in v1**. **When WS proxying is added later**, a turn MUST be pinned to one backend keyed on the **`x-codex-turn-state`** token (captured at turn start, resent unchanged within a turn, never reused across turns). This is **not** the §15 monitoring session id and **not** a best-effort optimization — it is turn-scoped **correctness** (see §0 D3). If the pinned backend is unhealthy mid-turn, fail over per the group strategy and signal that server-side (in-memory) turn state may be lost.
- **19.2 Failover boundary + idempotency:** re-selection happens **only before any byte is written to the client** (upstream error status pre-stream, or connect/timeout before first byte). Once streaming starts, propagate the upstream error in-band and stop — never switch mid-stream. Cross-account POST retries are gated to avoid double execution / double token spend; optional `Idempotency-Key` passthrough.
- **19.3 Single-flight token refresh + rotation-safe:** a **single per-account single-flight primitive is shared by both the proxy hot path and the health probe engine** (§12) — concurrent 401s (and any probe-triggered refresh) for one account coalesce into **one** refresh; the rotated `refresh_token` is persisted **atomically (temp+rename), interprocess-safe**, before waiters proceed. Prevents "concurrent refresh invalidates the account" (a reused `refresh_token` permanently bricks it — see §0 D6).
- **19.3a Credential generations (`credential_version`) — authoritative ordering:** every account row carries a **monotonic `credential_version`**. It — not file mtime or a journal `Seq` — is the source of truth for "which credential is newer", because on-disk write order does NOT reflect the causal order tokens were minted upstream (a later file write can hold an older token). All credential mutations are version-aware:
  - **Online refresh (serve/probe):** captures `base = credential_version` at read; commits with a **version CAS** — `UPDATE … SET tokens, credential_version = base+1 WHERE credential_version = base`. If a concurrent **login** already advanced the version, the refresh is **superseded** (skipped) and the caller re-reads the authoritative row rather than returning its now-stale rotated token.
  - **Login / `import --force` (replace):** an **unconditional new generation** (`credential_version = current+1`) — freshly minted creds always win over an in-flight refresh derived from an older generation.
  - **Recovery journal** records `base_version`, `target_version`, and `operation` alongside the sealed tokens. On startup/refresh a journal is applied **only when `DB.credential_version == base_version`** (set to `target_version`) and treated as already-applied when the DB is at/after `target_version`. When a valid, applicable candidate coexists with a corrupt sibling, the corrupt one is provably garbage (a coherent newer generation would require the DB to be past `base_version`) so the valid one is applied and both files cleaned up. Recovery is **fail-closed** (retain, refuse, never guess) when the ordering is genuinely unresolvable: no valid candidate but a corrupt one present; an already-applied/ambiguous valid candidate sitting beside a corrupt (possibly-lost-newer) one; or a version-less legacy journal beside a corrupt sibling. It never silently picks the older token and never auto-deletes an uncertain candidate. This is the mechanism behind the §1 "seamless automatic state recovery on restart" goal.
- **19.3b Cross-process credential lock:** all credential mutations (refresh commit, login/import replace, delete, startup replay) run under a per-data-dir **blocking advisory lock**, so a live `serve` refresh and a CLI `login` in a separate process cannot interleave DB writes or clobber the same journal file. The in-process single-flight (§19.3) only guards one process; this guards across processes.
- **19.3c Command guard ordering (one-shot CLI):** every credential-touching one-shot command acquires guards in ONE fixed order — **single-instance lock** (offline commands only: `backup` / `rotate-key` / `restore`, which must exclude a live `serve`) → **maintenance lock** (serializes one-shots incl. `restore` against each other; concurrent-safe commands `init` / `admin` / `import` / `login` take only this) → **restore-marker check** (LAST, under the locks). Doing the marker check under the locks closes a TOCTOU where a concurrent `restore` sets the marker in the gap; it also fixed `rotate-key`, which previously never checked the marker and could re-encrypt a half-restored DB, and `init` / `admin reset-auth`, which checked with no lock held (audit P1#5). **Safe account delete (P1#4):** `DeleteAccount` commits the DB row deletion FIRST, then removes the (now-moot) rotation journal best-effort — the reverse order could destroy a still-live account's recovery journal if the DB delete then failed. **Login-replace cleanup (P2#8):** likewise, once a login/import `--force` has COMMITTED the new credential generation, removing its recovery journal is best-effort — a cleanup failure never fails the (already-committed) login, and the leftover versioned journal is recognized as already-applied (`dbVer ≥ target`) and dropped by the next recovery pass.
- **19.4 OpenAI-compatible error envelope:** poolgate-originated errors return `{"error":{message,type,code,param}}` with distinct types (`poolgate_no_healthy_account`, `poolgate_all_exhausted`, `poolgate_key_unscoped`, …); upstream error bodies pass through preserving their shape.

## 20. Backup, restore & disaster recovery — MUST

- **20.1 Portable encrypted bundle:** `poolgate backup` → one self-describing encrypted bundle (accounts+tokens, policies/endpoints/keys, and the master key **re-wrapped under a user passphrase**, not the machine keychain). `poolgate restore` re-wraps into the new host's keychain and verifies a decrypt round-trip.
- **20.2 Master-key portability:** restore never relies on the machine-bound keychain/DPAPI key; the passphrase-wrapped key in the bundle is the portable root. Naive file-copy backups are documented as non-portable (they only fail at restore time).
- **20.3 Cold CLI backup only (hot/auto backup are non-goals):** `poolgate backup` is an **offline** operation — it takes the single-instance lock, so `serve` must be **stopped** first. This is a deliberate, permanent design choice, not a temporary limitation: it guarantees no online token refresh can mutate the DB or the out-of-DB rotation journal (§19.3) between the pending-journal check and the DB snapshot. **Live/hot/online backup is a non-goal**, and **automatic/scheduled backup is a non-goal** — backup is a manual, on-demand CLI action (consistent with §0 D9 "on-demand export, no scheduler"). Snapshotting itself uses `VACUUM INTO` for a consistent DB image; the operator runs it while poolgate is stopped.
- **20.4 Migration safety:** persisted schema version; **refuse to start** (clear message) when the binary is older than the DB (downgrade guard); **pre-migration auto-snapshot** for rollback; defined seed-from-YAML ↔ DB-of-record reconciliation.
- **20.5 Scheduled backups — NON-GOAL (superseded by §0 D10 / §20.3):** periodic/automatic encrypted snapshots are **not** provided. Backup is a manual, on-demand cold CLI action with `serve` stopped; retention/scheduling is left to the operator's own tooling (cron + the offline `poolgate backup`) if desired.

## 21. Runtime & deployment operations

- **21.1 Health endpoints:** unauthenticated, secret-free `/healthz` (alive) + `/readyz` (**migrations applied + ≥1 endpoint has a reachable healthy account**), separate from `/e/<ep>/v1`. `/readyz` is **secret-free and leaks no account ids**.
- **21.2 Graceful shutdown:** SIGTERM → stop accepting new, **drain in-flight SSE/streams** to a deadline then force-close, flush pending `request_logs`, persist health state.
- **21.3 Single-instance lock:** flock/PID lock on the data dir; clear "already running" error (no double probe scheduler / port fights).
- **21.4 Clock alignment:** anchor usage windows (e.g. the 5h / weekly example windows — see §0 D4) to upstream usage-endpoint timestamps (not host wall clock); monitor/report clock skew.
- **21.5 Docker hardening:** non-root UID, distroless/scratch (CGO-free build), read-only rootfs + tmpfs, HEALTHCHECK, multi-arch (amd64/arm64).
- **21.6 Recipes:** docker-compose + Caddy/nginx starter configs wiring `external_origin` + `trusted_proxies`; systemd unit sample.
- **21.7 Config surface:** every config key overridable by env var; `_FILE` convention for secrets. Subpath / path-prefix hosting is deferred (v1: deferred — see §0 D9).

## 22. Security hardening additions

- **22.1 SSRF guard** (webhook + upstream-override egress): resolve-then-connect, **block private/loopback/link-local/`169.254.169.254`/ULA/`::1`**, re-validate at connect time (anti DNS-rebinding), HTTPS only.
- **22.2 Proxy-key lifecycle:** per-key expiry + rotation via **multiple active keys + manual rotation** (dual-key grace window dropped); optional per-key IP allowlist; **endpoint scoping** + per-account concurrency caps (a per-key request **rate-limit** is not implemented today — throttling is via the concurrency cap; per-key **spend budgets** dropped — see §0 D9). Keys are stored **hashed** (SHA-256 + a short display hint), never in the clear.
- **22.3 Admin sessions:** lifetime + idle timeout, rotate on register/login, **"revoke all sessions"**; same-origin CORS by default.
- **22.4 Anti-brute-force:** rate-limit + lockout + backoff on recovery-code and bootstrap-token attempts.
- **22.5 Audit log:** completeness spec (auth, CRUD, key use, config changes) + **append-only**, and a **keyless SHA-256 hash chain** (re-added post-v1, PR #53) detecting accidental corruption + mid-log tamper/delete/reorder via `GET /admin/api/audit/verify`; it does NOT detect tail-truncation or a DB writer who recomputes the tail (would need an out-of-DB key / external notarization).
- **22.6 Master-key rotation:** **done post-v1 (PR #54)** — `poolgate rotate-key` mints a fresh master key and bulk re-encrypts every secret column (account access/refresh tokens, notify channel config) in one transaction, writing a pre-rotation snapshot first, taking the single-instance lock, and atomically swapping the keyfile (or printing the new key for `master_key_source=env`). backup/restore (§20) also covers key portability.
- **22.7 Request-body logging:** off by default; explicit opt-in with redaction.

## 23. Routing & account additions

- **23.1 Concurrency:** per-account concurrency cap + **least-in-flight** selection (a refinement within `load-balance`, not a separate strategy — see §0 D7); when no member is free the proxy **fails fast** with 429 + Retry-After by default. Optional bounded-queue backpressure (wait briefly for a slot before 429) is opt-in via `server.backpressure_wait` (a duration; empty/0 = fail fast).
- **23.2 Match rules:** per-endpoint/key **model allow-deny** is **deferred** — the `ApiKey` model carries no model-scope field and nothing enforces one in v1; the shipped per-key controls are endpoint scoping + IP allowlist (+ expiry). The Surge-style match-rule engine (model / header / path → group) is likewise **deferred** (see §0 D9).
- **23.3 Upstream rate limits:** relay upstream rate-limit headers to the client; drive cooldown from `Retry-After`.
- **23.4 Streamed token accounting:** parse SSE `usage` / `include_usage` to record tokens for streamed responses (feeds §15 + budgets).
- **23.5 Route matrix + allowlist:** the **inbound** surface implemented in v1 is the Responses API **only** — `POST /e/<ep>/v1/responses` (HTTP+SSE) and `GET /e/<ep>/v1/responses` (WebSocket upgrade), plus the unauthenticated `/healthz` + `/readyz`. The broader OpenAI-compatible routes (`/v1/chat/completions`, a synthesized `/v1/models`, `/v1/messages`) are **deferred** — not yet registered. Routing is **allowlist-only** (no blanket path forwarding to the upstream token). **Upstream is a translation gateway, not a transparent reverse proxy:** `Authorization` + `ChatGPT-Account-ID` are rewritten **together** and Codex identity headers preserved (see §0 D1 / §6). **Transport:** serves HTTP POST+SSE (stateless) and, post-v1 (PR #46/#50), the **WebSocket** upgrade — configurable via `server.transport` (see §0 D2).
- **23.6 Account states & login:** terminal `revoked`/`dead` (no auto-recovery — §4/§12) vs transient `expired`; duplicate dedup by account id on import; archive/soft-delete + **crypto-shred**; interactive **OAuth authorization-code login with PKCE** — **loopback callback + single-use `state` + S256** (see §0 fixes) + MFA (not just JSON import), headless handoff.

## 24. Observability & UX additions

- **24.1 Logs/trace:** structured **slog JSON** (stdout/file, rotation) + the in-app monitor (§15); per-request routing/failover **decision trace**. Prometheus `/metrics` is **dropped from v1** and OpenTelemetry is **not in scope** (see §0 D9).
- **24.2 Quota forecast (display-only):** burn-rate over the generic percent-usage windows (`health_checks` series) → "hits 0 at ~HH:MM before reset" as a **display aid only**; `best-quota` routes on **current** headroom (min `(100 − used_percent)` across windows — §4 / §0 D4 / D7), not projected. Shown alongside the 3–4 headline counters (§15); full chart suite deferred (§0 D9).
- **24.3 Client-config generator:** per-endpoint panel + key picker → copy-ready blocks (Codex `~/.codex/config`, Cursor base_url+key, curl, OpenAI SDK env).
- **24.4 Test & dry-run:** inline "test this endpoint" + policy **dry-run** ("which account would be picked now").
- **24.5 Safe destructive ops:** blast-radius confirmation + soft-delete/undo.
- **24.6 Exports:** **on-demand** usage CSV/JSON export only (scheduler dropped). Cost-per-token / subscription-value accounting is **cut** (see §0 D9).
- **24.7 Theme:** **single UI language + dark mode** in v1. i18n framework, accessibility program, and mobile-responsive layout are **deferred** (see §0 D9).

## 25. Testing & QA plan

**Mandatory UT coverage (project rule):** every package ships with unit tests — no package is merged without them. CI enforces `go test ./...` **and `-race`**, plus a **coverage floor** (≥ 80% for `internal/*`; the security/correctness-critical logic — `crypto`, `store`, `oauth` refresh single-flight, `gateway` header-rewrite + auth + failover, `policy` selection — is held near-full). Tests are written **alongside** each stage, not deferred. Prefer table-driven tests + the fake upstream (§25.1) + an injectable clock (§25.3) so everything is deterministic.

- **25.1 Fake upstream:** in-process `httptest` fake (scripted SSE, 401/429/5xx, latency, quota/plan JSON) + **golden contract fixtures** vs real OpenAI/ChatGPT shapes.
- **25.2 Streaming chaos:** mid-stream account death, client-disconnect → upstream cancellation, failover-boundary (§19.2) correctness.
- **25.3 Deterministic engine tests:** policy engine for the **4 v1 strategies** (fallback order, `load-balance` round-robin fairness, `weighted` proportional split, `best-quota` headroom + deterministic tie-break) + health state machine with an **injectable clock**. (Cycle-reject / nesting tests are deferred with those features — see §0 D7/D8.)
- **25.4 Concurrency/soak:** single-flight refresh under N concurrent 401s (§19.3); SQLite under load.
- **25.5 CI matrix:** OS seams (keychain/DPAPI, modernc sqlite, migrations); fuzz SSE relay + trusted-proxy parsers. (Reproducible-build verification is deferred with the SLSA/reproducible-build gate — see §0 D9.)

## 26. Backlog (accepted, later)

Canary/shadow mirroring is **out of scope** for single-user. Remaining niceties (cost accounting, scheduled exports, full data-wipe) are folded above where cheap; implement opportunistically after Phases 1–5.

## 27. Section → phase mapping

§19 + §23 → **Phase 2** (proxy/policy correctness). §20 (+§21.3/.4) → **Phase 1 & 5**. §21 health/drain → **Phase 2**, Docker/recipes/config → **Phase 5**. §22 → **Phase 3**. §24 → **Phase 4** (metrics/trace also Phase 2). §25 → **all phases** (write tests alongside each).

