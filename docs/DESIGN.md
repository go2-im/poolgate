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

**All listener ports are configurable** (admin + proxy), defaults are just defaults.

The binary **never launches or manages a tunnel itself** — but it is built to run **smoothly behind whatever you put in front of it**: a reverse proxy (Caddy/nginx) *or* an external tunnel you run (cloudflared, ngrok, etc.). See §14 for how (trusted-proxy headers, external origin, streaming pass-through). So "remote" = you front the loopback listener with your own TLS reverse proxy or tunnel.

> WebAuthn passkeys are bound to the RP ID (domain). A passkey registered on `localhost` will not work on `your.domain` and vice-versa — register one per environment (or one roaming/phone passkey usable across them). RP ID / origin are config (and can be derived from trusted forwarded headers, §14). **Cross-device / QR sign-in is supported** — the WebAuthn config allows platform, cross-platform, and hybrid (caBLE) authenticators, so the browser can show a QR code to authenticate with a passkey on your phone (§16).

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

## 4. Policy engine (Surge-inspired)

Three entities:

- **Account** — a pooled Codex/ChatGPT credential (the leaf "proxy"). Carries a **state** (`ok` / `cooldown` / `quota_exhausted` / `expired` / `unknown`), last usage snapshot (5h / 1week windows, plan), and measured latency. State is maintained both passively (from real proxy traffic) and actively by the **health probe engine** (§12), which auto-recovers accounts when their quota/rate-limit clears. Also carries **management metadata** — **subscription type** (Free / Plus / Pro / Team / Enterprise / …, auto-detected from the plan endpoint where possible, editable), **subscription region/zone**, a human **label**, and free-form **tags/category** — used by the admin UI for grouping, search and sort (§13), and usable as account selectors when composing policies (e.g. "a policy over all Pro accounts in region US").
- **PolicyGroup** — named, has a `type` (strategy) and an **ordered member list**; each member is an Account **or another PolicyGroup** (nesting → a DAG; cycles rejected). Strategies:
  - `select` — manually pinned member.
  - `fallback` — first healthy in order; on 401/429/5xx/timeout advance + cooldown the failed member.
  - `round-robin` — rotate across healthy members.
  - `load-balance` — distribute (round-robin or weighted).
  - `url-test` — periodic health/latency probe; route to lowest-latency healthy member (interval configurable).
  - `best-quota` — route to the member with the most remaining usage (≈ codex-tools `switch --best`).
- **Endpoint** — a named inbound route bound to one PolicyGroup, surfaced as a distinct URL: `/e/<endpoint>/v1/...`. The caller picks a strategy by choosing the URL. API keys can be scoped to specific endpoints.

**A PolicyGroup _is_ your custom named strategy** — you bind an explicit subset of accounts to a strategy type, and reuse it. This is the primary, flexible/controllable model:

- `policy-1` = `round-robin` (balance) over **{A, B, C}**
- `policy-2` = `fallback` over **{A, C}**

Each named policy is independent and reusable; the **same account may appear in multiple policies**, and a policy contains only the accounts you choose (not the whole pool). Groups may additionally **nest** (a member can be another group) for advanced composition, but the common case is a flat named policy over a hand-picked account set. Each endpoint URL binds to one such policy, so different URLs = different account-set + strategy combinations.

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
- **Tables (initial):** `accounts` (incl. `subscription_type`, `region`/`zone`, `tags`, `label`, state, usage snapshot, latency), `policy_groups`, `group_members`, `endpoints`, `api_keys`, `key_scopes`, `webauthn_credentials`, `usage_snapshots`, `health_checks`, `request_logs` (time, api_key_id, session_id, endpoint, policy, account_id, model, status, latency_ms, tokens_in/out), `audit_log`, `settings`.

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
- Reverse proxy: `net/http/httputil.ReverseProxy` (FlushInterval=-1 for SSE) or manual relay.
- Frontend: **React** (Vite), built to static assets, embedded via `go:embed`.
- Config: **YAML**.
- Release/dist: **GoReleaser** (archives, Homebrew tap, Scoop, nfpm deb/rpm, Docker), **cosign** (keyless OIDC signing) + SLSA provenance, **Dependabot/Renovate** + `govulncheck` for dependency automation.

## 9. Build phases

1. **Core:** `config`, `store` (SQLite + field encryption; encrypt/decrypt round-trip test), `oauth` (login/import/refresh, issuer pinned). Plus **`poolgate init`** auto-provisioning + startup migrations (§17).
2. **Policy + proxy:** `policy` engine (strategies + nesting + cycle check + health), `proxy` server (`/e/<ep>/v1`, sk- auth, SSE, egress allowlist), **trusted-proxy header handling + streaming pass-through for tunnels/reverse-proxies (§14)**, per-request logging with session/model/tokens (§15).
   - **`health`**: probe engine + account state machine (usage-poll / auth-check / small live request), adaptive per-state scheduling, auto-recovery, feeds `url-test`/`best-quota` (see §12).
3. **Admin API + passkey:** WebAuthn register/login (bootstrap token, multiple passkeys, recovery codes, `admin reset-auth` CLI), session + CSRF, CRUD for accounts/groups/endpoints/keys. Accounts list API supports metadata (subscription type / region / tags), filter / search / sort / paginate in SQL (§13).
   - **`notify`**: channel CRUD (DingTalk / WeCom / custom webhook) + a "test" button; alert rules wired to policy/proxy events (see §11).
4. **Web UI:** React pages (login, dashboard/usage, accounts w/ categorize·search·sort, policy groups w/ composition view, endpoints, keys, **real-time monitor** — live scrolling logs + charts filterable by session/api-key/model (§15), settings), `go:embed`. Admin server exposes an SSE/WS live-events stream.
5. **Release:** GoReleaser-driven — cross-compiled single binary, `SHA256SUMS` + cosign signature, SLSA provenance, Homebrew tap / Scoop / Docker / deb-rpm, verification-gated `install.sh`, SHA-pinned CI, Dependabot, no silent auto-update, `docs/BUILD.md` (§18).
6. **Optional:** usage charts, account cooldown tuning, weighted load-balance.

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
| Quota low / exhausted | remaining 5h or 1week usage below threshold |
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

1. **Usage poll (zero token spend)** — read the ChatGPT usage endpoint for remaining 5h / 1week windows + plan. Primary signal for quota level and for detecting a reset. Default cadence for all accounts.
2. **Auth check (no/near-zero spend)** — `GET /v1/models` (or equivalent) to confirm the token is still valid (catches `expired`).
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

- Real proxy traffic transitions passively (401→try refresh→`expired`; 429/5xx→`cooldown`; quota=0→`quota_exhausted`).
- The probe engine transitions actively **and drives recovery**: degraded accounts (`cooldown` / `quota_exhausted`) are re-probed on a **shorter, backing-off interval** so recovery is discovered quickly; `ok` accounts are polled on a longer interval. On a successful probe, the account returns to `ok` and re-enters policy rotation automatically.

**Scheduling & cost control (all configurable):**

- Per-state intervals: e.g. `ok` usage-poll every N min; `cooldown`/`quota_exhausted` re-probe every M min with exponential backoff up to a cap; `expired` retried rarely (needs re-auth).
- Global mode switch: **usage-poll-only** (zero token spend) vs **allow small live requests** for degraded/recovery checks. Per-account override.
- Jittered schedules to avoid synchronized bursts; single-flight per account (no overlapping probes); probe results also feed the `url-test` (latency) and `best-quota` (remaining quota) policy strategies.

**Persistence & UI:** latest state + usage + latency per account in `accounts`; probe history in a `health_checks` table (pruned). The admin UI shows live per-account state, remaining quota bars, last-probe time, and a manual "probe now" button.

**Notifications:** state transitions fire alerts via `notify` (§11) — including a **recovered** event (`cooldown`/`quota_exhausted` → `ok`), plus degraded/expired/quota-low. Recovery notifications must reference the account by label/id only.

## 13. Account management (metadata, categorize, search, sort)

Each account carries management metadata (see §4): **subscription type**, **region/zone**, **label**, **tags/category**. The admin UI's Accounts view is built for a pool that may grow to dozens/hundreds:

- **Categorize / group by:** subscription type, region/zone, tag/category, or state.
- **Search / filter:** free-text over label/tags + faceted filters (type, region, state, quota range, "in policy X", "healthy only").
- **Sort:** by label, subscription type, region, state, remaining 5h/1week quota, latency, last-probe time, created/updated.
- **Bulk actions:** tag, set region/type, enable/disable, "probe now", add-to-policy.
- Subscription type is auto-detected from the plan endpoint where possible and stays editable; region/zone is a user-selected value (dropdown, config-defined list) — since it may not be reliably detectable.

Backed by indexed columns in `accounts`; the list API takes `filter` / `q` / `sort` / `page` params so filtering and sorting happen in SQL, not in the browser.

## 14. Ports, reverse-proxy & tunnel compatibility

Ports are fully configurable, and poolgate is designed to sit behind whatever fronting you choose (you run it; poolgate does not).

- **Configurable listeners:** `server.admin.{host,port}` and `server.proxy.{host,port}`; both default to loopback and can be changed freely.
- **Trusted proxies:** `server.trusted_proxies` (CIDR list). Only when the peer is a trusted proxy does poolgate honor `X-Forwarded-For` / `-Proto` / `-Host` (real client IP for logs/rate-limit, external scheme/host for URL/RP-origin). Untrusted peers' forwarded headers are ignored → no IP/host spoofing.
- **External origin:** `server.external_origin` (e.g. `https://poolgate.example.com`) sets the canonical scheme+host used for WebAuthn RP origin, cookie flags, and the proxy URLs shown in the UI to copy into Codex/Cursor — so behind a cloudflared/ngrok URL the UI shows the *public* endpoint, not `127.0.0.1`.
- **Streaming through tunnels:** SSE and WebSocket (`/v1/responses`, chat streaming) pass through with immediate per-chunk flush, `Cache-Control: no-transform`, no response buffering, and keep-alives tuned so cloudflared/ngrok/nginx don't buffer or drop long-lived streams. Idle/read timeouts are generous for streaming routes.
- **Still loopback by default:** the tunnel/proxy connects to the loopback listener; you never have to bind `0.0.0.0`.

> Security: since a tunnel makes the proxy effectively public, the `sk-` key remains the gate (constant-time). Do **not** expose the *admin* listener through a tunnel unless you intend to — and even then it is passkey-gated. Trusted-proxy parsing is strict to prevent spoofed client IPs. (See `docs/SECURITY.md`.)

## 15. Real-time request monitoring

A live observability view in the admin UI, backed by the proxy's per-request records.

- **Live log stream:** the admin server pushes new request records over SSE/WebSocket; the UI shows a **real-time scrolling log** (auto-scroll, pause, tail). Each row: time, endpoint, policy, chosen account (label), model, api-key (label), session, status, latency, tokens (in/out).
- **Charts / volume:** request rate over time, latency percentiles, token throughput, success vs error, and breakdowns by account / key / model — rolling windows with live update.
- **Filters:** by **session**, **api-key**, and **model** (composable), plus endpoint/account/status/time-range. Filtering runs in SQL over `request_logs` for history and is also applied to the live stream.
- **Session definition:** best-effort grouping — a client-supplied conversation/session id header if present, else derived per (api-key + client) connection; documented so it's predictable.
- **Storage/retention:** `request_logs` (indexed on time, api_key_id, model, session_id, account_id, status) with configurable retention/prune; aggregates can be rolled up to keep charts fast. No secrets in logs.

## 16. Admin auth details (passkey, QR/cross-device, CLI reset)

- **Passkey primary, no password.** Registration allows **platform** (Touch ID / Windows Hello), **cross-platform** (security keys), and **hybrid/caBLE** authenticators → the browser offers **QR-code sign-in with your phone**. Multiple passkeys can be registered (recommend a phone passkey + a hardware key backup).
- **Recovery:** one-time recovery codes generated at setup (shown once).
- **CLI full reset (always available locally):** `poolgate admin reset-auth` **completely resets admin login** — removes **all** registered passkeys, invalidates recovery codes and active sessions, and re-issues a one-time bootstrap registration token (printed to the local console). This is the guaranteed lockout escape hatch; it requires local shell access to the host (which already implies full control), never a network path.

## 17. First-run initialization (auto-provisioning)

Zero-to-running should be one step; setup is guided and idempotent.

- **`poolgate init`** (CLI): creates the config dir + data dir, generates the **master key** into the OS keychain (fallback `master.key`, `0600`), runs SQLite **schema migrations**, writes a default `config.yaml` (loopback defaults), and prints a **one-time admin bootstrap URL/token** to register the first passkey. Idempotent — safe to re-run; missing pieces are filled in.
- **Auto-migrate on startup:** every launch runs pending DB migrations, so upgrades need no manual DB steps.
- **Web first-run wizard:** if no passkey is registered, the admin UI opens a setup wizard — register first passkey (QR or platform), set `external_origin`/`rp_id`, import the first account(s), and create a starter policy + endpoint.
- **Docker/headless:** env-var-driven init (`POOLGATE_*`), data on a mounted volume; bootstrap token surfaced in container logs.

## 18. Distribution, packaging & release automation

Driven by **GoReleaser** + **GitHub Actions**; every channel ships verifiable artifacts.

**Install channels (Homebrew primary):**

- **Homebrew tap** — `brew install go2-im/tap/poolgate` (formula auto-updated on release; macOS + Linux).
- **Scoop / winget** — Windows (optional).
- **Docker image** — `ghcr.io/go2-im/poolgate` (self-host).
- **deb/rpm** via `nfpm` — Linux servers (optional).
- **One-line install script** — `install.sh` detects OS/arch, downloads the matching archive from the latest GitHub Release, **verifies `SHA256SUMS` + the cosign signature before installing** (never a blind `curl | sh`; Homebrew is still the recommended path). This directly addresses the audited "unverifiable binary / curl-pipe-sh" risk.

**Release CI (`release.yml`, on tag `v*`):** GoReleaser cross-compiles (darwin/linux/windows × amd64/arm64), builds archives + `SHA256SUMS`, **signs with cosign (keyless via GitHub OIDC)**, emits **SLSA provenance / artifact attestations**, publishes the GitHub Release, updates the Homebrew tap, and pushes the Docker image. All third-party Actions are **SHA-pinned**, `permissions` least-privileged, `id-token: write` only where needed — no long-lived signing key or registry token in the job env.

**CI (`ci.yml`, on PR/push):** `go build ./...`, `go vet`, `staticcheck`, unit tests, `govulncheck`, frontend build, and the suspicious-domain lint — all green required to merge.

**Dependency automation:** **Dependabot** (or Renovate) for `gomod`, `github-actions`, and the frontend `npm` ecosystem — grouped, scheduled PRs, gated by `ci.yml` + `govulncheck`.

**App self-update policy:** consistent with §Security — **no silent auto-update**. `poolgate` may *check* and report a newer version, but upgrading is an explicit `brew upgrade` / re-run of the verified installer.

