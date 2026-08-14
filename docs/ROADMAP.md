# poolgate — Roadmap & Continuation Plan

**Purpose:** hand-off doc so a *fresh* session (new context, no memory of prior chats) can pick up and finish poolgate. Read this first, then `docs/DESIGN.md` **§0** (authoritative decisions) + `docs/REVIEW.md` (verified Codex facts).

---

## 1. What poolgate is

Single-user, self-hostable manager + **OpenAI-compatible reverse proxy (translation gateway)** for a pool of Codex/ChatGPT accounts, with a composable routing-policy engine and a passkey-protected web admin UI. Single Go binary; pure-Go SQLite; embedded web UI.

## 2. Status (as of this doc)

**Done & on `main`:** Phase 1 (config/store/crypto/oauth/init), Phase 2a (translation gateway, one account E2E), Phase 2b (policy strategies + health engine + usage model), **Phase 3** (admin backend: passkey/WebAuthn auth, sessions/CSRF/CSP, admin REST API incl. import endpoint, second loopback listener), **CI** (`.github/workflows/ci.yml`), and a from-source install script (`scripts/install.sh`).

**Packages (14, all ≥80% unit-test coverage, total ~92%):** `model config crypto store oauth gateway authimport usage policy health adminauth webauthnsvc admin` + `cmd/poolgate`.

**Verified toolchain state:** `go build ./... && go vet ./... && staticcheck@2026.1 ./... && go test -race ./...` all green; CI enforces a ≥80%-per-package coverage gate.

## 3. Remaining work (dependency order)

Do these as separate branches → PRs (see §5). Each must keep the ≥80% coverage gate green.

1. **Notifications module (`internal/notify`)** — DingTalk / WeCom / custom-webhook channels + alert rules wired to health/policy events (account expired/cooldown/recovered, policy-no-healthy-member, quota-low, auth anomalies). **SSRF guard** on webhook egress (block private/loopback/link-local/metadata IPs, resolve-then-connect, HTTPS-only). Never put secrets in alert payloads. See DESIGN §11, §22.1. *(Backend; UI in step 3.)*
2. **Real-time monitor backend** — admin SSE/WS stream of per-request records; headline counters (3–4); filter by session/api-key/model; per-request routing/failover decision trace; quota-burn *display-only* forecast. Sanitize client-supplied fields before persisting/streaming. DESIGN §15, §24.1–24.2.
3. **Phase 4 — React admin UI** (`web/`, Vite, embedded via `go:embed`) — the biggest chunk. Pages: passkey login (register via bootstrap token + QR/cross-device; login; recovery), dashboard/usage, accounts (categorize/search/sort + **Import account** button → `POST /admin/api/accounts/import`), policy groups editor, endpoints (+ copy-ready client-config generator for Codex/Cursor/curl/SDK), api keys, real-time monitor (live log + counters + filters), settings, dark mode. DESIGN §9 phase 4, §13, §15, §24.3–24.5. Single UI language + dark mode only (i18n framework/a11y/mobile deferred).
4. **Phase 5 — Release pipeline** — `.github/workflows/release.yml` + GoReleaser: cross-compiled signed binaries + `SHA256SUMS` + **cosign (keyless OIDC)**, **Homebrew tap** (`go2-im/homebrew-tap`), **Docker image** (`ghcr.io/go2-im/poolgate`), verified `install.sh` for binaries; Dependabot; `docs/BUILD.md`. SHA-pin all actions; least-priv perms. Defer full SLSA provenance + reproducible-build gate + Scoop/winget/deb-rpm. DESIGN §18, §0 D9.
5. **Ops/DR & security hardening** — `poolgate backup`/`restore` (portable passphrase-wrapped bundle + master-key portability), schema-version downgrade guard + pre-migration snapshot, graceful-shutdown SSE drain, single-instance lock, clock-alignment to upstream usage timestamps, Docker hardening (non-root/distroless/read-only rootfs), docker-compose + Caddy/nginx recipes, full env-var override (`_FILE` secrets), memory hygiene (disable core dumps, mlock master key), proxy-key lifecycle (expiry/rotation/IP-allowlist), audit-log completeness (append-only). DESIGN §20, §21, §22.
6. **Advanced routing** — per-account concurrency cap + least-in-flight + bounded queue/backpressure; interactive OAuth authorization-code (PKCE) login beyond JSON import. DESIGN §23.1, §23.6.

**Later / backlog:** WebSocket transport proxying + **`x-codex-turn-state` turn affinity** (DESIGN §0 D2/D3, §19.1) — needed only if not forcing HTTP fallback; nested policy groups; match-rule engine; master-key rotation; subpath hosting; weighted load-balance; expanded charts; i18n/a11y/mobile; cost accounting; hash-chain audit. (Schema hooks for these already exist where noted.)

## 4. Critical Codex-0.147.0 facts (don't re-derive wrong)

Verified against `openai/codex@rust-v0.147.0` (see REVIEW.md §1):
- **Translation gateway, not transparent proxy:** upstream `https://chatgpt.com/backend-api/codex/responses`, `stream:true` + `Accept: text/event-stream`; rewrite `Authorization` **and** `ChatGPT-Account-ID` **together**; preserve `originator`(=`codex_cli_rs`)/`User-Agent`/`OpenAI-Beta`/`x-codex-turn-state`.
- **Transport:** Codex tries **WebSocket first**; v1 **does not accept the WS upgrade** → Codex falls back to stateless HTTP POST+SSE. WS proxying + turn-affinity is deferred.
- **Usage:** `GET /backend-api/wham/usage` → generic `plan_type` + percent windows `{used_percent, window_seconds, resets_at}` (NOT fixed 5h/1week token columns).
- **Auth-check probe:** real `GET {base}/models?client_version=` (200 valid / 401·403 invalid).
- **OAuth:** refresh **rotates** the refresh_token; a reused one permanently bricks the account → per-account single-flight refresh + atomic persistence (already implemented in `internal/oauth`).

## 5. Dev conventions (a new session MUST follow)

- **Repo:** `go2-im/poolgate` (public). Layout = bare repo + worktrees under `$HOME/workspaces/danny-plus/poolgate/`: `.bare/` (hub), `main/` (main worktree), plus feature worktrees. Git over **SSH** (`git@github.com:go2-im/poolgate.git`); commit identity `danny <danny@go2.im>`.
- **`main` is protected — PR only.** No direct pushes. Each item above = a feature branch → PR → CI `go` check green → squash-merge (auto-merge is on; head branch auto-deleted on merge). For go2-im API/PR ops via `gh`, use the token: `secret-load GITHUB_TOKEN_GITHUB_COM_GO2IM -- bash -c 'export GH_HOST=github.com GH_TOKEN="$GITHUB_TOKEN_GITHUB_COM_GO2IM"; gh ...'` (git push itself is SSH).
- **CI gate:** `ci.yml` runs build/vet/staticcheck@2026.1/`go test -race`/**coverage ≥80% per package**/govulncheck(advisory)/domain-lint. Keep it green; **every package needs unit tests** (DESIGN §25).
- **Authoritative design:** `docs/DESIGN.md §0` supersedes conflicting prose below it. `docs/REVIEW.md` = the two audits + Codex verification. `docs/SECURITY.md` = hardening matrix.
- **Build approach that worked:** for each phase, run a **sequential Workflow** (contract/foundation → deps → integrate), keep each stage small (a too-large stage once blew the structured-output cap — split it), each stage runs `go build/vet/staticcheck/test -race`. **Always verify the full gate locally yourself before trusting a workflow's "green" and before opening the PR** (IDE/gopls diagnostics are often stale mid-run — the real toolchain is the source of truth). Then push branch → open PR → auto-merge.
- **Import is always explicit** (CLI `poolgate import <path>` + admin-UI button); never auto-import.
- **Secrets:** never print/log token values; app secrets field-encrypted at rest; keychain via `secret-*` helpers + `sys_envs/secret-map.json`.

## 6. Suggested next-session kickoff

1. `git -C $HOME/workspaces/danny-plus/poolgate/main fetch --prune && git -C .../main merge --ff-only origin/main` (get merged Phase 3).
2. Read this file + DESIGN §0 + REVIEW §1.
3. Pick item 1 (Notifications) or item 3 (Phase 4 UI) — recommended order is 1 → 2 → 3 (so the UI can surface notifications + live monitor together), then 4 → 5 → 6.
4. Branch → sequential build Workflow → verify gate locally → PR → merge.
