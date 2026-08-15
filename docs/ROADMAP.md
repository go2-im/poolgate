# poolgate — Roadmap & Continuation Plan

**Purpose:** hand-off doc so a *fresh* session (new context, no memory of prior chats) can pick up and finish poolgate. Read this first, then `docs/DESIGN.md` **§0** (authoritative decisions) + `docs/REVIEW.md` (verified Codex facts).

---

## 1. What poolgate is

Single-user, self-hostable manager + **OpenAI-compatible reverse proxy (translation gateway)** for a pool of Codex/ChatGPT accounts, with a composable routing-policy engine and a passkey-protected web admin UI. Single Go binary; pure-Go SQLite; embedded web UI.

## 2. Status (as of this doc)

**Done & on `main`:** Phase 1 (config/store/crypto/oauth/init), Phase 2a (translation gateway, one account E2E), Phase 2b (policy strategies + health engine + usage model), **Phase 3** (admin backend: passkey/WebAuthn auth, sessions/CSRF/CSP, admin REST API incl. import endpoint, second loopback listener), **Notifications backend** (`internal/notify`: DingTalk/WeCom/webhook channels + SSRF-guarded egress + dispatcher, wired to health/gateway events — PR #3), **Real-time monitor backend** (`internal/monitor`: request_logs + filtered SSE stream + headline counters + decision trace + best-effort token sniff — PR #6), **Advanced routing (concurrency half)** (per-account concurrency cap + least-in-flight load-balance + bounded-queue 429 backpressure — PR #7), **Phase 4 admin UI (first slice)** (`internal/webui` go:embed + SPA serve handler; React+Vite app in `web/` with passkey login — register/login/recovery — and a dashboard reading status/usage/health; built bundle committed — PR #9), **CI** (`.github/workflows/ci.yml`), and from-source **install + uninstall** scripts (`scripts/install.sh`, `scripts/uninstall.sh` — PR #4).

**Packages (17, all ≥80% unit-test coverage, total ~91%):** `model config crypto store oauth gateway authimport usage policy health adminauth webauthnsvc admin notify monitor webui` + `cmd/poolgate`.

**Verified toolchain state:** `go build ./... && go vet ./... && staticcheck@2026.1 ./... && go test -race ./...` all green; CI enforces a ≥80%-per-package coverage gate.

## 3. Remaining work (dependency order)

Do these as separate branches → PRs (see §5). Each must keep the ≥80% coverage gate green.

1. **Phase 4 — React admin UI (remaining pages)** (`web/`, Vite, embedded via `go:embed`). **Done (PR #9):** the embed/serve foundation (`internal/webui`), passkey **login** (bootstrap-token register + login + recovery), and a **dashboard** (status/usage/health). **Remaining pages:** accounts (categorize/search/sort + **Import account** button → `POST /admin/api/accounts/import` + per-account concurrency cap), policy groups editor, endpoints (+ copy-ready client-config generator for Codex/Cursor/curl/SDK), api keys, **notifications** (channel CRUD + send-test, over `/admin/api/notify/channels`), **real-time monitor** (live SSE log + counters + filters, over `/admin/api/monitor/*`), settings. QR/cross-device passkey registration polish. DESIGN §9 phase 4, §11, §13, §15, §24.3–24.5. Single UI language + dark mode only (i18n framework/a11y/mobile deferred). Build note: the committed bundle is produced with `cd web && npm install && npm run build` (see `web/README.md`).
2. **Phase 5 — Release pipeline** — `.github/workflows/release.yml` + GoReleaser: cross-compiled signed binaries + `SHA256SUMS` + **cosign (keyless OIDC)**, **Homebrew tap** (`go2-im/homebrew-tap`), **Docker image** (`ghcr.io/go2-im/poolgate`), verified `install.sh` for binaries; Dependabot; `docs/BUILD.md`. SHA-pin all actions; least-priv perms. Defer full SLSA provenance + reproducible-build gate + Scoop/winget/deb-rpm. DESIGN §18, §0 D9.
3. **Ops/DR & security hardening** — `poolgate backup`/`restore` (portable passphrase-wrapped bundle + master-key portability), schema-version downgrade guard + pre-migration snapshot, graceful-shutdown SSE drain, single-instance lock, clock-alignment to upstream usage timestamps, Docker hardening (non-root/distroless/read-only rootfs), docker-compose + Caddy/nginx recipes, full env-var override (`_FILE` secrets), memory hygiene (disable core dumps, mlock master key), proxy-key lifecycle (expiry/rotation/IP-allowlist), audit-log completeness (append-only). DESIGN §20, §21, §22.
4. **Interactive OAuth login (rest of advanced routing)** — OAuth authorization-code login with **PKCE** (loopback callback + single-use `state` + S256) beyond JSON import, so accounts can be added by signing in (§23.6). The concurrency/backpressure half of §23.1 is done (PR #7); the deferred `auth_anomaly` + `startup_bind_warning` notify events (the `notify` engine already defines those kinds) can be wired here or with the monitor UI. DESIGN §23.6, §0 fixes.

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

1. `git -C $HOME/workspaces/danny-plus/poolgate/main fetch --prune && git -C .../main merge --ff-only origin/main` (get the merged monitor / routing / admin-UI PRs).
2. Read this file + DESIGN §0 + REVIEW §1.
3. Next up is item 1's **remaining Phase 4 pages** (accounts / endpoints / keys / notifications / monitor / settings — all their backends are merged), then 2 → 3 → 4. The admin UI source is in `web/` (rebuild the embedded bundle with `npm run build`).
4. Branch → sequential build Workflow → verify gate locally → PR → merge.
