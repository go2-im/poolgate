# poolgate — Roadmap & Continuation Plan

**Purpose:** hand-off doc so a *fresh* session (new context, no memory of prior chats) can pick up and finish poolgate. Read this first, then `docs/DESIGN.md` **§0** (authoritative decisions) + `docs/REVIEW.md` (verified Codex facts).

---

## 1. What poolgate is

Single-user, self-hostable manager + **OpenAI-compatible reverse proxy (translation gateway)** for a pool of Codex/ChatGPT accounts, with a composable routing-policy engine and a passkey-protected web admin UI. Single Go binary; pure-Go SQLite; embedded web UI.

## 2. Status (as of this doc)

**Done & on `main`:** Phase 1 (config/store/crypto/oauth/init), Phase 2a (translation gateway, one account E2E), Phase 2b (policy strategies + health engine + usage model), **Phase 3** (admin backend: passkey/WebAuthn auth, sessions/CSRF/CSP, admin REST API incl. import endpoint, second loopback listener), **Notifications backend** (`internal/notify`: DingTalk/WeCom/webhook channels + SSRF-guarded egress + dispatcher, wired to health/gateway events — PR #3), **Real-time monitor backend** (`internal/monitor`: request_logs + filtered SSE stream + headline counters + decision trace + best-effort token sniff — PR #6), **Advanced routing (concurrency half)** (per-account concurrency cap + least-in-flight load-balance + bounded-queue 429 backpressure — PR #7), **Phase 4 admin UI (complete)** (`internal/webui` go:embed + SPA serve handler; React+Vite app in `web/`): passkey login (register/login/recovery) + dashboard (PR #9); accounts / policy groups / endpoints / api keys management pages (PR #11); and **notifications** (channel CRUD + send-test), the **real-time monitor** (live `EventSource` SSE tail + headline counters + composable filters), and **settings** (revoke-all-sessions, register-additional-passkey, WebAuthn scope panel) — plus a new secret-free `GET /admin/api/settings` endpoint (PR #13); built bundle committed. **CI** (`.github/workflows/ci.yml`), and from-source **install + uninstall** scripts (`scripts/install.sh`, `scripts/uninstall.sh` — PR #4).

**Packages (19, all ≥80% unit-test coverage, total ~91%):** `model config crypto store oauth gateway authimport usage policy health adminauth webauthnsvc admin notify monitor webui backup lock` + `cmd/poolgate`.

**Release pipeline (Phase 5 — PR #15):** `poolgate version` (ldflags-stamped) + `.goreleaser.yaml` (pinned GoReleaser v2.8.2): static reproducible binaries (linux/darwin × amd64/arm64), `SHA256SUMS`, **cosign keyless** signing of checksums **and** image manifests, multi-arch images to `ghcr.io/go2-im/poolgate` (`:latest` prerelease-guarded), Homebrew tap `go2-im/homebrew-tap`; distroless nonroot `Dockerfile.goreleaser`; SHA-pinned `release.yml` (least-priv, single-flight); `dependabot.yml`; `docs/BUILD.md`. Fires on a pushed `v*` tag; needs the `HOMEBREW_TAP_GITHUB_TOKEN` repo secret.

**Verified toolchain state:** `go build ./... && go vet ./... && staticcheck@2026.1 ./... && go test -race ./...` all green; CI enforces a ≥80%-per-package coverage gate.

## 3. Remaining work (dependency order)

Do these as separate branches → PRs (see §5). Each must keep the ≥80% coverage gate green.

**Phases 1–5 are complete** (see §2). The admin UI (all pages) and the release pipeline ship. Remaining, in dependency order:

1. **Ops/DR & security hardening** — **DONE so far:** `backup`/`restore` (PR #20) — a portable passphrase-wrapped bundle (argon2id + secretbox) carrying the master key + a consistent `VACUUM INTO` DB snapshot; read-only source, atomic restore (temp+fsync+rename, `--force`, env-source skips the keyfile), pre-auth KDF-param DoS cap; and a **single-instance `serve` lock** (PR #22) — advisory `flock` on `poolgate.lock` acquired before store open (gates migrations); `restore` also refuses to run against a live server; and a **graceful SSE drain** (PR #24) — the admin listener cancels request contexts at shutdown so the monitor SSE feed drains promptly, while the proxy keeps the full `Shutdown` grace so finite relays complete intact. **Remaining:** schema-version downgrade guard + pre-migration snapshot, clock-alignment to upstream usage timestamps, Docker hardening (read-only rootfs — the image is already distroless nonroot), docker-compose + Caddy/nginx recipes, full env-var override (`_FILE` secrets; `POOLGATE_PROXY_HOST`/`PORT` already added in PR #15), memory hygiene (disable core dumps, mlock master key), proxy-key lifecycle (expiry/rotation/IP-allowlist), audit-log completeness (append-only). DESIGN §20, §21, §22.
2. **Interactive OAuth login (rest of advanced routing)** — OAuth authorization-code login with **PKCE** (loopback callback + single-use `state` + S256) beyond JSON import, so accounts can be added by signing in (§23.6). The concurrency/backpressure half of §23.1 is done (PR #7); the deferred `auth_anomaly` + `startup_bind_warning` notify events (the `notify` engine already defines those kinds) can be wired here or with the monitor UI. DESIGN §23.6, §0 fixes.

**Optional Phase 4 UI refinements (deferrable):** accounts categorize/search/sort + per-account concurrency-cap editing (needs a small account-PATCH endpoint), the full client-config generator (Codex/Cursor/curl/SDK snippets + key picker), and QR/cross-device passkey polish.

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
3. **Phases 1–5 shipped** (admin UI PRs #9/#11/#13; release pipeline PR #15). **Item 1 (Ops/DR) in progress:** `backup`/`restore` (PR #20), single-instance `serve` lock (PR #22), graceful SSE drain (PR #24) done. Next within item 1: pre-migration snapshot + downgrade guard, compose/reverse-proxy recipes, `_FILE` secrets, proxy-key lifecycle, append-only audit. Then **item 2 — interactive OAuth PKCE login**. Optional Phase 4 UI refinements (accounts search/sort + concurrency-cap editing, client-config generator, QR passkey polish) don't block 1–2.
4. Branch → sequential build Workflow → verify gate locally → PR → merge.
