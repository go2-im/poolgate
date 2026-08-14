# poolgate — Design Review & Verification Log

Archive of the design audits and the authoritative Codex-API verification. This is the record behind the v3 decisions in `DESIGN.md §0`.

---

## 1. Codex 0.147.0 API verification (authoritative)

Verified against the real OpenAI Codex CLI source at tag **`rust-v0.147.0`** (`openai/codex`, commit `be6e8ea`), with file:line citations. This corrected two earlier wrong assumptions.

| # | Assumption | Verdict | Reality (0.147.0) |
|---|-----------|---------|-------------------|
| A-1 | Not a transparent proxy — translation gateway | **CONFIRMED** | Base `chatgpt.com/backend-api/codex`, path `responses`; `stream: true` hardcoded (`core/src/client.rs:928`) + forced `Accept: text/event-stream` (`codex-api/src/endpoint/responses.rs:148-151`). Must rewrite `Authorization` **+** `ChatGPT-Account-ID` together (client refuses to cross account boundary, `model-provider/src/auth.rs:143-148`); preserve `originator` (default `codex_cli_rs`), `User-Agent`, `OpenAI-Beta`, `x-codex-turn-state`. |
| A-2 | `store:false` / stateless per request | **REFUTED (nuanced)** | `store = provider.is_azure_responses_endpoint()` — false for OpenAI but **not hardcoded** (`core/src/client.rs:926`); the `store:false` seen earlier were **test fixtures**. HTTP Responses path has **no** `previous_response_id`, sends full `input` inline (stateless). **WS path** uses `ResponseCreateWsRequest` with `previous_response_id` + **incremental delta items** (`codex-api/src/common.rs:302-329`, `client.rs:1651-1660`), relying on the backend holding context **in-memory** (store=false ⇒ not shared) → **turn-scoped stickiness is a correctness requirement**, signalled by the **`x-codex-turn-state`** header (captured at turn start, resent unchanged within a turn, never across turns — `client.rs:270-286,1909-1914`). |
| A-3 | WebSocket transport (warmup + conn-scoped reuse) | **CONFIRMED (stronger)** | WS is the **primary** transport for the built-in OpenAI provider (`supports_websockets:true`); HTTP POST+SSE is the **fallback**. `OpenAI-Beta: responses_websockets=2026-02-06`, v2 `response.create` warmup with `generate=false`, connection-scoped `previous_response_id` reuse (`core/src/client.rs:949-957,1817-1843`). |
| A-4 | Generic percent windows + plan_type (not 5h/1week tokens) | **CONFIRMED** | `GET /backend-api/wham/usage` (ChatGPT) / `/api/codex/usage` (Codex-API). `RateLimitStatusPayload`: required `plan_type`; `rate_limit{primary_window, secondary_window}`; each `RateLimitWindowSnapshot{used_percent, window_seconds, resets_*}`; `credits`, `additional_rate_limits[]`. |
| A-5 | No upstream `/v1/models`; probe useless | **REFUTED** | Real authenticated `GET https://chatgpt.com/backend-api/codex/models?client_version=<v>` exists (`codex-api/src/endpoint/models.rs:31-44`), gated on codex backend. 200=valid, 401/403=invalid → **use it as the zero-spend token auth-check probe**. |
| A-6 | OAuth rotates refresh_token; concurrent refresh bricks account | **CONFIRMED (severe)** | Refresh overwrites stored `refresh_token` (`login/src/auth/manager.rs:1493-1499`); `refresh_token_reused` → permanent Exhausted (`manager.rs:1552-1556`). Codex's own guard is only in-process `Semaphore(1)` + TOCTOU + non-atomic write → poolgate **must** do per-account single-flight refresh with atomic, interprocess-safe persistence. |

### Net corrections to the design
1. **Stateful within a turn** (WS path), not stateless. Affinity is **correctness**, keyed on **`x-codex-turn-state`** (turn-scoped), not on a best-effort session id, not "optional."
2. **v1 decision:** don't proxy the WebSocket upgrade → Codex falls back to **HTTP POST+SSE** (stateless, full inline input, no `previous_response_id`) → **turn-affinity complexity is removed from v1**. WS proxying + `x-codex-turn-state` sticky routing is a later phase. (Risk noted: WS-first is the default, and OpenAI may change fallback behavior — track Codex client version.)
3. Model usage as **generic percent windows + plan_type**; use the real **`/models`** endpoint as the cheap auth-check; make **single-flight+atomic refresh** a P1 correctness item.

---

## 2. Critical design review — confirmed fixes (folded into v3)

From an 8-lens adversarial review (48 agents). CONFIRMED/PARTIAL only.

**High:**
- Session affinity was keyed on a best-effort session id (§19.1 vs §15) → re-key on `x-codex-turn-state` (see A-2); for HTTP fallback (v1) it's moot.
- `best-quota` had no defined metric → normalize as fraction of each plan's own window caps (`min` across windows), deterministic tie-break.
- Per-account refresh + state mutated by probe engine **and** hot path with no shared lock → one per-account single-flight primitive shared by both (A-6).
- No config/policy hot-reload from admin (SQLite) to the running proxy → atomic snapshot rebuilt on admin commit; else stale routing / key-revocation lag.
- Auto-recovery re-probes rate-limited accounts before `Retry-After` → make `Retry-After` (or conservative default) the gate.
- Bootstrap token: no TTL/single-use, emitted to persistent logs → short TTL + single-use; write to a file/one-time reveal, not durable logs.

**Medium (selected):** account-state enum drift (add terminal `revoked`/`dead`); WebAuthn RP origin resolved once at startup from static config only (never per-request forwarded headers); data-model gaps (affinity, timing columns, budgets/expiry/grace, schema_migrations, sessions, recovery_codes, notify, backups, match_rules); hot-path SQLite write model (buffered async writer; in-memory counters); atomic select+increment for least-in-flight; PKCE callback spec (loopback port, single-use `state`, S256); memory hygiene (disable core dumps, mlock master key); sanitize client fields into logs/monitor; `/readyz` "healthy" definition; backup restorability check (integrity_check + sample decrypt + schema version).

---

## 3. Over-engineering / YAGNI audit — trim decisions (folded into v3)

From a 4-area audit (24 agents) with steelman verification. For single-user self-hosted:

- **CUT:** six install channels → **3** (GitHub Release binaries + verified `install.sh` + Docker); cost-per-token accounting.
- **DEFER (keep schema hooks):** nested policy groups (v1 flat-only); match-rule routing engine (keep model allow-deny); master-key rotation/bulk re-encrypt (backup/restore covers portability); subpath hosting.
- **SIMPLIFY:** strategies **6→3** (`fallback`, `best-quota`, `load-balance` with round-robin as its mode; `select` = single-member group; weighted LB later); burn-rate forecast → display-only, route on current quota; audit log → plain append-only (drop hash-chain); drop per-key spend budgets (keep rate-limit + scoping); dual-key grace → multiple active keys + manual rotation; keep SHA256SUMS+cosign, drop full SLSA + reproducible-build CI gate; keep portable backup + downgrade guard + pre-migration snapshot + `VACUUM INTO`, drop always-on scheduler (document cron); UI: keep live log + 3–4 headline counters (drop chart suite/rollup tables), single language + dark mode (drop i18n framework/a11y/mobile program), on-demand export only; drop `/metrics` from v1 (slog JSON + in-app monitor suffice).
- **KEEP (flags rejected):** `url-test` (near-free argmin over already-collected latency, reflects per-account throttling — but note it's coupled to the health engine); field encryption, SSRF guard, passkey, egress allowlist, two-listener split.

---

## 4. Scope / phasing correction

"Phase 2" had absorbed ~80% of the hard problems. Split into:
- **Phase 2a (walking skeleton):** config + store (one encrypted account imported from `~/.codex/auth.json`) + on-path single-flight token refresh + one `sk-` key + one endpoint + `fallback` + the **translation gateway** (rewrite auth/account headers, force HTTP POST+SSE by not offering WS) → proxy one account end-to-end.
- **Phase 2b:** remaining strategies + health engine + usage model + (later) WS proxying with `x-codex-turn-state` affinity.

Move §20 portable backup and §21.4 clock-alignment out of Phase 1 (they depend on later subsystems); reconcile §9.6 (weighted LB / charts marked "optional") with §4/§23.
