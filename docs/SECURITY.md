# poolgate — Security model & hardening matrix

poolgate is designed against a security audit of a comparable tool (a multi-account Codex proxy/manager). Every confirmed issue from that audit is turned into a requirement here. Nothing in poolgate performs telemetry, credential exfiltration, or silent remote code execution.

## Baseline (must always hold)

- **Loopback by default** — both servers bind `127.0.0.1`; binding wider is explicit + warned.
- **No outbound tunnel** — remote access is via the operator's own reverse proxy + TLS.
- **Secrets encrypted at rest** — token fields encrypted (`nacl/secretbox`); master key from OS keychain/keyfile, never plaintext beside the DB. Backups encrypted too.
- **Passkey admin login** — WebAuthn/FIDO2, phishing-resistant; sessions are `Secure/HttpOnly/SameSite=Strict`; CSRF on state-changing admin routes.
- **Proxy inbound auth** — `sk-` keys stored **hashed** (SHA-256; a short suffix hint for display), constant-time compare, per-key endpoint scoping, optional per-key IP allowlist + expiry, and per-account concurrency caps. (There is no per-key request-rate limiter today — throttling is via the concurrency cap; a true per-key rate limit is a possible future addition.)
- **Egress allowlist** — upstream + OAuth issuer pinned; `Authorization`-bearing requests to non-allowlisted hosts are refused.
- **Logs carry no secrets** — no token/key material (not even prefixes) in logs; redaction middleware.
- **No silent auto-update** — releases are signed + checksummed; any update is verified and user-confirmed.
- **Verified install** — the one-line `install.sh` verifies `SHA256SUMS` + cosign signature before installing (no blind `curl | sh`); Homebrew is the recommended path. Release artifacts carry cosign signatures + SLSA provenance; dependencies are auto-updated (Dependabot/Renovate) and scanned (`govulncheck`).
- **Notifications carry no secrets** — DingTalk / WeCom / custom-webhook alerts reference accounts by label/id only (never tokens, `sk-` keys, or PII); webhook URLs are HTTPS-only and validated; notification egress is separate from the credential-egress allowlist.
- **Trusted-proxy parsing is strict** — `X-Forwarded-*` headers are honored only from configured `trusted_proxies` CIDRs; untrusted peers can't spoof client IP or host. poolgate never launches a tunnel itself.
- **Tunnel/reverse-proxy exposure is deliberate** — behind cloudflared/ngrok/reverse-proxy the proxy is effectively public, gated by the `sk-` key; the admin listener should not be tunnel-exposed unless intended (and remains passkey-gated). Monitoring/live-log data contains no secrets.

## Audit finding → poolgate mitigation

| # | Audit finding (sev) | poolgate mitigation | Module / phase |
|---|---------------------|---------------------|----------------|
| A | Proxy binds `0.0.0.0` by default (MEDIUM) | Default `127.0.0.1`; LAN / `0.0.0.0` is a **supported opt-in** (reverse-proxy fronting recommended over direct port access); non-loopback bind emits an informational startup notice; access always gated by `sk-` key / passkey; UI shows the **real** bind address; admin stays loopback unless deliberately fronted | config, proxy server / 2 |
| B | CSP disabled + broad IPC surface (MEDIUM) | Strict CSP on admin (`default-src 'self'`, no inline/`unsafe-*`), `X-Frame-Options: DENY`, `X-Content-Type-Options`; every admin endpoint behind auth + CSRF | api middleware / 3 |
| C | Release CI uses mutable action tags while holding signing key + npm token (MEDIUM) | All GitHub Actions **SHA-pinned**; least-priv `permissions`; OIDC short-lived creds; signing job isolated | .github / 5 |
| D | Tokens stored plaintext + shadow backups (LOW) | **Field-encrypted** secrets in SQLite; encrypted backups; `0600`; OS keychain master key | store / 1 |
| E | Upstream host read from external `config.toml`, unpinned (LOW) | Upstream **pinned + host allowlist**; overrides only via explicit poolgate config | proxy, config / 2 |
| F | OAuth refresh URL built from unverified `id_token.iss` (LOW) | Issuer **pinned** to `auth.openai.com`; `iss` from imported tokens ignored | oauth / 1 |
| G | Public tunnel guarded only by app key (LOW) | **Feature removed** — no outbound tunnel; remote = your reverse proxy + TLS | — |
| H | Published binaries unverifiable, no provenance (LOW) | SHA256SUMS + signature; **SLSA/artifact provenance**; reproducible builds; from-source docs | .github, docs / 5 |
| I | Auto-updater silent from mutable pointer (LOW) | No silent update; if added, signature-verified + user-confirmed | (n/a for CLI/proxy) |
| J | Key prefix printed to stdout (INFO) | No key/token material in logs at all | logger / all |
| K | Typosquat `openrouter.icu` in examples (LOW) | Only official domains in examples; CI lint for suspicious domains | web, docs / 4 |
| L | (positive) token only sent to official backend | Preserved + enforced via egress allowlist | proxy / 2 |
| M | (positive) `/v1` requires a key; (positive) tunnel binary from official source only | Preserved: mandatory `sk-` key, constant-time; no obfuscated downloads | auth / 2-3 |

## Per-phase security acceptance checks

- **Phase 1:** encrypt→store→decrypt round-trip test passes; issuer-pinning unit test (poisoned `iss` ignored); DB file `0600`.
- **Phase 2:** proxy rejects unknown host egress; unauthenticated `/v1` → 401; default bind is `127.0.0.1` (test).
- **Phase 3:** unauthenticated admin API → 401; missing CSRF token rejected; CSP header present; passkey register/login + recovery + `admin reset-auth` work.
- **Phase 5:** release artifacts have checksums + signature + provenance; CI actions are SHA-pinned; domain-lint passes.

## v3 additions (from design review — see REVIEW.md)

- **Refresh single-flight + atomic persistence (P1).** OAuth rotates `refresh_token`; a reused one permanently bricks the account. One per-account single-flight shared by the probe engine **and** the proxy hot path; persist via temp-file + atomic rename, interprocess-safe (flock). Never fire concurrent refreshes for one account.
- **WebAuthn RP origin is static-only.** RP ID / origin resolved **once at startup** from `external_origin` (else `rp_id`/`rp_origin`); **never** derived from per-request forwarded headers. Forwarded headers (trusted CIDRs only) affect client-IP logging + cookie-Secure decision, not identity.
- **Bootstrap/registration token.** Short TTL (~10–15 min) **and** single-use (consumed on first successful passkey registration); for Docker/headless prefer a one-time file/reveal over persistent container logs.
- **PKCE interactive login.** Loopback callback bound to `127.0.0.1` on the registered port; cryptographically-random `state` bound to the initiating admin session and single-use; PKCE S256; strict redirect binding.
- **Memory hygiene for secrets.** Disable core dumps at startup (RLIMIT_CORE=0 / PR_SET_DUMPABLE=0); `mlock`/guard the master key and passphrase-derived keys against swap; zeroize where practical.
- **Log/monitor injection.** Treat all client-supplied fields (session id, model, headers) as untrusted: length-cap and strip/escape control chars/newlines before persisting to `request_logs` or pushing to the live SSE/WS monitor.
- **Auto-recovery gated by `Retry-After`.** Never re-probe a 429'd account before `max(Retry-After, backoff)`; enforce a per-account daily live-probe budget + global probe rate cap; default probe mode = usage-poll-only (live probes opt-in) to avoid anti-abuse flags.
- **Backup restorability.** Verify a backup by PRAGMA `integrity_check` + sample-decrypt of each secret column type + schema-version check; the passphrase-wrapped master key makes the bundle portable across hosts.
- **Audit log:** **append-only** table (INSERT-only in code paths) covering auth / CRUD / key-use / config changes, with a **keyless SHA-256 hash chain** (re-added post-v1) verifiable via `GET /admin/api/audit/verify`. It detects accidental corruption and mid-log tamper/delete/reorder; it does **not** detect tail-truncation or an adversary with DB write who recomputes the tail (that would need a key held outside the DB or external notarization).
- **`/readyz` is secret-free** and returns not-ready when no endpoint has a reachable healthy account; `/healthz` is liveness only. Neither leaks account identifiers.
