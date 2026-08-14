# poolgate — Security model & hardening matrix

poolgate is designed against a security audit of a comparable tool (a multi-account Codex proxy/manager). Every confirmed issue from that audit is turned into a requirement here. Nothing in poolgate performs telemetry, credential exfiltration, or silent remote code execution.

## Baseline (must always hold)

- **Loopback by default** — both servers bind `127.0.0.1`; binding wider is explicit + warned.
- **No outbound tunnel** — remote access is via the operator's own reverse proxy + TLS.
- **Secrets encrypted at rest** — token fields encrypted (`nacl/secretbox`); master key from OS keychain/keyfile, never plaintext beside the DB. Backups encrypted too.
- **Passkey admin login** — WebAuthn/FIDO2, phishing-resistant; sessions are `Secure/HttpOnly/SameSite=Strict`; CSRF on state-changing admin routes.
- **Proxy inbound auth** — `sk-` keys, constant-time compare, per-key endpoint scoping + rate limit.
- **Egress allowlist** — upstream + OAuth issuer pinned; `Authorization`-bearing requests to non-allowlisted hosts are refused.
- **Logs carry no secrets** — no token/key material (not even prefixes) in logs; redaction middleware.
- **No silent auto-update** — releases are signed + checksummed; any update is verified and user-confirmed.
- **Notifications carry no secrets** — DingTalk / WeCom / custom-webhook alerts reference accounts by label/id only (never tokens, `sk-` keys, or PII); webhook URLs are HTTPS-only and validated; notification egress is separate from the credential-egress allowlist.

## Audit finding → poolgate mitigation

| # | Audit finding (sev) | poolgate mitigation | Module / phase |
|---|---------------------|---------------------|----------------|
| A | Proxy binds `0.0.0.0` by default (MEDIUM) | Default `127.0.0.1`; wider bind requires explicit flag + startup/UI warning; admin server stays loopback-only; UI shows the **real** bind address | config, proxy server / 2 |
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
