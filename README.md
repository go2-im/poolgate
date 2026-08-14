# poolgate

**Single-user, self-hostable manager + OpenAI-compatible reverse proxy for a pool of Codex/ChatGPT accounts, with a composable (Surge-style) routing-policy engine and a passkey-protected web admin UI.**

> Status: 🚧 design + scaffolding. No public release yet. Module path `github.com/danny/poolgate` is a placeholder until the remote is created.

## What it is

- Import multiple Codex/ChatGPT accounts (OAuth login or `~/.codex/auth.json` import), view usage, and expose them as a local **OpenAI-compatible `/v1`** endpoint.
- **Composable routing policies** inspired by Surge policy groups: `select` / `fallback` / `round-robin` / `load-balance` / `url-test` / `best-quota`, groups can nest.
- **Multiple named proxy endpoints** — each URL (`/e/<name>/v1`) is bound to a policy group, so you point Codex/Cursor at a specific URL to pick a strategy.
- **Web admin UI** (React), served by the same Go binary, protected by **passkey (WebAuthn/FIDO2)** login.

## Design principles

- **Security-first**, hardened against every issue found auditing a comparable tool — see [`docs/SECURITY.md`](docs/SECURITY.md).
- **Loopback by default.** Binds `127.0.0.1`; exposing wider is explicit and warned.
- **No outbound tunnel.** Remote access is via *your own* reverse proxy (Caddy/nginx) + TLS.
- **Encrypted secrets at rest.** Tokens are field-encrypted in SQLite; master key from OS keychain / keyfile.
- **Single Go binary** (pure-Go SQLite, embedded web UI), easy to cross-compile and self-host.

## Docs

- [`docs/DESIGN.md`](docs/DESIGN.md) — architecture, policy engine, storage, config, build phases.
- [`docs/SECURITY.md`](docs/SECURITY.md) — threat model + the audit-derived hardening matrix.

## License

MIT — see [`LICENSE`](LICENSE).
