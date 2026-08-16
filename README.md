# poolgate

**Single-user, self-hostable manager and OpenAI-compatible reverse proxy for a pool of Codex/ChatGPT accounts — with a composable routing-policy engine and a passkey-protected web admin UI.**

## What it does

- **Pool multiple Codex/ChatGPT accounts** — import via OAuth or `~/.codex/auth.json`, auto-refresh tokens, and view per-account usage.
- **Expose them as a local OpenAI-compatible `/v1` endpoint** — a translation gateway to the ChatGPT/Codex backend (rewrites auth per pooled account, forwards streaming responses).
- **Composable, named routing policies** — `fallback`, `best-quota` (route to the account with the most remaining headroom), and `load-balance`. Each policy is bound to its own endpoint URL (`/e/<name>/v1`), so you pick a strategy simply by choosing which URL your client points at.
- **Active health probing with auto-recovery** — accounts that hit a rate-limit or exhaust their quota are detected and automatically returned to rotation once they recover.
- **Passkey-protected web admin UI** — WebAuthn (including phone/QR cross-device sign-in), served by the same binary.

## Design principles

- **Security-first.** Loopback by default; no outbound tunnel (front it with your own reverse proxy + TLS for remote access); account tokens are field-encrypted at rest; upstream host and OAuth issuer are pinned; secrets are never logged. See [`docs/SECURITY.md`](docs/SECURITY.md).
- **Single Go binary** — pure-Go SQLite and an embedded web UI, so it's trivial to cross-compile and self-host.

## Install

### From source (one command)

```bash
git clone https://github.com/go2-im/poolgate.git
cd poolgate
./scripts/install.sh --init
```

Requires **Go 1.25+**. This builds the binary, installs it (to `/usr/local/bin`, or `~/.local/bin` without sudo), and — with `--init` — provisions the config/data dir and prints a one-time link to register your first passkey. Run `./scripts/install.sh --help` for options (`--prefix`, `--service`, `--no-build`).

Packaged release builds (Homebrew tap, Docker image, signed binaries) are described in [`docs/DESIGN.md`](docs/DESIGN.md#18-distribution-packaging--release-automation).

### Uninstall

```bash
./scripts/uninstall.sh              # remove the installed binary
./scripts/uninstall.sh --service    # also remove the systemd unit / launchd agent
./scripts/uninstall.sh --purge      # ALSO delete the data dir (accounts, tokens, master key)
```

`uninstall.sh` mirrors the installer: it removes the `poolgate` binary from the same prefix (`--prefix`, else `/usr/local/bin` then `~/.local/bin`). `--service` removes the service unit. `--purge` is **irreversible** — it deletes your encrypted accounts *and* the master key that decrypts them, so it always confirms first (pass `--yes` to skip, `--data-dir` to point at a non-default data dir). Run `./scripts/uninstall.sh --help` for all options.

## Quick start

```bash
poolgate init                       # provision config/data dir + master key; prints a first-passkey link
poolgate import ~/.codex/auth.json  # explicit — accounts are never imported automatically
poolgate serve                      # start the proxy (127.0.0.1:8787) + admin (127.0.0.1:7070)

# open the passkey-protected admin UI (register your first passkey with the
# bootstrap token from `poolgate init`):
#   http://127.0.0.1:7070

# point your Codex/Cursor/OpenAI client at:
#   http://127.0.0.1:8787/e/<endpoint>/v1
```

## Docs

- [`docs/DESIGN.md`](docs/DESIGN.md) — architecture, policy engine, storage, auth, config.
- [`docs/SECURITY.md`](docs/SECURITY.md) — threat model and hardening.
- [`docs/RUN.md`](docs/RUN.md) — local run guide.
- [`docs/DEPLOY.md`](docs/DEPLOY.md) — Docker Compose + reverse-proxy (Caddy/nginx) deployment.

## License

MIT — see [`LICENSE`](LICENSE).
