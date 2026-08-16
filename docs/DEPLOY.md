# Deploying poolgate with Docker Compose + a reverse proxy

This is a production-shaped recipe: the published container image behind a
reverse proxy that terminates TLS. Example files live in [`../deploy/`](../deploy):

| File | Purpose |
|------|---------|
| [`deploy/docker-compose.yml`](../deploy/docker-compose.yml) | poolgate + Caddy, internal-only listeners, hardened runtime |
| [`deploy/config.yaml`](../deploy/config.yaml) | binds admin to the network + sets the WebAuthn origin |
| [`deploy/Caddyfile`](../deploy/Caddyfile) | TLS + reverse proxy for both hostnames (auto HTTPS) |
| [`deploy/nginx.conf`](../deploy/nginx.conf) | drop-in alternative if you already run nginx |

The image is `ghcr.io/go2-im/poolgate:latest` (multi-arch, distroless/nonroot,
built by the release pipeline — see [`BUILD.md`](BUILD.md)).

## Topology

```
                       :443
  clients ──TLS──▶ ┌──────────┐   api.example.com   ──▶ poolgate :8787  (proxy)
                   │  caddy   │
  browser ──TLS──▶ └──────────┘   admin.example.com ──▶ poolgate :7070  (admin)
                        │
                   internal docker network "edge" (no host ports on poolgate)
```

Only the reverse proxy publishes host ports (80/443). poolgate publishes
**nothing** — both listeners are reachable only from the proxy on the internal
network. Inside the container both bind `0.0.0.0` (the image already sets
`POOLGATE_PROXY_HOST=0.0.0.0`; `config.yaml` sets the admin host) so the proxy in
a *different* container can reach them; loopback would not be cross-container
reachable.

## Why the admin surface needs HTTPS

Passkeys (WebAuthn) only work in a **secure context** bound to a stable
**Relying Party ID**. So the admin UI must be served over HTTPS at a fixed
hostname, and `server.admin.external_origin` / `rp_id` in `config.yaml` must
match that hostname. poolgate resolves the RP inputs **once at startup from
static config, never from request headers** — so a reverse proxy in front cannot
change or spoof them. Pick `rp_id` before onboarding: passkeys registered under
one RP ID do not verify under another.

## 1. DNS + prerequisites

- Point `api.example.com` and `admin.example.com` at the host's public IP.
- Open TCP 80 + 443 to the host (Caddy needs 80 for the ACME HTTP challenge).
- Install Docker Engine + the Compose plugin.

Copy the four files from `deploy/` to the host and replace every `example.com`
hostname (in `config.yaml`, `Caddyfile`/`nginx.conf`) and the ACME `email`.

## 2. One-shot bootstrap (`init`)

`init` creates the data dir, generates `master.key` in the volume (keyfile
mode), runs migrations, and prints a **single-use, ~15-minute** admin bootstrap
token. Run it once, as a throwaway container that shares the same volume:

```sh
docker compose run --rm poolgate init
```

Copy the printed `pgbt_…` token — you need it to register the first passkey, and
it is shown only once (persisted only as a SHA-256 hash).

## 3. Start

```sh
docker compose up -d
```

Caddy will obtain certificates for both hostnames on first request (give it a few
seconds). Check readiness through the proxy hostname:

```sh
curl -s https://api.example.com/readyz     # {"status":"ready"} once an account is eligible
```

## 4. Register the first passkey

Open `https://admin.example.com` in a browser, choose "register", and paste the
bootstrap token from step 2. Complete the WebAuthn ceremony with your platform
authenticator (or a QR-linked phone). **Store the one-time recovery codes shown
after registration** — they are displayed only once. The token is consumed on
success.

Lost every passkey and recovery code? Re-issue a token from local shell access:

```sh
docker compose run --rm poolgate admin reset-auth
```

## 5. Import an account pool

Either from the signed-in admin UI (Accounts → import), or as a one-shot CLI
container. To import a Codex `auth.json` from the host, bind-mount it read-only:

```sh
docker compose run --rm \
  -v "$HOME/.codex/auth.json:/tmp/auth.json:ro" \
  poolgate import /tmp/auth.json
```

The first import also creates a default policy group, a `default` endpoint, and
one `sk-` inbound key — **printed once**. Point OpenAI-compatible clients at:

```
https://api.example.com/e/default/v1/responses
Authorization: Bearer sk-…your-key…
```

## Streaming (SSE) — do not buffer

poolgate streams Server-Sent Events on **both** surfaces: the proxy relays the
upstream completion stream, and the admin live monitor is an SSE feed. The
recipes already disable response buffering — Caddy via `flush_interval -1`,
nginx via `proxy_buffering off;` + HTTP/1.1 + long read timeouts. If you adapt
another proxy, replicate that or completions will arrive in delayed batches (or
time out).

## Hardening options

- **Runtime**: the compose service already runs `read_only` rootfs (only the
  `/data` volume and a small `/tmp` tmpfs are writable), `no-new-privileges`, and
  `cap_drop: ALL`. The image is distroless/nonroot (uid 65532) to begin with.
- **Memory hygiene**: on `serve`, poolgate disables core dumps (so a crash cannot
  write the decrypted master key to a core file) and attempts to lock its memory
  against swap. Core-dump disabling always applies; memory locking is bounded by
  `RLIMIT_MEMLOCK`, so the compose recipe raises the `memlock` ulimit to `-1`
  (unlimited) to let it succeed without any added capability. Omit that and serve
  still runs — it just logs `memory hygiene not fully applied` and continues.
- **Master key via secret (instead of the keyfile in the volume)**: set
  `master_key_source: env` in `config.yaml`, generate a 32-byte key, and feed it
  as a file so it never sits in the process environment — poolgate reads the
  `<NAME>_FILE` convention for any secret:

  ```sh
  openssl rand -base64 32 > secrets/poolgate_master_key   # keep this safe + backed up
  ```

  ```yaml
  # docker-compose.yml (additions)
  services:
    poolgate:
      environment:
        POOLGATE_MASTER_KEY_FILE: /run/secrets/poolgate_master_key
      secrets:
        - poolgate_master_key
  secrets:
    poolgate_master_key:
      file: ./secrets/poolgate_master_key
  ```

  With `env` mode `backup` will NOT write the key into the bundle — you must keep
  this key to decrypt any restore. `POOLGATE_BACKUP_PASSPHRASE_FILE` works the
  same way for `backup`/`restore`.
- **Restrict the admin surface by IP** at the proxy (commented blocks in both
  recipes), in addition to poolgate's own passkey session + CSRF + CSP.

## Caveats when fronted by a reverse proxy

- **Proxy-key IP allowlists see the *proxy's* IP.** An `sk-` key's optional IP
  allowlist is matched against the direct TCP peer (poolgate does not trust
  `X-Forwarded-For`). Behind a reverse proxy that peer is the proxy container, so
  a per-key allowlist cannot distinguish real clients — enforce client IP rules
  at the reverse proxy instead.
- **Persist `caddy-data`.** It holds the ACME certificates and account key;
  losing it forces re-issuance (and can hit Let's Encrypt rate limits).

## Backups

Snapshot the encrypted DB + master key into one passphrase-wrapped bundle:

```sh
docker compose run --rm \
  -e POOLGATE_BACKUP_PASSPHRASE \
  -v "$PWD/backups:/backups" \
  poolgate backup --out /backups/poolgate-$(date +%F).pgbak
```

Provide the passphrase via `POOLGATE_BACKUP_PASSPHRASE` in your host shell (passed
through with `-e`) or `--passphrase-file`. Restore is atomic and refuses to
overwrite a live DB; see `poolgate restore -h`.
