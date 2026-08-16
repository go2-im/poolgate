# Building & releasing poolgate

poolgate ships as a single static Go binary with the admin UI embedded
(`go:embed`). There is no runtime dependency on Node, a C toolchain, or a system
SQLite — `modernc.org/sqlite` is pure Go and builds are `CGO_ENABLED=0`.

## Build from source

```bash
# Binary for the host platform (admin UI bundle is committed under
# internal/webui/dist, so no npm step is needed).
go build -o poolgate ./cmd/poolgate
./poolgate version
```

To rebuild the embedded admin UI after changing anything under `web/`:

```bash
cd web
npm install
npm run build      # emits internal/webui/dist (committed)
```

The one-command from-source installer is `scripts/install.sh` (and
`scripts/uninstall.sh` to remove it).

## Version stamping

`poolgate version` prints the version, commit, and build date. For source builds
these default to `dev` / `none` / `unknown`. Releases inject real values via
`-ldflags` (GoReleaser does this automatically):

```bash
go build -ldflags "-s -w \
  -X main.version=v1.2.3 \
  -X main.commit=$(git rev-parse HEAD) \
  -X main.date=$(git show -s --format=%cI HEAD)" \
  -o poolgate ./cmd/poolgate
```

## Releasing

Releases are automated by [GoReleaser](https://goreleaser.com) via
`.github/workflows/release.yml`, triggered on a pushed semver tag:

```bash
git tag -s v1.2.3 -m "v1.2.3"    # signed/annotated tag
git push origin v1.2.3
```

The workflow (see `.goreleaser.yaml`) then:

1. cross-compiles static binaries for **linux/darwin × amd64/arm64**;
2. packages per-target `tar.gz` archives + a `SHA256SUMS` file;
3. **cosign keyless-signs** the checksum file (Sigstore OIDC — no private key;
   the workflow's `id-token: write` permission mints the token);
4. publishes multi-arch Docker images to **`ghcr.io/go2-im/poolgate`**
   (`:vX.Y.Z` and `:latest`);
5. pushes a Homebrew formula to **`go2-im/homebrew-tap`** (skipped for
   prerelease tags like `v1.2.3-rc1`).

### Required repository secrets

| Secret | Purpose |
|--------|---------|
| `GITHUB_TOKEN` | provided automatically; creates the Release + pushes to ghcr |
| `HOMEBREW_TAP_GITHUB_TOKEN` | PAT with `contents:write` on `go2-im/homebrew-tap` so the formula can be pushed |

All actions are **SHA-pinned** (see the version comments), matching `ci.yml`.

### Validate the release config locally

```bash
# Static validation of .goreleaser.yaml (no build, no publish). Use the same
# pinned version the release workflow uses.
go run github.com/goreleaser/goreleaser/v2@v2.8.2 check

# Build the current target only, into ./dist, without publishing.
go run github.com/goreleaser/goreleaser/v2@v2.8.2 build --snapshot --clean --single-target
```

## Install a release

### Homebrew

```bash
brew install go2-im/tap/poolgate
```

### Docker

The image binds the proxy to `0.0.0.0` (via `POOLGATE_PROXY_HOST`, baked into
the image) so a published port works. The **admin** listener stays loopback and
is intentionally not `EXPOSE`d — reach it via an SSH tunnel or a sidecar.

Like the CLI, the container never auto-imports accounts, so first run is
**init → import → serve** against a persistent `/data` volume:

```bash
# 1. Initialize: creates the master key + DB and prints a single-use bootstrap
#    token (register your first admin passkey with it).
docker run --rm -v poolgate-data:/data ghcr.io/go2-im/poolgate:latest init

# 2. Import a Codex auth.json (explicit; prints the sk- proxy key once).
docker run --rm -v poolgate-data:/data -v "$PWD/auth.json:/auth.json:ro" \
  ghcr.io/go2-im/poolgate:latest import /auth.json

# 3. Serve (default CMD). Publish the proxy port.
docker run -d --name poolgate -v poolgate-data:/data -p 8787:8787 \
  ghcr.io/go2-im/poolgate:latest
```

`docker run … version` prints the build metadata without touching `/data`.

### Verify a release (cosign)

Binaries are covered by the signed checksum file; the container images are signed
directly.

```bash
# Archives — verify the signed SHA256SUMS, then check a downloaded archive.
cosign verify-blob \
  --certificate SHA256SUMS.pem \
  --signature SHA256SUMS.sig \
  --certificate-identity-regexp 'https://github.com/go2-im/poolgate/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing

# Container image — verify the keyless signature on the pulled tag.
cosign verify ghcr.io/go2-im/poolgate:latest \
  --certificate-identity-regexp 'https://github.com/go2-im/poolgate/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```
