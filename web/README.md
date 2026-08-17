# poolgate admin web UI

The React + Vite single-page admin UI (DESIGN.md §9 phase 4). It talks to the
loopback admin API and is **embedded into the Go binary**: `npm run build` emits
the bundle to `../internal/webui/dist`, which `internal/webui` embeds via a Go
`embed` directive. That built `dist` **is committed**, so `go build` / `go install`
/ `scripts/install.sh` ship the UI with **no npm step**.

> **Keeping `dist` in sync:** because the bundle is committed (and there is no
> lockfile / CI frontend build by design), any change under `web/src` MUST be
> followed by `npm run build` and committing the regenerated `internal/webui/dist`
> in the SAME change — otherwise the shipped UI drifts from the source. Reviewers
> should reject a `web/src` diff that does not also update `internal/webui/dist`.

## Develop

```bash
cd web
npm install
npm run dev        # Vite dev server (proxy admin API calls to your running poolgate)
```

## Build (regenerate the embedded bundle)

```bash
cd web
npm install
npm run build      # -> ../internal/webui/dist  (commit the result)
```

Then rebuild the Go binary so it embeds the new bundle.

## Notes

- **CSP.** The admin server sends a strict `Content-Security-Policy` (no inline
  scripts/styles). The build is configured accordingly: only external, same-origin
  JS/CSS, and the Vite module-preload polyfill (which injects an inline script) is
  disabled. Components must not use inline `style={{}}` props — use CSS classes.
- **Single UI language + dark mode only** in v1 (i18n / a11y / mobile deferred).
- The lockfile and `.npmrc` are intentionally not committed; dependency versions
  are pinned in `package.json`.
