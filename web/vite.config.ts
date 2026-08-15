import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// poolgate admin SPA build config.
//
// - Output goes straight into the Go package that embeds it (internal/webui/dist)
//   so `go build` picks up the committed bundle with no npm step.
// - modulePreload polyfill is disabled: it would inject an INLINE <script>, which
//   the admin server's strict CSP (default-src 'self', no unsafe-inline) forbids.
//   The rest of the build already emits only external, same-origin JS/CSS.
export default defineConfig({
  plugins: [react()],
  base: '/',
  build: {
    outDir: '../internal/webui/dist',
    emptyOutDir: true,
    modulePreload: { polyfill: false },
    // Single JS + single CSS chunk keeps the embedded asset set small + stable.
    rollupOptions: {
      output: {
        entryFileNames: 'assets/[name]-[hash].js',
        chunkFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash][extname]',
      },
    },
  },
})
