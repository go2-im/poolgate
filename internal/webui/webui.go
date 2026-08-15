// Package webui serves poolgate's embedded admin single-page app (DESIGN.md §9
// phase 4). The built Vite/React bundle in dist/ is embedded into the binary with
// an embed directive, so a plain `go build` / `install.sh` needs no npm and ships
// the UI in the single binary. The bundle is rebuilt from ../../web (see web/README.md).
//
// The handler serves static assets by path with an index.html fallback for
// client-side routes, and deliberately refuses the /admin/ API namespace (a stray
// API path must 404, never return the SPA HTML). It is mounted UNAUTHENTICATED so
// the login page loads before a session exists; the API routes it sits beside
// stay session-guarded.
package webui

import (
	"embed"
	"errors"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed all:dist
var distFS embed.FS

// ErrNoBundle is returned by Handler when the embedded dist has no index.html
// (i.e. the frontend was never built). Callers may treat the UI as unavailable.
var ErrNoBundle = errors.New("webui: embedded dist has no index.html (frontend not built)")

// Handler builds the SPA http.Handler over the embedded bundle.
func Handler() (http.Handler, error) {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		return nil, err
	}
	index, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		return nil, ErrNoBundle
	}
	fileServer := http.FileServer(http.FS(sub))
	return &spaHandler{fs: sub, index: index, files: fileServer}, nil
}

type spaHandler struct {
	fs    fs.FS
	index []byte
	files http.Handler
}

func (h *spaHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// The /admin/ namespace is the API surface; never serve the SPA there so a
	// stray/unknown API path returns 404 instead of HTML. Case-folded so a
	// non-canonical casing (e.g. /ADMIN/…) can't slip past into the SPA shell.
	if strings.HasPrefix(strings.ToLower(r.URL.Path), "/admin/") {
		http.NotFound(w, r)
		return
	}
	p := strings.TrimPrefix(r.URL.Path, "/")
	if p == "" {
		h.serveIndex(w)
		return
	}
	if fileExists(h.fs, p) {
		h.files.ServeHTTP(w, r)
		return
	}
	// A missing hashed asset must 404 (not silently fall back to HTML, which
	// would break module loading with a confusing MIME error).
	if strings.HasPrefix(p, "assets/") {
		http.NotFound(w, r)
		return
	}
	// Any other path is a client-side route → serve the SPA shell.
	h.serveIndex(w)
}

func (h *spaHandler) serveIndex(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(h.index)
}

func fileExists(fsys fs.FS, name string) bool {
	f, err := fsys.Open(name)
	if err != nil {
		return false
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.IsDir() {
		return false
	}
	return true
}
