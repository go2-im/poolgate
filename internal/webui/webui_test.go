package webui

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newHandler(t *testing.T) http.Handler {
	t.Helper()
	h, err := Handler()
	if err != nil {
		t.Fatalf("Handler: %v (was the frontend built into dist/?)", err)
	}
	return h
}

func do(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestServesIndexAtRoot(t *testing.T) {
	h := newHandler(t)
	rec := do(t, h, "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	if !strings.Contains(rec.Body.String(), "<div id=\"root\">") {
		t.Errorf("index body missing app root: %q", rec.Body.String())
	}
}

func TestSPAFallbackForClientRoute(t *testing.T) {
	h := newHandler(t)
	rec := do(t, h, "/some/client/route")
	if rec.Code != http.StatusOK {
		t.Fatalf("client route = %d, want 200 (SPA fallback)", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "<div id=\"root\">") {
		t.Error("client route did not fall back to index.html")
	}
}

func TestRefusesAdminNamespace(t *testing.T) {
	h := newHandler(t)
	for _, p := range []string{"/admin/api/accounts", "/ADMIN/api/status", "/Admin/login/begin"} {
		rec := do(t, h, p)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s = %d, want 404 (never serve SPA for API paths, any casing)", p, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "<div id=\"root\">") {
			t.Errorf("SPA HTML leaked for %q", p)
		}
	}
}

func TestMissingAssetIs404(t *testing.T) {
	h := newHandler(t)
	rec := do(t, h, "/assets/does-not-exist-12345.js")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing asset = %d, want 404", rec.Code)
	}
}

func TestServesRealAsset(t *testing.T) {
	entries, err := fs.ReadDir(distFS, "dist/assets")
	if err != nil || len(entries) == 0 {
		t.Skipf("no built assets to test (%v)", err)
	}
	h := newHandler(t)
	name := entries[0].Name()
	rec := do(t, h, "/assets/"+name)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /assets/%s = %d, want 200", name, rec.Code)
	}
	if rec.Body.Len() == 0 {
		t.Error("asset body is empty")
	}
}
