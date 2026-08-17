package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go2-im/poolgate/internal/model"
)

// readyzStatus serves the gateway routes and returns the /readyz status code.
func readyzStatus(t *testing.T, gw *Gateway) int {
	t.Helper()
	srv := httptest.NewServer(gw.Routes())
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// TestReadyzOKAccountReadyEvenAfterGrace: a proven-healthy (ok) account makes
// /readyz ready regardless of the cold-start grace (the grace only matters for
// unknown accounts).
func TestReadyzOKAccountReadyEvenAfterGrace(t *testing.T) {
	st, cfg := newStore(t)
	a := seedAccount(t, st, "ok", "tok", "id-ok") // StateOK
	seedGroupEndpointKey(t, st, model.StrategyFallback, a.ID)
	gw := New(st, cfg, WithLogger(quietLogger()), WithReadyzGrace(time.Nanosecond)) // grace already elapsed
	if got := readyzStatus(t, gw); got != http.StatusOK {
		t.Fatalf("readyz = %d, want 200 (ok account is ready irrespective of grace)", got)
	}
}

// TestReadyzUnknownReadyWithinGrace: a freshly-imported (unknown) account reports
// ready during the cold-start grace so a fresh process is routable promptly.
func TestReadyzUnknownReadyWithinGrace(t *testing.T) {
	st, cfg := newStore(t)
	a, err := st.InsertAccount(context.Background(), model.Account{
		Label: "u", AccessToken: "tok", AccountID: "id-u", State: model.StateUnknown,
	})
	if err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}
	seedGroupEndpointKey(t, st, model.StrategyFallback, a.ID)
	gw := New(st, cfg, WithLogger(quietLogger())) // default 90s grace; test is fast → within it
	if got := readyzStatus(t, gw); got != http.StatusOK {
		t.Fatalf("readyz = %d, want 200 (unknown account within cold-start grace)", got)
	}
}

// TestReadyzUnknownNotReadyAfterGrace: once the cold-start grace elapses, an
// unknown-only pool is NOT ready — readiness needs a probe-confirmed account.
func TestReadyzUnknownNotReadyAfterGrace(t *testing.T) {
	st, cfg := newStore(t)
	a, err := st.InsertAccount(context.Background(), model.Account{
		Label: "u", AccessToken: "tok", AccountID: "id-u", State: model.StateUnknown,
	})
	if err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}
	seedGroupEndpointKey(t, st, model.StrategyFallback, a.ID)
	gw := New(st, cfg, WithLogger(quietLogger()), WithReadyzGrace(time.Nanosecond)) // grace elapsed
	if got := readyzStatus(t, gw); got != http.StatusServiceUnavailable {
		t.Fatalf("readyz = %d, want 503 (unknown-only pool after grace)", got)
	}
}

// TestReadyzStrictRequiresHealthy: with readyz_require_healthy, an unknown account
// is never accepted (no grace); only a proven-ok account reports ready.
func TestReadyzStrictRequiresHealthy(t *testing.T) {
	st, cfg := newStore(t)
	cfg.Server.ReadyzRequireHealthy = true
	a, err := st.InsertAccount(context.Background(), model.Account{
		Label: "u", AccessToken: "tok", AccountID: "id-u", State: model.StateUnknown,
	})
	if err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}
	seedGroupEndpointKey(t, st, model.StrategyFallback, a.ID)
	gw := New(st, cfg, WithLogger(quietLogger())) // default grace, but strict ignores it
	if got := readyzStatus(t, gw); got != http.StatusServiceUnavailable {
		t.Fatalf("strict readyz with only an unknown account = %d, want 503", got)
	}
	// Promote to ok → now ready.
	if err := st.UpdateState(context.Background(), a.ID, model.StateOK); err != nil {
		t.Fatalf("UpdateState: %v", err)
	}
	if got := readyzStatus(t, gw); got != http.StatusOK {
		t.Fatalf("strict readyz with an ok account = %d, want 200", got)
	}
}
