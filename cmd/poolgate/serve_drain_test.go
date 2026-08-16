package main

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"
)

// TestServeListenerDrainsStreamingHandler asserts that a long-lived streaming
// handler (one that blocks on r.Context().Done(), like the monitor SSE feed) is
// unblocked promptly when the serve context is cancelled — so shutdown does not
// wait out the full drain deadline. Regression guard for the graceful SSE drain
// (DESIGN §21.2 / serveListener BaseContext + cancel-before-Shutdown).
func TestServeListenerDrainsStreamingHandler(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	var once sync.Once
	started := make(chan struct{})
	returned := make(chan struct{})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		once.Do(func() { close(started) })
		<-r.Context().Done() // block like an SSE stream until the request ctx ends
		close(returned)
	})

	ready := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() { errCh <- serveListener(ctx, "127.0.0.1:0", h, func(b string) { ready <- b }) }()
	addr := <-ready

	// Fire a request that will hang inside the handler.
	go func() {
		resp, err := http.Get("http://" + addr + "/")
		if err == nil {
			_ = resp.Body.Close()
		}
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("handler never started")
	}

	// Cancel the serve context; the streaming handler's r.Context() must be
	// cancelled well before the 5s Shutdown deadline.
	start := time.Now()
	cancel()

	select {
	case <-returned:
	case <-time.After(3 * time.Second):
		t.Fatal("streaming handler was not drained on shutdown (waited out the deadline)")
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("serveListener = %v, want nil", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("serveListener did not return after cancel")
	}
	if elapsed := time.Since(start); elapsed > 4*time.Second {
		t.Errorf("drain took %v, expected prompt (< the 5s deadline)", elapsed)
	}
}
