package admin

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/go2-im/poolgate/internal/model"
)

// fakeNotifier records Test calls and returns a scripted error.
type fakeNotifier struct {
	err    error
	called int
	lastID string
}

func (f *fakeNotifier) Test(_ context.Context, ch model.NotifyChannel) error {
	f.called++
	f.lastID = ch.ID
	return f.err
}

func validCreateBody() map[string]any {
	return map[string]any{
		"type":    "dingtalk",
		"name":    "ops",
		"enabled": true,
		"events":  []string{"account_expired", "quota_low"},
		"config": map[string]any{
			"url":    "https://oapi.dingtalk.com/robot/send?access_token=TOK",
			"secret": "SUPERSECRET",
		},
	}
}

func TestNotifyChannelCreateAndListSecretFree(t *testing.T) {
	h := newHarness(t)
	cookie, csrf := h.authed()
	rec := h.do(http.MethodPost, "/admin/api/notify/channels", validCreateBody(), func(r *http.Request) {
		r.AddCookie(cookie)
		r.Header.Set(CSRFHeaderName, csrf)
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d, want 201 (%s)", rec.Code, rec.Body.String())
	}
	// The response and any subsequent read must never contain the secret/URL.
	if strings.Contains(rec.Body.String(), "SUPERSECRET") || strings.Contains(rec.Body.String(), "access_token") {
		t.Fatalf("create response leaked secret: %s", rec.Body.String())
	}
	created := decodeBody(t, rec)
	id, _ := created["id"].(string)
	if id == "" {
		t.Fatal("create response missing id")
	}

	// List is secret-free too.
	cookie2, _ := h.authed()
	rec = h.do(http.MethodGet, "/admin/api/notify/channels", nil, func(r *http.Request) { r.AddCookie(cookie2) })
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d, want 200", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "SUPERSECRET") || strings.Contains(rec.Body.String(), "access_token") {
		t.Fatalf("list leaked secret: %s", rec.Body.String())
	}

	// Get is secret-free.
	cookie3, _ := h.authed()
	rec = h.do(http.MethodGet, "/admin/api/notify/channels/"+id, nil, func(r *http.Request) { r.AddCookie(cookie3) })
	if rec.Code != http.StatusOK {
		t.Fatalf("get = %d, want 200", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "SUPERSECRET") {
		t.Fatalf("get leaked secret: %s", rec.Body.String())
	}
	// But the stored channel DID capture the secret (verify via the fake store).
	stored := h.store.channels[id]
	if stored.Config.Secret != "SUPERSECRET" {
		t.Errorf("stored secret = %q, want SUPERSECRET", stored.Config.Secret)
	}
}

func TestNotifyChannelCreateValidation(t *testing.T) {
	h := newHarness(t)
	cases := []struct {
		name string
		body map[string]any
	}{
		{"bad type", map[string]any{"type": "slack", "name": "x", "config": map[string]any{"url": "https://a.example.com"}}},
		{"missing name", map[string]any{"type": "dingtalk", "config": map[string]any{"url": "https://a.example.com"}}},
		{"http url", map[string]any{"type": "dingtalk", "name": "x", "config": map[string]any{"url": "http://a.example.com"}}},
		{"missing url", map[string]any{"type": "dingtalk", "name": "x", "config": map[string]any{}}},
		{"bad event", map[string]any{"type": "dingtalk", "name": "x", "events": []string{"nope"}, "config": map[string]any{"url": "https://a.example.com"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cookie, csrf := h.authed()
			rec := h.do(http.MethodPost, "/admin/api/notify/channels", tc.body, func(r *http.Request) {
				r.AddCookie(cookie)
				r.Header.Set(CSRFHeaderName, csrf)
			})
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("%s: code = %d, want 400 (%s)", tc.name, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestNotifyChannelPatch(t *testing.T) {
	h := newHarness(t)
	id := seedChannel(t, h)

	patch := map[string]any{
		"name":    "renamed",
		"enabled": false,
		"events":  []string{"account_cooldown"},
		"config":  map[string]any{"url": "https://qyapi.weixin.qq.com/x?key=NEW"},
	}
	cookie, csrf := h.authed()
	rec := h.do(http.MethodPatch, "/admin/api/notify/channels/"+id, patch, func(r *http.Request) {
		r.AddCookie(cookie)
		r.Header.Set(CSRFHeaderName, csrf)
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("patch = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	stored := h.store.channels[id]
	if stored.Name != "renamed" || stored.Enabled {
		t.Errorf("patch not applied: %+v", stored)
	}
	if !strings.Contains(stored.Config.URL, "NEW") {
		t.Errorf("config not replaced: %q", stored.Config.URL)
	}
}

func TestNotifyChannelPatchInvalidEvent(t *testing.T) {
	h := newHarness(t)
	id := seedChannel(t, h)
	cookie, csrf := h.authed()
	rec := h.do(http.MethodPatch, "/admin/api/notify/channels/"+id, map[string]any{"events": []string{"nope"}}, func(r *http.Request) {
		r.AddCookie(cookie)
		r.Header.Set(CSRFHeaderName, csrf)
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("patch bad event = %d, want 400", rec.Code)
	}
}

func TestNotifyChannelNotFound(t *testing.T) {
	h := newHarness(t)
	cookie, _ := h.authed()
	rec := h.do(http.MethodGet, "/admin/api/notify/channels/missing", nil, func(r *http.Request) { r.AddCookie(cookie) })
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get missing = %d, want 404", rec.Code)
	}
	cookie, csrf := h.authed()
	rec = h.do(http.MethodDelete, "/admin/api/notify/channels/missing", nil, func(r *http.Request) {
		r.AddCookie(cookie)
		r.Header.Set(CSRFHeaderName, csrf)
	})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("delete missing = %d, want 404", rec.Code)
	}
}

func TestNotifyChannelDelete(t *testing.T) {
	h := newHarness(t)
	id := seedChannel(t, h)
	cookie, csrf := h.authed()
	rec := h.do(http.MethodDelete, "/admin/api/notify/channels/"+id, nil, func(r *http.Request) {
		r.AddCookie(cookie)
		r.Header.Set(CSRFHeaderName, csrf)
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("delete = %d, want 200", rec.Code)
	}
	if _, ok := h.store.channels[id]; ok {
		t.Error("channel not deleted from store")
	}
}

func TestNotifyChannelTest(t *testing.T) {
	notifier := &fakeNotifier{}
	h := newHarness(t, WithNotifier(notifier))
	id := seedChannel(t, h)

	cookie, csrf := h.authed()
	rec := h.do(http.MethodPost, "/admin/api/notify/channels/"+id+"/test", nil, func(r *http.Request) {
		r.AddCookie(cookie)
		r.Header.Set(CSRFHeaderName, csrf)
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("test = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if notifier.called != 1 || notifier.lastID != id {
		t.Errorf("notifier called=%d lastID=%q", notifier.called, notifier.lastID)
	}
}

func TestNotifyChannelTestDeliveryFailure(t *testing.T) {
	notifier := &fakeNotifier{err: errors.New("delivery boom")}
	h := newHarness(t, WithNotifier(notifier))
	id := seedChannel(t, h)
	cookie, csrf := h.authed()
	rec := h.do(http.MethodPost, "/admin/api/notify/channels/"+id+"/test", nil, func(r *http.Request) {
		r.AddCookie(cookie)
		r.Header.Set(CSRFHeaderName, csrf)
	})
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("test failure = %d, want 502", rec.Code)
	}
	// The error message must not echo any upstream detail.
	if strings.Contains(rec.Body.String(), "boom") {
		t.Errorf("test failure leaked upstream detail: %s", rec.Body.String())
	}
}

func TestNotifyChannelTestNoNotifier(t *testing.T) {
	h := newHarness(t) // no notifier wired
	id := seedChannel(t, h)
	cookie, csrf := h.authed()
	rec := h.do(http.MethodPost, "/admin/api/notify/channels/"+id+"/test", nil, func(r *http.Request) {
		r.AddCookie(cookie)
		r.Header.Set(CSRFHeaderName, csrf)
	})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("test without notifier = %d, want 503", rec.Code)
	}
}

func TestNotifyChannelPatchPreservesSecretWhenConfigOmitted(t *testing.T) {
	h := newHarness(t)
	id := seedChannel(t, h) // seeded URL + Secret "S"
	before := h.store.channels[id].Config

	// Metadata-only PATCH (no "config" key) must NOT blank the stored secrets.
	cookie, csrf := h.authed()
	rec := h.do(http.MethodPatch, "/admin/api/notify/channels/"+id, map[string]any{"enabled": false}, func(r *http.Request) {
		r.AddCookie(cookie)
		r.Header.Set(CSRFHeaderName, csrf)
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("patch = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	got := h.store.channels[id]
	if got.Enabled {
		t.Error("enabled not flipped to false")
	}
	if got.Config.URL != before.URL || got.Config.Secret != before.Secret {
		t.Errorf("metadata-only patch clobbered config: got %+v, want %+v", got.Config, before)
	}
}

// seedChannel stores a channel directly and returns its id.
func seedChannel(t *testing.T, h *harness) string {
	t.Helper()
	ch, err := h.store.InsertNotifyChannel(context.Background(), model.NotifyChannel{
		Type: model.ChannelDingTalk, Name: "seed", Enabled: true,
		Config: model.NotifyConfig{URL: "https://oapi.dingtalk.com/robot/send?access_token=T", Secret: "S"},
	})
	if err != nil {
		t.Fatalf("seed channel: %v", err)
	}
	return ch.ID
}
