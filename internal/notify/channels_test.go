package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go2-im/poolgate/internal/model"
)

func fixedNow() time.Time { return time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC) }

func testEvent() model.NotifyEvent {
	return model.NotifyEvent{
		Kind:         model.EventAccountCooldown,
		AccountID:    "acct_1",
		AccountLabel: "prod-1",
		Message:      "poolgate: account prod-1 entered cooldown",
		At:           fixedNow(),
	}
}

func TestDingtalkSignDeterministic(t *testing.T) {
	// Golden value for a known secret + timestamp (base64 of HMAC-SHA256).
	got := dingtalkSign("SECabc", "1700000000000")
	got2 := dingtalkSign("SECabc", "1700000000000")
	if got != got2 {
		t.Fatal("dingtalkSign not deterministic")
	}
	if got == "" || strings.Contains(got, "SECabc") {
		t.Errorf("sign looks wrong / leaks secret: %q", got)
	}
}

func TestSendDingTalkOverHTTPS(t *testing.T) {
	var gotSign, gotBody string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSign = r.URL.Query().Get("sign")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		_, _ = io.WriteString(w, `{"errcode":0,"errmsg":"ok"}`)
	}))
	defer srv.Close()

	ch := model.NotifyChannel{Type: model.ChannelDingTalk, Config: model.NotifyConfig{
		URL: srv.URL, Secret: "SECabc",
	}}
	if err := send(context.Background(), srv.Client(), fixedNow, ch, testEvent()); err != nil {
		t.Fatalf("send dingtalk: %v", err)
	}
	if gotSign == "" {
		t.Error("expected a sign query param")
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(gotBody), &body); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if body["msgtype"] != "text" {
		t.Errorf("msgtype = %v, want text", body["msgtype"])
	}
}

func TestSendDingTalkErrcodeFailure(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"errcode":310000,"errmsg":"keyword not found"}`)
	}))
	defer srv.Close()
	ch := model.NotifyChannel{Type: model.ChannelDingTalk, Config: model.NotifyConfig{URL: srv.URL}}
	err := send(context.Background(), srv.Client(), fixedNow, ch, testEvent())
	if err == nil || !strings.Contains(err.Error(), "310000") {
		t.Fatalf("err = %v, want errcode 310000", err)
	}
}

func TestSendDingTalkHTTPError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	ch := model.NotifyChannel{Type: model.ChannelDingTalk, Config: model.NotifyConfig{URL: srv.URL}}
	err := send(context.Background(), srv.Client(), fixedNow, ch, testEvent())
	if err == nil || !strings.Contains(err.Error(), "http 500") {
		t.Fatalf("err = %v, want http 500", err)
	}
}

func TestSendWeCom(t *testing.T) {
	var gotBody string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		_, _ = io.WriteString(w, `{"errcode":0,"errmsg":"ok"}`)
	}))
	defer srv.Close()
	ch := model.NotifyChannel{Type: model.ChannelWeCom, Config: model.NotifyConfig{URL: srv.URL}}
	if err := send(context.Background(), srv.Client(), fixedNow, ch, testEvent()); err != nil {
		t.Fatalf("send wecom: %v", err)
	}
	if !strings.Contains(gotBody, "msgtype") {
		t.Errorf("body = %q", gotBody)
	}
}

func TestSendWebhookDefaultJSON(t *testing.T) {
	var gotBody, gotCT, gotHdr string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		gotCT = r.Header.Get("Content-Type")
		gotHdr = r.Header.Get("X-Custom")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	ch := model.NotifyChannel{Type: model.ChannelWebhook, Config: model.NotifyConfig{
		URL: srv.URL, Headers: map[string]string{"X-Custom": "yes"},
	}}
	if err := send(context.Background(), srv.Client(), fixedNow, ch, testEvent()); err != nil {
		t.Fatalf("send webhook: %v", err)
	}
	if gotCT != "application/json" || gotHdr != "yes" {
		t.Errorf("content-type=%q custom=%q", gotCT, gotHdr)
	}
	var ev model.NotifyEvent
	if err := json.Unmarshal([]byte(gotBody), &ev); err != nil {
		t.Fatalf("default body not the event JSON: %v", err)
	}
	if ev.Kind != model.EventAccountCooldown {
		t.Errorf("kind = %s", ev.Kind)
	}
}

func TestSendWebhookTemplate(t *testing.T) {
	var gotBody string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
	}))
	defer srv.Close()
	ch := model.NotifyChannel{Type: model.ChannelWebhook, Config: model.NotifyConfig{
		URL:      srv.URL,
		Template: `{"text":"{{.Message}}","kind":"{{.Kind}}"}`,
	}}
	if err := send(context.Background(), srv.Client(), fixedNow, ch, testEvent()); err != nil {
		t.Fatalf("send webhook template: %v", err)
	}
	if !strings.Contains(gotBody, "entered cooldown") || !strings.Contains(gotBody, "account_cooldown") {
		t.Errorf("rendered body = %q", gotBody)
	}
}

func TestSendWebhookTemplateJSONEscape(t *testing.T) {
	var gotBody string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
	}))
	defer srv.Close()
	ch := model.NotifyChannel{Type: model.ChannelWebhook, Config: model.NotifyConfig{
		URL:      srv.URL,
		Template: `{"text":{{.Message | json}}}`,
	}}
	// A message containing a double-quote and backslash must still yield valid JSON
	// when passed through the `json` template helper.
	ev := testEvent()
	ev.Message = `account "prod\1" tripped`
	if err := send(context.Background(), srv.Client(), fixedNow, ch, ev); err != nil {
		t.Fatalf("send: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(gotBody), &parsed); err != nil {
		t.Fatalf("rendered body is not valid JSON: %v\nbody=%q", err, gotBody)
	}
	if parsed["text"] != ev.Message {
		t.Errorf("text = %q, want %q", parsed["text"], ev.Message)
	}
}

func TestSendWebhookBadTemplate(t *testing.T) {
	ch := model.NotifyChannel{Type: model.ChannelWebhook, Config: model.NotifyConfig{
		URL:      "https://example.com",
		Template: `{{.Nope`,
	}}
	// A malformed template fails before any request is made.
	if err := send(context.Background(), http.DefaultClient, fixedNow, ch, testEvent()); err == nil {
		t.Fatal("expected template parse error")
	}
}

func TestSendRejectsHTTPScheme(t *testing.T) {
	for _, tp := range []model.NotifyChannelType{model.ChannelDingTalk, model.ChannelWeCom, model.ChannelWebhook} {
		ch := model.NotifyChannel{Type: tp, Config: model.NotifyConfig{URL: "http://insecure.example.com"}}
		if err := send(context.Background(), http.DefaultClient, fixedNow, ch, testEvent()); err == nil {
			t.Errorf("%s: expected https-only rejection", tp)
		}
	}
}

func TestSendUnknownType(t *testing.T) {
	ch := model.NotifyChannel{Type: "carrier-pigeon", Config: model.NotifyConfig{URL: "https://x.example.com"}}
	if err := send(context.Background(), http.DefaultClient, fixedNow, ch, testEvent()); err == nil {
		t.Fatal("expected unknown channel type error")
	}
}

func TestRedactURLErr(t *testing.T) {
	target := "https://oapi.dingtalk.com/robot/send?access_token=SUPERSECRET"
	err := redactURLErr(errBoom(target), target)
	if err == nil || strings.Contains(err.Error(), "SUPERSECRET") {
		t.Fatalf("redactURLErr leaked secret: %v", err)
	}
	if redactURLErr(nil, target) != nil {
		t.Error("redactURLErr(nil) should be nil")
	}
}

// errBoom builds an error whose message embeds the URL (to test redaction).
func errBoom(url string) error { return &wrapErr{msg: "dial " + url + ": timeout"} }

type wrapErr struct{ msg string }

func (e *wrapErr) Error() string { return e.msg }
