// channels.go implements the three v1 delivery channels (DESIGN.md §11):
// DingTalk custom robot (with 加签/HMAC-SHA256 signing), WeCom group robot, and a
// generic custom webhook. All delivery goes over the SSRF-guarded HTTP client
// (see ssrf.go); the payload is built from a secret-free model.NotifyEvent.
//
// Error hygiene (SECURITY.md): errors returned here NEVER echo the channel URL,
// signing secret, or any request header — only the channel type, HTTP status,
// and (for DingTalk/WeCom) the upstream errcode/errmsg, which contain no
// poolgate secret. Callers log these safely.
package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/go2-im/poolgate/internal/model"
)

// maxRespBody caps how much of a channel response we read (for the errcode check
// and to bound memory). Notification acks are tiny.
const maxRespBody = 64 << 10

// errPermanent marks a delivery failure that can never succeed on retry (bad
// config, unknown type, malformed template, upstream rejection by errcode). The
// dispatcher checks errors.Is(err, errPermanent) and skips the retry/backoff loop
// for these (ErrInsecureScheme is treated the same way).
var errPermanent = errors.New("notify: permanent delivery error")

// send dispatches ev to ch over client, choosing the per-type formatter/signer.
// now supplies the timestamp for DingTalk signing (injectable for tests).
func send(ctx context.Context, client *http.Client, now func() time.Time, ch model.NotifyChannel, ev model.NotifyEvent) error {
	switch ch.Type {
	case model.ChannelDingTalk:
		return sendDingTalk(ctx, client, now, ch.Config, ev)
	case model.ChannelWeCom:
		return sendWeCom(ctx, client, ch.Config, ev)
	case model.ChannelWebhook:
		return sendWebhook(ctx, client, ch.Config, ev)
	default:
		return fmt.Errorf("notify: unknown channel type %q: %w", ch.Type, errPermanent)
	}
}

// robotAck is the common DingTalk / WeCom robot response envelope.
type robotAck struct {
	ErrCode int    `json:"errcode"`
	ErrMsg  string `json:"errmsg"`
}

// sendDingTalk posts a text message to a DingTalk custom robot. When cfg.Secret is
// set it appends the 加签 timestamp+sign query params. A 2xx HTTP status with a
// non-zero errcode is still a failure.
func sendDingTalk(ctx context.Context, client *http.Client, now func() time.Time, cfg model.NotifyConfig, ev model.NotifyEvent) error {
	if err := requireHTTPS(cfg.URL); err != nil {
		return err
	}
	target := cfg.URL
	if cfg.Secret != "" {
		ts := strconv.FormatInt(now().UnixMilli(), 10)
		sign := dingtalkSign(cfg.Secret, ts)
		sep := "&"
		if !strings.Contains(target, "?") {
			sep = "?"
		}
		target += sep + "timestamp=" + ts + "&sign=" + url.QueryEscape(sign)
	}
	body, err := json.Marshal(map[string]any{
		"msgtype": "text",
		"text":    map[string]string{"content": ev.Message},
	})
	if err != nil {
		return fmt.Errorf("notify: marshal dingtalk body: %w", err)
	}
	return postRobot(ctx, client, "dingtalk", target, body)
}

// dingtalkSign computes the DingTalk 加签 value: base64(HMAC-SHA256(secret,
// "<timestamp>\n<secret>")).
func dingtalkSign(secret, timestamp string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp + "\n" + secret))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// sendWeCom posts a text message to a WeCom / 企业微信 group robot.
func sendWeCom(ctx context.Context, client *http.Client, cfg model.NotifyConfig, ev model.NotifyEvent) error {
	if err := requireHTTPS(cfg.URL); err != nil {
		return err
	}
	body, err := json.Marshal(map[string]any{
		"msgtype": "text",
		"text":    map[string]string{"content": ev.Message},
	})
	if err != nil {
		return fmt.Errorf("notify: marshal wecom body: %w", err)
	}
	return postRobot(ctx, client, "wecom", cfg.URL, body)
}

// postRobot sends a JSON body to a DingTalk/WeCom robot and validates both the
// HTTP status and the errcode in the ack. The error never includes the URL.
func postRobot(ctx context.Context, client *http.Client, kind, target string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("notify: build %s request: %w", kind, err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("notify: %s delivery failed: %w", kind, redactURLErr(err, target))
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxRespBody))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("notify: %s delivery failed: http %d", kind, resp.StatusCode)
	}
	var ack robotAck
	if err := json.Unmarshal(raw, &ack); err == nil && ack.ErrCode != 0 {
		return fmt.Errorf("notify: %s rejected: errcode %d (%s): %w", kind, ack.ErrCode, ack.ErrMsg, errPermanent)
	}
	return nil
}

// sendWebhook posts (or uses cfg.Method) the event to a custom webhook. When
// cfg.Template is set it is rendered with the event fields; otherwise a compact
// secret-free JSON object is sent. Custom headers are applied.
func sendWebhook(ctx context.Context, client *http.Client, cfg model.NotifyConfig, ev model.NotifyEvent) error {
	if err := requireHTTPS(cfg.URL); err != nil {
		return err
	}
	body, contentType, err := webhookBody(cfg, ev)
	if err != nil {
		return err
	}
	method := strings.ToUpper(strings.TrimSpace(cfg.Method))
	if method == "" {
		method = http.MethodPost
	}
	req, err := http.NewRequestWithContext(ctx, method, cfg.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("notify: build webhook request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)
	for k, v := range cfg.Headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("notify: webhook delivery failed: %w", redactURLErr(err, cfg.URL))
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxRespBody))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("notify: webhook delivery failed: http %d", resp.StatusCode)
	}
	return nil
}

// webhookBody renders the request body for a custom webhook. A configured
// template wins; otherwise the event is marshaled as compact JSON.
//
// text/template does NOT escape for JSON, so a template that interpolates a field
// carrying a quote/backslash (e.g. an account label) would emit malformed JSON.
// A `json` template function is provided so operators can write a safe body, e.g.
//
//	{"text": {{.Message | json}}, "kind": {{.Kind | json}}}
//
// (`json` emits a fully-quoted, escaped JSON string). Bare `{{.Message}}`
// interpolation remains available for non-JSON bodies.
func webhookBody(cfg model.NotifyConfig, ev model.NotifyEvent) (body []byte, contentType string, err error) {
	if strings.TrimSpace(cfg.Template) == "" {
		b, merr := json.Marshal(ev)
		if merr != nil {
			return nil, "", fmt.Errorf("notify: marshal webhook event: %w", merr)
		}
		return b, "application/json", nil
	}
	tmpl, terr := template.New("webhook").Funcs(template.FuncMap{"json": jsonEscape}).Parse(cfg.Template)
	if terr != nil {
		return nil, "", fmt.Errorf("notify: parse webhook template: %w: %w", terr, errPermanent)
	}
	var buf bytes.Buffer
	if eerr := tmpl.Execute(&buf, ev); eerr != nil {
		return nil, "", fmt.Errorf("notify: render webhook template: %w: %w", eerr, errPermanent)
	}
	return buf.Bytes(), "application/json", nil
}

// jsonEscape renders v as a JSON value (a quoted, escaped string for strings), so
// a webhook template can interpolate untrusted fields safely: `{{.Message | json}}`.
func jsonEscape(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// redactURLErr strips a channel URL out of a transport error string so a secret
// robot token embedded in the URL never lands in logs. It preserves the rest of
// the error (e.g. the SSRF ErrBlockedAddress, DNS failure) for diagnosis.
func redactURLErr(err error, target string) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if target != "" && strings.Contains(msg, target) {
		msg = strings.ReplaceAll(msg, target, "<redacted-url>")
	}
	// Also redact the host:port form url.Error tends to include.
	if u, perr := url.Parse(target); perr == nil && u.Host != "" && strings.Contains(msg, u.Host) {
		msg = strings.ReplaceAll(msg, u.Host, "<redacted-host>")
	}
	return fmt.Errorf("%s", msg)
}
