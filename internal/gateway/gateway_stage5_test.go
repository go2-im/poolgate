package gateway

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

// TestErrorEnvelopeIncludesParam proves the OpenAI-compatible error envelope always
// carries all four keys — message, type, code, AND param (audit P3; §19.4) — so a
// client reading error.param never hits a missing key.
func TestErrorEnvelopeIncludesParam(t *testing.T) {
	rec := httptest.NewRecorder()
	writeError(rec, 503, "poolgate_no_healthy_account", "no_healthy_account", "no healthy account")

	var body map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode envelope: %v (body=%s)", err, rec.Body.String())
	}
	var detail map[string]json.RawMessage
	if err := json.Unmarshal(body["error"], &detail); err != nil {
		t.Fatalf("decode error detail: %v", err)
	}
	for _, k := range []string{"message", "type", "code", "param"} {
		if _, ok := detail[k]; !ok {
			t.Errorf("error envelope missing key %q (have %v)", k, detail)
		}
	}
}
