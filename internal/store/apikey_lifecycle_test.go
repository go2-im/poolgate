package store

import (
	"context"
	"testing"
	"time"

	"github.com/go2-im/poolgate/internal/model"
)

// TestApiKeyLifecyclePersistence round-trips the v6 expiry + IP-allowlist columns
// through insert / list / get-by-key / get-by-id and exercises RotateApiKey.
func TestApiKeyLifecyclePersistence(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	exp := time.Date(2099, 1, 2, 15, 4, 5, 0, time.UTC)
	created, err := s.InsertApiKey(ctx, model.ApiKey{
		Key: "sk-lifecycle-000", Label: "lc", Endpoints: []string{"default"},
		ExpiresAt: exp, IPAllowlist: []string{"203.0.113.4", "10.0.0.0/8"},
	})
	if err != nil {
		t.Fatalf("InsertApiKey: %v", err)
	}

	check := func(name string, k model.ApiKey) {
		if !k.ExpiresAt.Equal(exp) {
			t.Errorf("%s: expiry = %v, want %v", name, k.ExpiresAt, exp)
		}
		if len(k.IPAllowlist) != 2 || k.IPAllowlist[0] != "203.0.113.4" {
			t.Errorf("%s: ip_allowlist = %v, want [203.0.113.4 10.0.0.0/8]", name, k.IPAllowlist)
		}
	}

	byKey, err := s.GetApiKeyByKey(ctx, "sk-lifecycle-000")
	if err != nil {
		t.Fatalf("GetApiKeyByKey: %v", err)
	}
	check("get-by-key", byKey)

	byID, err := s.GetApiKeyByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetApiKeyByID: %v", err)
	}
	check("get-by-id", byID)

	list, err := s.ListApiKeys(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListApiKeys: %v (n=%d)", err, len(list))
	}
	check("list", list[0])

	// Rotate: key changes, everything else preserved.
	rotated, err := s.RotateApiKey(ctx, created.ID, "sk-lifecycle-ROT")
	if err != nil {
		t.Fatalf("RotateApiKey: %v", err)
	}
	if rotated.Key != "sk-lifecycle-ROT" {
		t.Errorf("rotated key = %q, want sk-lifecycle-ROT", rotated.Key)
	}
	check("rotated", rotated)
	if _, err := s.GetApiKeyByKey(ctx, "sk-lifecycle-000"); err == nil {
		t.Error("old key still resolves after rotation")
	}

	// Rotate a missing id → ErrNotFound.
	if _, err := s.RotateApiKey(ctx, "key_missing", "sk-x"); err != ErrNotFound {
		t.Errorf("rotate missing = %v, want ErrNotFound", err)
	}
}

// TestApiKeyExpiredHelper covers model.ApiKey.Expired.
func TestApiKeyExpiredHelper(t *testing.T) {
	now := time.Now().UTC()
	if (model.ApiKey{}).Expired(now) {
		t.Error("zero expiry should never be expired")
	}
	if !(model.ApiKey{ExpiresAt: now.Add(-time.Second)}).Expired(now) {
		t.Error("past expiry should be expired")
	}
	if (model.ApiKey{ExpiresAt: now.Add(time.Hour)}).Expired(now) {
		t.Error("future expiry should not be expired")
	}
	// Exactly at expiry counts as expired (now not before ExpiresAt).
	if !(model.ApiKey{ExpiresAt: now}).Expired(now) {
		t.Error("expiry == now should be expired")
	}
}
