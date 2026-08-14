package store

import (
	"context"
	"strings"
	"testing"

	"github.com/go2-im/poolgate/internal/model"
)

func sampleChannel() model.NotifyChannel {
	return model.NotifyChannel{
		Type:    model.ChannelDingTalk,
		Name:    "ops",
		Enabled: true,
		Config: model.NotifyConfig{
			URL:    "https://oapi.dingtalk.com/robot/send?access_token=SECRET_TOKEN",
			Secret: "SEC_signing",
		},
		Events:       []model.NotifyEventKind{model.EventAccountExpired, model.EventQuotaLow},
		MinHeadroom:  10,
		DedupSeconds: 300,
	}
}

func TestNotifyChannelRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	created, err := s.InsertNotifyChannel(ctx, sampleChannel())
	if err != nil {
		t.Fatalf("InsertNotifyChannel: %v", err)
	}
	if created.ID == "" {
		t.Fatal("InsertNotifyChannel did not assign an id")
	}

	got, err := s.GetNotifyChannel(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetNotifyChannel: %v", err)
	}
	if got.Config.URL != created.Config.URL || got.Config.Secret != "SEC_signing" {
		t.Errorf("config not round-tripped: %+v", got.Config)
	}
	if got.Type != model.ChannelDingTalk || got.Name != "ops" || !got.Enabled {
		t.Errorf("scalar fields not round-tripped: %+v", got)
	}
	if len(got.Events) != 2 || got.Events[0] != model.EventAccountExpired {
		t.Errorf("events not round-tripped: %+v", got.Events)
	}
	if got.MinHeadroom != 10 || got.DedupSeconds != 300 {
		t.Errorf("thresholds not round-tripped: %+v", got)
	}
}

func TestNotifyChannelConfigEncryptedAtRest(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	created, err := s.InsertNotifyChannel(ctx, sampleChannel())
	if err != nil {
		t.Fatalf("InsertNotifyChannel: %v", err)
	}
	// The raw config column must NOT contain the plaintext secret.
	var rawConfig string
	if err := s.db.QueryRowContext(ctx,
		`SELECT config FROM notify_channels WHERE id = ?`, created.ID).Scan(&rawConfig); err != nil {
		t.Fatalf("read raw config: %v", err)
	}
	if strings.Contains(rawConfig, "SECRET_TOKEN") || strings.Contains(rawConfig, "SEC_signing") {
		t.Fatalf("plaintext secret leaked into stored config column: %q", rawConfig)
	}
}

func TestListNotifyChannelsOrdered(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	for _, name := range []string{"a", "b", "c"} {
		ch := sampleChannel()
		ch.Name = name
		if _, err := s.InsertNotifyChannel(ctx, ch); err != nil {
			t.Fatalf("insert %s: %v", name, err)
		}
	}
	list, err := s.ListNotifyChannels(ctx)
	if err != nil {
		t.Fatalf("ListNotifyChannels: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("len = %d, want 3", len(list))
	}
	for _, ch := range list {
		if ch.Config.URL == "" {
			t.Errorf("channel %s missing decrypted config", ch.ID)
		}
	}
}

func TestUpdateNotifyChannel(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	created, err := s.InsertNotifyChannel(ctx, sampleChannel())
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	created.Name = "renamed"
	created.Enabled = false
	created.Config.URL = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=NEWKEY"
	created.Type = model.ChannelWeCom
	if err := s.UpdateNotifyChannel(ctx, created); err != nil {
		t.Fatalf("UpdateNotifyChannel: %v", err)
	}
	got, err := s.GetNotifyChannel(ctx, created.ID)
	if err != nil {
		t.Fatalf("get after update: %v", err)
	}
	if got.Name != "renamed" || got.Enabled || got.Type != model.ChannelWeCom {
		t.Errorf("update not applied: %+v", got)
	}
	if !strings.Contains(got.Config.URL, "NEWKEY") {
		t.Errorf("config not updated: %q", got.Config.URL)
	}
}

func TestNotifyChannelErrors(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.GetNotifyChannel(ctx, "missing"); err != ErrNotFound {
		t.Errorf("GetNotifyChannel(missing) err = %v, want ErrNotFound", err)
	}
	if err := s.DeleteNotifyChannel(ctx, "missing"); err != ErrNotFound {
		t.Errorf("DeleteNotifyChannel(missing) err = %v, want ErrNotFound", err)
	}
	if err := s.UpdateNotifyChannel(ctx, model.NotifyChannel{Type: model.ChannelDingTalk}); err == nil {
		t.Error("UpdateNotifyChannel with empty id should error")
	}
	if err := s.UpdateNotifyChannel(ctx, model.NotifyChannel{ID: "x", Type: "bogus"}); err == nil {
		t.Error("UpdateNotifyChannel with bad type should error")
	}
	if _, err := s.InsertNotifyChannel(ctx, model.NotifyChannel{Type: "bogus"}); err == nil {
		t.Error("InsertNotifyChannel with bad type should error")
	}

	// Delete happy path.
	created, err := s.InsertNotifyChannel(ctx, sampleChannel())
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := s.DeleteNotifyChannel(ctx, created.ID); err != nil {
		t.Fatalf("DeleteNotifyChannel: %v", err)
	}
	if _, err := s.GetNotifyChannel(ctx, created.ID); err != ErrNotFound {
		t.Errorf("after delete err = %v, want ErrNotFound", err)
	}
}

func TestMigrationV4Applied(t *testing.T) {
	s := newTestStore(t)
	v, err := s.SchemaVersion(context.Background())
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if v < 4 {
		t.Fatalf("SchemaVersion = %d, want >= 4 (notify_channels)", v)
	}
}
