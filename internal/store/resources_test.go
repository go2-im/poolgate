package store

import (
	"context"
	"errors"
	"testing"

	"github.com/go2-im/poolgate/internal/model"
)

func TestDeleteAccount(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	a, err := s.InsertAccount(ctx, model.Account{AccessToken: "a", RefreshToken: "r"})
	if err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}
	// A usage snapshot + health check should cascade away with the account.
	if _, err := s.SaveUsageSnapshot(ctx, model.UsageSnapshot{AccountID: a.ID}); err != nil {
		t.Fatalf("SaveUsageSnapshot: %v", err)
	}
	if _, err := s.RecordHealthCheck(ctx, model.HealthCheck{AccountID: a.ID, Kind: model.HealthKindUsagePoll}); err != nil {
		t.Fatalf("RecordHealthCheck: %v", err)
	}

	if err := s.DeleteAccount(ctx, a.ID); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}
	if _, err := s.GetAccount(ctx, a.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetAccount after delete = %v, want ErrNotFound", err)
	}
	if _, err := s.GetLatestUsage(ctx, a.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetLatestUsage after delete = %v, want ErrNotFound", err)
	}
	// Deleting a missing account is ErrNotFound.
	if err := s.DeleteAccount(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteAccount(missing) = %v, want ErrNotFound", err)
	}
}

func TestApiKeyByIDAndDelete(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	k, err := s.InsertApiKey(ctx, model.ApiKey{Key: "sk-abc", Label: "l", Endpoints: []string{"prod"}})
	if err != nil {
		t.Fatalf("InsertApiKey: %v", err)
	}
	got, err := s.GetApiKeyByID(ctx, k.ID)
	if err != nil {
		t.Fatalf("GetApiKeyByID: %v", err)
	}
	if got.Key != "" || got.KeyHash != hashAPIKey("sk-abc") || got.KeyHint != "-abc" ||
		len(got.Endpoints) != 1 || got.Endpoints[0] != "prod" {
		t.Fatalf("GetApiKeyByID = %+v, unexpected (Key must be empty, hash/hint set)", got)
	}
	if _, err := s.GetApiKeyByID(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetApiKeyByID(missing) = %v, want ErrNotFound", err)
	}
	if err := s.DeleteApiKey(ctx, k.ID); err != nil {
		t.Fatalf("DeleteApiKey: %v", err)
	}
	if err := s.DeleteApiKey(ctx, k.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteApiKey(twice) = %v, want ErrNotFound", err)
	}
}

func TestListAndDeleteEndpoints(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	g, err := s.InsertPolicyGroup(ctx, model.PolicyGroup{Name: "g", Strategy: model.StrategyFallback})
	if err != nil {
		t.Fatalf("InsertPolicyGroup: %v", err)
	}
	for _, n := range []string{"b", "a"} {
		if _, err := s.InsertEndpoint(ctx, model.Endpoint{Name: n, GroupID: g.ID}); err != nil {
			t.Fatalf("InsertEndpoint(%s): %v", n, err)
		}
	}
	eps, err := s.ListEndpoints(ctx)
	if err != nil {
		t.Fatalf("ListEndpoints: %v", err)
	}
	if len(eps) != 2 || eps[0].Name != "a" || eps[1].Name != "b" {
		t.Fatalf("ListEndpoints = %+v, want sorted [a b]", eps)
	}
	if err := s.DeleteEndpoint(ctx, "a"); err != nil {
		t.Fatalf("DeleteEndpoint: %v", err)
	}
	if err := s.DeleteEndpoint(ctx, "a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteEndpoint(twice) = %v, want ErrNotFound", err)
	}
}

func TestListUpdateDeletePolicyGroups(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	a1, _ := s.InsertAccount(ctx, model.Account{AccessToken: "a", RefreshToken: "r"})
	a2, _ := s.InsertAccount(ctx, model.Account{AccessToken: "a", RefreshToken: "r"})

	gb, err := s.InsertPolicyGroup(ctx, model.PolicyGroup{
		Name: "beta", Strategy: model.StrategyFallback, MemberAccountIDs: []string{a1.ID},
	})
	if err != nil {
		t.Fatalf("InsertPolicyGroup beta: %v", err)
	}
	if _, err := s.InsertPolicyGroup(ctx, model.PolicyGroup{Name: "alpha", Strategy: model.StrategyLoadBalance}); err != nil {
		t.Fatalf("InsertPolicyGroup alpha: %v", err)
	}

	groups, err := s.ListPolicyGroups(ctx)
	if err != nil {
		t.Fatalf("ListPolicyGroups: %v", err)
	}
	if len(groups) != 2 || groups[0].Name != "alpha" || groups[1].Name != "beta" {
		t.Fatalf("ListPolicyGroups = %+v, want sorted [alpha beta]", groups)
	}

	// Update beta: change strategy and swap members.
	gb.Strategy = model.StrategyBestQuota
	gb.MemberAccountIDs = []string{a2.ID, a1.ID}
	if err := s.UpdatePolicyGroup(ctx, gb); err != nil {
		t.Fatalf("UpdatePolicyGroup: %v", err)
	}
	got, err := s.GetPolicyGroup(ctx, gb.ID)
	if err != nil {
		t.Fatalf("GetPolicyGroup: %v", err)
	}
	if got.Strategy != model.StrategyBestQuota {
		t.Fatalf("strategy = %q, want best-quota", got.Strategy)
	}
	if len(got.MemberAccountIDs) != 2 || got.MemberAccountIDs[0] != a2.ID || got.MemberAccountIDs[1] != a1.ID {
		t.Fatalf("members = %v, want [%s %s]", got.MemberAccountIDs, a2.ID, a1.ID)
	}

	// Update with empty id and missing id.
	if err := s.UpdatePolicyGroup(ctx, model.PolicyGroup{}); err == nil {
		t.Fatal("UpdatePolicyGroup(empty id) = nil, want error")
	}
	if err := s.UpdatePolicyGroup(ctx, model.PolicyGroup{ID: "missing", Strategy: model.StrategyFallback}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("UpdatePolicyGroup(missing) = %v, want ErrNotFound", err)
	}

	// Delete restricted by endpoint FK, then allowed after endpoint removal.
	if _, err := s.InsertEndpoint(ctx, model.Endpoint{Name: "ep", GroupID: gb.ID}); err != nil {
		t.Fatalf("InsertEndpoint: %v", err)
	}
	if err := s.DeletePolicyGroup(ctx, gb.ID); err == nil {
		t.Fatal("DeletePolicyGroup(referenced) = nil, want FK error")
	}
	if err := s.DeleteEndpoint(ctx, "ep"); err != nil {
		t.Fatalf("DeleteEndpoint: %v", err)
	}
	if err := s.DeletePolicyGroup(ctx, gb.ID); err != nil {
		t.Fatalf("DeletePolicyGroup: %v", err)
	}
	if err := s.DeletePolicyGroup(ctx, gb.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeletePolicyGroup(twice) = %v, want ErrNotFound", err)
	}
}

func TestPolicyGroupWeightsRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	a1, _ := s.InsertAccount(ctx, model.Account{AccessToken: "a", RefreshToken: "r"})
	a2, _ := s.InsertAccount(ctx, model.Account{AccessToken: "a", RefreshToken: "r"})

	g, err := s.InsertPolicyGroup(ctx, model.PolicyGroup{
		Name: "w", Strategy: model.StrategyWeighted,
		MemberAccountIDs: []string{a1.ID, a2.ID},
		MemberWeights:    map[string]int{a1.ID: 3}, // a2 defaults to 1 (omitted)
	})
	if err != nil {
		t.Fatalf("InsertPolicyGroup: %v", err)
	}

	got, err := s.GetPolicyGroup(ctx, g.ID)
	if err != nil {
		t.Fatalf("GetPolicyGroup: %v", err)
	}
	if got.Weight(a1.ID) != 3 || got.Weight(a2.ID) != 1 {
		t.Errorf("weights = a1:%d a2:%d, want 3/1", got.Weight(a1.ID), got.Weight(a2.ID))
	}

	// Update changes weights.
	got.MemberWeights = map[string]int{a2.ID: 5}
	if err := s.UpdatePolicyGroup(ctx, got); err != nil {
		t.Fatalf("UpdatePolicyGroup: %v", err)
	}
	after, _ := s.GetPolicyGroup(ctx, g.ID)
	if after.Weight(a1.ID) != 1 || after.Weight(a2.ID) != 5 {
		t.Errorf("after update: a1:%d a2:%d, want 1/5", after.Weight(a1.ID), after.Weight(a2.ID))
	}
}
