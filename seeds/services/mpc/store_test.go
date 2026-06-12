package main

import (
	"context"
	"testing"
)

func TestStoreKeyShareCeremonyFlows(t *testing.T) {
	_, store, _ := newMPCService(t)
	tenantID := "tenant-store"

	key := MPCKey{
		ID:                "mkey1",
		TenantID:          tenantID,
		Name:              "wallet",
		Algorithm:         "ECDSA_SECP256K1",
		Threshold:         2,
		ParticipantCount:  3,
		Participants:      []string{"node-1", "node-2", "node-3"},
		PublicCommitments: []string{"1", "2"},
		Status:            "pending_dkg",
		ShareVersion:      1,
		Metadata:          map[string]interface{}{"a": "b"},
	}
	if err := store.CreateMPCKey(context.Background(), key); err != nil {
		t.Fatalf("create key: %v", err)
	}
	gotKey, err := store.GetMPCKey(context.Background(), tenantID, key.ID)
	if err != nil {
		t.Fatalf("get key: %v", err)
	}
	if gotKey.Algorithm != key.Algorithm {
		t.Fatalf("unexpected key %+v", gotKey)
	}

	shares := []MPCShare{
		{ID: "s1", TenantID: tenantID, KeyID: key.ID, NodeID: "node-1", ShareX: 1, ShareYValue: "11", ShareYHash: "h1", ShareVersion: 1, Status: "active"},
		{ID: "s2", TenantID: tenantID, KeyID: key.ID, NodeID: "node-2", ShareX: 2, ShareYValue: "22", ShareYHash: "h2", ShareVersion: 1, Status: "active"},
	}
	if err := store.ReplaceShares(context.Background(), tenantID, key.ID, shares, ""); err != nil {
		t.Fatalf("replace shares: %v", err)
	}
	gotShares, err := store.ListShares(context.Background(), tenantID, key.ID)
	if err != nil {
		t.Fatalf("list shares: %v", err)
	}
	if len(gotShares) != 2 {
		t.Fatalf("expected 2 shares got %d", len(gotShares))
	}

	ceremony := MPCCeremony{
		ID:                   "c1",
		TenantID:             tenantID,
		Type:                 "sign",
		KeyID:                key.ID,
		Algorithm:            key.Algorithm,
		Threshold:            2,
		ParticipantCount:     2,
		Participants:         []string{"node-1", "node-2"},
		Status:               "pending",
		Result:               map[string]interface{}{},
		RequiredContributors: 2,
	}
	if err := store.CreateCeremony(context.Background(), ceremony); err != nil {
		t.Fatalf("create ceremony: %v", err)
	}
	if err := store.UpsertCeremonyContribution(context.Background(), MPCContribution{
		TenantID:   tenantID,
		CeremonyID: "c1",
		PartyID:    "node-1",
		Payload:    map[string]interface{}{"partial_signature": "abc"},
	}); err != nil {
		t.Fatalf("upsert contribution: %v", err)
	}
	contribs, err := store.ListCeremonyContributions(context.Background(), tenantID, "c1")
	if err != nil {
		t.Fatalf("list contribution: %v", err)
	}
	if len(contribs) != 1 {
		t.Fatalf("expected 1 contribution got %d", len(contribs))
	}
}
