package main

import (
	"context"
	"testing"
)

func TestServiceDKGSignDecryptLifecycle(t *testing.T) {
	svc, _, pub := newMPCService(t)
	tenantID := "tenant-svc"

	dkg, err := svc.InitiateDKG(context.Background(), DKGInitiateRequest{
		TenantID:     tenantID,
		KeyName:      "custody",
		Algorithm:    "ECDSA_SECP256K1",
		Threshold:    2,
		Participants: []string{"node-1", "node-2", "node-3"},
		KeyCoreKeyID: "kc-1",
		CreatedBy:    "alice",
	})
	if err != nil {
		t.Fatalf("init dkg: %v", err)
	}
	keyID := dkg.KeyID
	if keyID == "" {
		t.Fatalf("expected key id")
	}

	dkg, err = svc.ContributeDKG(context.Background(), dkg.ID, DKGContributeRequest{TenantID: tenantID, PartyID: "node-1"})
	if err != nil {
		t.Fatalf("dkg contribution 1: %v", err)
	}
	dkg, err = svc.ContributeDKG(context.Background(), dkg.ID, DKGContributeRequest{TenantID: tenantID, PartyID: "node-2"})
	if err != nil {
		t.Fatalf("dkg contribution 2: %v", err)
	}
	if dkg.Status != "completed" {
		t.Fatalf("expected completed dkg, got %s", dkg.Status)
	}

	sign, err := svc.InitiateSign(context.Background(), SignInitiateRequest{
		TenantID:    tenantID,
		KeyID:       keyID,
		MessageHash: "deadbeef",
	})
	if err != nil {
		t.Fatalf("init sign: %v", err)
	}
	sign, err = svc.ContributeSign(context.Background(), sign.ID, SignContributeRequest{TenantID: tenantID, PartyID: "node-1"})
	if err != nil {
		t.Fatalf("sign contribution 1: %v", err)
	}
	sign, err = svc.ContributeSign(context.Background(), sign.ID, SignContributeRequest{TenantID: tenantID, PartyID: "node-2"})
	if err != nil {
		t.Fatalf("sign contribution 2: %v", err)
	}
	if sign.Status != "completed" {
		t.Fatalf("expected completed sign, got %s", sign.Status)
	}
	signResult, err := svc.GetCeremonyResult(context.Background(), tenantID, sign.ID, "sign")
	if err != nil {
		t.Fatalf("get sign result: %v", err)
	}
	if firstString(signResult["signature"]) == "" {
		t.Fatalf("expected signature in result")
	}

	decrypt, err := svc.InitiateDecrypt(context.Background(), DecryptInitiateRequest{
		TenantID:     tenantID,
		KeyID:        keyID,
		Ciphertext:   "7b2274657374223a227061796c6f6164227d",
		Participants: []string{"node-1", "node-2"},
	})
	if err != nil {
		t.Fatalf("init decrypt: %v", err)
	}
	decrypt, err = svc.ContributeDecrypt(context.Background(), decrypt.ID, DecryptContributeRequest{TenantID: tenantID, PartyID: "node-1"})
	if err != nil {
		t.Fatalf("decrypt contribution 1: %v", err)
	}
	decrypt, err = svc.ContributeDecrypt(context.Background(), decrypt.ID, DecryptContributeRequest{TenantID: tenantID, PartyID: "node-2"})
	if err != nil {
		t.Fatalf("decrypt contribution 2: %v", err)
	}
	if decrypt.Status != "completed" {
		t.Fatalf("expected completed decrypt, got %s", decrypt.Status)
	}
	decResult, err := svc.GetCeremonyResult(context.Background(), tenantID, decrypt.ID, "decrypt")
	if err != nil {
		t.Fatalf("get decrypt result: %v", err)
	}
	if firstString(decResult["plaintext_b64"]) == "" {
		t.Fatalf("expected plaintext result")
	}

	keyAfterRefresh, err := svc.RefreshShares(context.Background(), keyID, ShareRefreshRequest{TenantID: tenantID, Actor: "alice"})
	if err != nil {
		t.Fatalf("refresh shares: %v", err)
	}
	if keyAfterRefresh.ShareVersion < 2 {
		t.Fatalf("expected share version increase, got %d", keyAfterRefresh.ShareVersion)
	}

	backup, err := svc.BackupShare(context.Background(), ShareBackupRequest{
		TenantID:    tenantID,
		KeyID:       keyID,
		NodeID:      "node-1",
		Destination: "dr-site-a",
		RequestedBy: "alice",
	})
	if err != nil {
		t.Fatalf("backup share: %v", err)
	}
	if firstString(backup["backup_artifact"]) == "" {
		t.Fatalf("expected backup artifact")
	}

	rotated, err := svc.RotateMPCKey(context.Background(), keyID, KeyRotateRequest{TenantID: tenantID, Actor: "alice"})
	if err != nil {
		t.Fatalf("rotate key: %v", err)
	}
	if rotated.ShareVersion <= keyAfterRefresh.ShareVersion {
		t.Fatalf("expected rotated share version > refreshed")
	}

	if pub.Count("audit.mpc.threshold_sign_initiated") == 0 ||
		pub.Count("audit.mpc.threshold_sign_completed") == 0 ||
		pub.Count("audit.mpc.threshold_decrypt_completed") == 0 {
		t.Fatalf("expected mpc audit events to be published")
	}
}
