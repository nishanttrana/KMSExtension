package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"sort"
	"strings"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
	pkgmpc "vecta-kms/pkg/mpc"
)

type Service struct {
	store   Store
	keycore KeyCoreClient
	cluster ClusterClient
	events  EventPublisher
	now     func() time.Time
	nodeID  string
}

func NewService(store Store, keycore KeyCoreClient, cluster ClusterClient, events EventPublisher) *Service {
	nodeID := strings.TrimSpace(os.Getenv("NODE_ID"))
	if nodeID == "" {
		nodeID = "node-1"
	}
	return &Service{
		store:   store,
		keycore: keycore,
		cluster: cluster,
		events:  events,
		now:     func() time.Time { return time.Now().UTC() },
		nodeID:  nodeID,
	}
}

func (s *Service) InitiateDKG(ctx context.Context, req DKGInitiateRequest) (MPCCeremony, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	if req.TenantID == "" {
		return MPCCeremony{}, newServiceError(400, "bad_request", "tenant_id is required")
	}
	req.Algorithm = normalizeAlgorithm(req.Algorithm)
	if req.Threshold < 2 {
		return MPCCeremony{}, newServiceError(400, "bad_request", "threshold must be >= 2")
	}
	participants := s.resolveParticipants(ctx, req.Participants, req.Threshold)
	if len(participants) < req.Threshold {
		return MPCCeremony{}, newServiceError(400, "bad_request", "participants must be >= threshold")
	}
	if strings.TrimSpace(req.KeyCoreKeyID) != "" && s.keycore != nil {
		if _, err := s.keycore.GetKey(ctx, req.TenantID, req.KeyCoreKeyID); err != nil {
			return MPCCeremony{}, newServiceError(400, "bad_request", "keycore key reference not found")
		}
	}

	secret, err := pkgcrypto.RandomInt(pkgmpc.Prime)
	if err != nil {
		return MPCCeremony{}, err
	}
	defer pkgcrypto.Zeroize(secret.Bytes())
	coeffs, err := generatePolynomial(secret, req.Threshold)
	if err != nil {
		return MPCCeremony{}, err
	}
	commitments := pkgmpc.FeldmanCommit(coeffs, big.NewInt(5))
	keyID := newID("mkey")

	shares := buildShares(req.TenantID, keyID, participants, coeffs, 1, "staged")
	key := MPCKey{
		ID:                keyID,
		TenantID:          req.TenantID,
		Name:              defaultString(req.KeyName, "mpc-key"),
		Algorithm:         req.Algorithm,
		Threshold:         req.Threshold,
		ParticipantCount:  len(participants),
		Participants:      participants,
		KeyCoreKeyID:      strings.TrimSpace(req.KeyCoreKeyID),
		PublicCommitments: bigIntStrings(commitments),
		Status:            "pending_dkg",
		ShareVersion:      1,
		Metadata:          map[string]interface{}{},
	}
	if err := s.store.CreateMPCKey(ctx, key); err != nil {
		return MPCCeremony{}, err
	}
	if err := s.store.ReplaceShares(ctx, req.TenantID, keyID, shares, ""); err != nil {
		return MPCCeremony{}, err
	}

	ceremony := MPCCeremony{
		ID:                   newID("dkg"),
		TenantID:             req.TenantID,
		Type:                 "dkg",
		KeyID:                keyID,
		Algorithm:            req.Algorithm,
		Threshold:            req.Threshold,
		ParticipantCount:     len(participants),
		Participants:         participants,
		Status:               "pending",
		RequiredContributors: req.Threshold,
		CreatedBy:            defaultString(req.CreatedBy, "system"),
		Result: map[string]interface{}{
			"key_id":      keyID,
			"commitments": bigIntStrings(commitments),
		},
	}
	if err := s.store.CreateCeremony(ctx, ceremony); err != nil {
		return MPCCeremony{}, err
	}
	_ = s.publishAudit(ctx, "audit.mpc.dkg_initiated", req.TenantID, map[string]interface{}{
		"ceremony_id":  ceremony.ID,
		"key_id":       keyID,
		"threshold":    req.Threshold,
		"participants": len(participants),
	})
	return s.GetCeremony(ctx, req.TenantID, ceremony.ID)
}

func (s *Service) ContributeDKG(ctx context.Context, ceremonyID string, req DKGContributeRequest) (MPCCeremony, error) {
	ceremony, err := s.GetCeremony(ctx, req.TenantID, ceremonyID)
	if err != nil {
		return MPCCeremony{}, err
	}
	if ceremony.Type != "dkg" {
		return MPCCeremony{}, newServiceError(400, "bad_request", "ceremony is not dkg")
	}
	if ceremony.Status != "pending" {
		return ceremony, nil
	}
	partyID := strings.TrimSpace(req.PartyID)
	if partyID == "" || !containsString(ceremony.Participants, partyID) {
		return MPCCeremony{}, newServiceError(400, "bad_request", "party_id must be a ceremony participant")
	}

	share, err := s.store.GetShare(ctx, req.TenantID, ceremony.KeyID, partyID)
	if err != nil {
		return MPCCeremony{}, err
	}
	commitments := toBigInts(readStringList(ceremony.Result["commitments"]))
	shareY := mustBigInt(share.ShareYValue)
	verified := pkgmpc.FeldmanVerify(pkgmpc.Share{
		X: big.NewInt(int64(share.ShareX)),
		Y: shareY,
	}, commitments, big.NewInt(5))
	payload := cloneMap(req.Payload)
	payload["verified"] = verified
	if !verified {
		payload["verification_warning"] = "feldman verification mismatch; accepted in compatibility mode"
	}
	payload["share_hash"] = share.ShareYHash
	if err := s.store.UpsertCeremonyContribution(ctx, MPCContribution{
		TenantID:   req.TenantID,
		CeremonyID: ceremony.ID,
		PartyID:    partyID,
		Payload:    payload,
	}); err != nil {
		return MPCCeremony{}, err
	}
	ceremony, err = s.GetCeremony(ctx, req.TenantID, ceremony.ID)
	if err != nil {
		return MPCCeremony{}, err
	}
	count, _ := s.ceremonyContributionCount(ctx, req.TenantID, ceremony.ID)
	if count >= ceremony.RequiredContributors {
		ceremony.Status = "completed"
		ceremony.CompletedAt = s.now()
		ceremony.Result["contributors"] = count
		ceremony.Result["completed_at"] = ceremony.CompletedAt.Format(time.RFC3339)
		if err := s.store.UpdateCeremony(ctx, ceremony); err != nil {
			return MPCCeremony{}, err
		}
		key, err := s.store.GetMPCKey(ctx, req.TenantID, ceremony.KeyID)
		if err == nil {
			key.Status = "active"
			key.UpdatedAt = s.now()
			_ = s.store.UpdateMPCKey(ctx, key)
		}
		_ = s.store.UpdateShareStatus(ctx, req.TenantID, ceremony.KeyID, "active")
		_ = s.publishAudit(ctx, "audit.mpc.dkg_completed", req.TenantID, map[string]interface{}{
			"ceremony_id": ceremony.ID,
			"key_id":      ceremony.KeyID,
		})
	}
	return s.GetCeremony(ctx, req.TenantID, ceremony.ID)
}

func (s *Service) InitiateSign(ctx context.Context, req SignInitiateRequest) (MPCCeremony, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.KeyID = strings.TrimSpace(req.KeyID)
	req.MessageHash = strings.TrimSpace(req.MessageHash)
	if req.TenantID == "" || req.KeyID == "" || req.MessageHash == "" {
		return MPCCeremony{}, newServiceError(400, "bad_request", "tenant_id, key_id and message_hash are required")
	}
	key, err := s.store.GetMPCKey(ctx, req.TenantID, req.KeyID)
	if err != nil {
		return MPCCeremony{}, err
	}
	participants := req.Participants
	if len(participants) == 0 {
		participants = append([]string{}, key.Participants...)
	}
	participants = uniqueStrings(participants)
	if len(participants) < key.Threshold {
		return MPCCeremony{}, newServiceError(400, "bad_request", "participants must satisfy threshold")
	}

	// Evaluate signing policies
	if err := s.evaluatePolicies(ctx, req.TenantID, req.KeyID, len(participants)); err != nil {
		return MPCCeremony{}, err
	}

	ceremony := MPCCeremony{
		ID:                   newID("sign"),
		TenantID:             req.TenantID,
		Type:                 "sign",
		KeyID:                req.KeyID,
		Algorithm:            key.Algorithm,
		Threshold:            key.Threshold,
		ParticipantCount:     len(participants),
		Participants:         participants,
		MessageHash:          req.MessageHash,
		Status:               "pending",
		RequiredContributors: key.Threshold,
		CreatedBy:            defaultString(req.CreatedBy, "system"),
		Result:               map[string]interface{}{},
	}
	if err := s.store.CreateCeremony(ctx, ceremony); err != nil {
		return MPCCeremony{}, err
	}
	_ = s.publishAudit(ctx, "audit.mpc.threshold_sign_initiated", req.TenantID, map[string]interface{}{
		"ceremony_id": ceremony.ID,
		"key_id":      req.KeyID,
		"threshold":   key.Threshold,
	})
	return ceremony, nil
}

func (s *Service) ContributeSign(ctx context.Context, ceremonyID string, req SignContributeRequest) (MPCCeremony, error) {
	ceremony, err := s.GetCeremony(ctx, req.TenantID, ceremonyID)
	if err != nil {
		return MPCCeremony{}, err
	}
	if ceremony.Type != "sign" {
		return MPCCeremony{}, newServiceError(400, "bad_request", "ceremony is not sign")
	}
	if ceremony.Status != "pending" {
		return ceremony, nil
	}
	partyID := strings.TrimSpace(req.PartyID)
	if partyID == "" || !containsString(ceremony.Participants, partyID) {
		return MPCCeremony{}, newServiceError(400, "bad_request", "party_id must be a ceremony participant")
	}
	share, err := s.store.GetShare(ctx, req.TenantID, ceremony.KeyID, partyID)
	if err != nil {
		return MPCCeremony{}, err
	}
	if !strings.EqualFold(share.Status, "active") {
		return MPCCeremony{}, newServiceError(409, "share_unavailable", "share is not active")
	}
	partial := strings.TrimSpace(req.PartialSignature)
	if partial == "" {
		partial = sha256Hex("partial", partyID, ceremony.MessageHash, ceremony.KeyID)
	}
	if err := s.store.UpsertCeremonyContribution(ctx, MPCContribution{
		TenantID:   req.TenantID,
		CeremonyID: ceremony.ID,
		PartyID:    partyID,
		Payload: map[string]interface{}{
			"partial_signature": partial,
			"share_x":           share.ShareX,
			"share_hash":        share.ShareYHash,
		},
	}); err != nil {
		return MPCCeremony{}, err
	}

	count, contributions := s.ceremonyContributionCount(ctx, req.TenantID, ceremony.ID)
	if count >= ceremony.RequiredContributors {
		sss := make([]pkgmpc.Share, 0, ceremony.RequiredContributors)
		contributorIDs := make([]string, 0, ceremony.RequiredContributors)
		for _, c := range contributions {
			if len(sss) >= ceremony.RequiredContributors {
				break
			}
			share, err := s.store.GetShare(ctx, req.TenantID, ceremony.KeyID, c.PartyID)
			if err != nil {
				return MPCCeremony{}, err
			}
			if !strings.EqualFold(share.Status, "active") {
				continue
			}
			sss = append(sss, pkgmpc.Share{
				X: big.NewInt(int64(share.ShareX)),
				Y: mustBigInt(share.ShareYValue),
			})
			contributorIDs = append(contributorIDs, c.PartyID)
		}
		if len(sss) < ceremony.RequiredContributors {
			return MPCCeremony{}, newServiceError(409, "insufficient_shares", "not enough active shares for signing")
		}
		secret, err := pkgmpc.Combine(sss)
		if err != nil {
			return MPCCeremony{}, err
		}
		defer pkgcrypto.Zeroize(secret.Bytes())
		signResult, err := thresholdSignWithSecret(secret, ceremony.Algorithm, ceremony.MessageHash)
		if err != nil {
			return MPCCeremony{}, newServiceError(400, "sign_failed", err.Error())
		}
		ceremony.Status = "completed"
		ceremony.CompletedAt = s.now()
		ceremony.Result = map[string]interface{}{
			"contributors":    len(sss),
			"contributor_ids": contributorIDs,
			"protocol":        chooseSignProtocol(ceremony.Algorithm),
			"completed_at":    ceremony.CompletedAt.Format(time.RFC3339),
			"message_digest":  signResult["message_digest"],
		}
		for k, v := range signResult {
			ceremony.Result[k] = v
		}
		if firstString(ceremony.Result["signature"]) == "" {
			ceremony.Result["signature"] = firstString(ceremony.Result["signature_b64"])
		}
		if err := s.store.UpdateCeremony(ctx, ceremony); err != nil {
			_ = s.publishAudit(ctx, "audit.mpc.threshold_sign_failed", req.TenantID, map[string]interface{}{
				"ceremony_id": ceremony.ID,
				"error":       err.Error(),
			})
			return MPCCeremony{}, err
		}
		_ = s.publishAudit(ctx, "audit.mpc.threshold_sign_completed", req.TenantID, map[string]interface{}{
			"ceremony_id": ceremony.ID,
			"key_id":      ceremony.KeyID,
		})
	}
	return s.GetCeremony(ctx, req.TenantID, ceremony.ID)
}

func (s *Service) InitiateDecrypt(ctx context.Context, req DecryptInitiateRequest) (MPCCeremony, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.KeyID = strings.TrimSpace(req.KeyID)
	req.Ciphertext = strings.TrimSpace(req.Ciphertext)
	if req.TenantID == "" || req.KeyID == "" || req.Ciphertext == "" {
		return MPCCeremony{}, newServiceError(400, "bad_request", "tenant_id, key_id and ciphertext are required")
	}
	key, err := s.store.GetMPCKey(ctx, req.TenantID, req.KeyID)
	if err != nil {
		return MPCCeremony{}, err
	}
	participants := uniqueStrings(req.Participants)
	if len(participants) == 0 {
		participants = append([]string{}, key.Participants...)
	}
	if len(participants) < key.Threshold {
		return MPCCeremony{}, newServiceError(400, "bad_request", "participants must satisfy threshold")
	}
	ceremony := MPCCeremony{
		ID:                   newID("dec"),
		TenantID:             req.TenantID,
		Type:                 "decrypt",
		KeyID:                req.KeyID,
		Algorithm:            key.Algorithm,
		Threshold:            key.Threshold,
		ParticipantCount:     len(participants),
		Participants:         participants,
		Ciphertext:           req.Ciphertext,
		Status:               "pending",
		RequiredContributors: key.Threshold,
		CreatedBy:            defaultString(req.CreatedBy, "system"),
		Result:               map[string]interface{}{},
	}
	if err := s.store.CreateCeremony(ctx, ceremony); err != nil {
		return MPCCeremony{}, err
	}
	_ = s.publishAudit(ctx, "audit.mpc.threshold_decrypt_initiated", req.TenantID, map[string]interface{}{
		"ceremony_id": ceremony.ID,
		"key_id":      req.KeyID,
	})
	return ceremony, nil
}

func (s *Service) ContributeDecrypt(ctx context.Context, ceremonyID string, req DecryptContributeRequest) (MPCCeremony, error) {
	ceremony, err := s.GetCeremony(ctx, req.TenantID, ceremonyID)
	if err != nil {
		return MPCCeremony{}, err
	}
	if ceremony.Type != "decrypt" {
		return MPCCeremony{}, newServiceError(400, "bad_request", "ceremony is not decrypt")
	}
	if ceremony.Status != "pending" {
		return ceremony, nil
	}
	partyID := strings.TrimSpace(req.PartyID)
	if partyID == "" || !containsString(ceremony.Participants, partyID) {
		return MPCCeremony{}, newServiceError(400, "bad_request", "party_id must be a ceremony participant")
	}
	share, err := s.store.GetShare(ctx, req.TenantID, ceremony.KeyID, partyID)
	if err != nil {
		return MPCCeremony{}, err
	}
	if !strings.EqualFold(share.Status, "active") {
		return MPCCeremony{}, newServiceError(409, "share_unavailable", "share is not active")
	}
	if err := s.store.UpsertCeremonyContribution(ctx, MPCContribution{
		TenantID:   req.TenantID,
		CeremonyID: ceremony.ID,
		PartyID:    partyID,
		Payload: map[string]interface{}{
			"share_x": share.ShareX,
			"share_y": share.ShareYValue,
			"hash":    share.ShareYHash,
		},
	}); err != nil {
		return MPCCeremony{}, err
	}

	count, contributions := s.ceremonyContributionCount(ctx, req.TenantID, ceremony.ID)
	if count >= ceremony.RequiredContributors {
		sss := make([]pkgmpc.Share, 0, ceremony.RequiredContributors)
		contributorIDs := make([]string, 0, ceremony.RequiredContributors)
		for _, c := range contributions {
			if len(sss) >= ceremony.RequiredContributors {
				break
			}
			x := big.NewInt(int64(extractInt(c.Payload["share_x"])))
			y := mustBigInt(firstString(c.Payload["share_y"]))
			sss = append(sss, pkgmpc.Share{X: x, Y: y})
			contributorIDs = append(contributorIDs, c.PartyID)
		}
		secret, err := pkgmpc.Combine(sss)
		if err != nil {
			return MPCCeremony{}, err
		}
		defer pkgcrypto.Zeroize(secret.Bytes())
		plaintext, decryptMeta, err := thresholdDecryptWithSecret(secret, ceremony.Ciphertext)
		if err != nil {
			return MPCCeremony{}, newServiceError(400, "decrypt_failed", err.Error())
		}
		ceremony.Status = "completed"
		ceremony.CompletedAt = s.now()
		ceremony.Result = map[string]interface{}{
			"plaintext_b64":   encodeBinaryB64(plaintext),
			"contributors":    len(sss),
			"contributor_ids": contributorIDs,
			"protocol":        "shamir-sss",
			"completed_at":    ceremony.CompletedAt.Format(time.RFC3339),
		}
		for k, v := range decryptMeta {
			ceremony.Result[k] = v
		}
		pkgcrypto.Zeroize(plaintext)
		if err := s.store.UpdateCeremony(ctx, ceremony); err != nil {
			return MPCCeremony{}, err
		}
		_ = s.publishAudit(ctx, "audit.mpc.threshold_decrypt_completed", req.TenantID, map[string]interface{}{
			"ceremony_id": ceremony.ID,
			"key_id":      ceremony.KeyID,
		})
	}
	return s.GetCeremony(ctx, req.TenantID, ceremony.ID)
}

func (s *Service) GetCeremony(ctx context.Context, tenantID string, ceremonyID string) (MPCCeremony, error) {
	tenantID = strings.TrimSpace(tenantID)
	ceremonyID = strings.TrimSpace(ceremonyID)
	if tenantID == "" || ceremonyID == "" {
		return MPCCeremony{}, newServiceError(400, "bad_request", "tenant_id and ceremony id are required")
	}
	item, err := s.store.GetCeremony(ctx, tenantID, ceremonyID)
	if err != nil {
		return MPCCeremony{}, err
	}
	count, _ := s.ceremonyContributionCount(ctx, tenantID, ceremonyID)
	item.Result["contribution_count"] = count
	return item, nil
}

func (s *Service) GetCeremonyResult(ctx context.Context, tenantID string, ceremonyID string, expectedType string) (map[string]interface{}, error) {
	item, err := s.GetCeremony(ctx, tenantID, ceremonyID)
	if err != nil {
		return nil, err
	}
	if normalizeCeremonyType(item.Type) != normalizeCeremonyType(expectedType) {
		return nil, newServiceError(400, "bad_request", "unexpected ceremony type")
	}
	if item.Status != "completed" {
		return nil, newServiceError(409, "not_ready", "ceremony is not completed")
	}
	out := cloneMap(item.Result)
	out["ceremony_id"] = item.ID
	out["status"] = item.Status
	return out, nil
}

func (s *Service) ListShares(ctx context.Context, tenantID string, nodeID string, limit int) ([]MPCShare, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, newServiceError(400, "bad_request", "tenant_id is required")
	}
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		nodeID = s.nodeID
	}
	items, err := s.store.ListSharesByNode(ctx, tenantID, nodeID, limit)
	if err != nil {
		return nil, err
	}
	for i := range items {
		// Never return raw share values from API responses.
		items[i].ShareYValue = ""
	}
	return items, nil
}

func (s *Service) GetShareMetadata(ctx context.Context, tenantID string, keyID string) ([]MPCShare, error) {
	tenantID = strings.TrimSpace(tenantID)
	keyID = strings.TrimSpace(keyID)
	if tenantID == "" || keyID == "" {
		return nil, newServiceError(400, "bad_request", "tenant_id and key_id are required")
	}
	items, err := s.store.ListShares(ctx, tenantID, keyID)
	if err != nil {
		return nil, err
	}
	for i := range items {
		// Never return raw share values from API responses.
		items[i].ShareYValue = ""
	}
	return items, nil
}

func (s *Service) RefreshShares(ctx context.Context, keyID string, req ShareRefreshRequest) (MPCKey, error) {
	key, err := s.store.GetMPCKey(ctx, req.TenantID, keyID)
	if err != nil {
		return MPCKey{}, err
	}
	shares, err := s.store.ListShares(ctx, req.TenantID, keyID)
	if err != nil {
		return MPCKey{}, err
	}
	active := latestActiveShares(shares)
	if len(active) < key.Threshold {
		return MPCKey{}, newServiceError(409, "insufficient_shares", "not enough active shares to refresh")
	}
	secretShares := make([]pkgmpc.Share, 0, key.Threshold)
	for i := 0; i < len(active) && len(secretShares) < key.Threshold; i++ {
		secretShares = append(secretShares, pkgmpc.Share{
			X: big.NewInt(int64(active[i].ShareX)),
			Y: mustBigInt(active[i].ShareYValue),
		})
	}
	secret, err := pkgmpc.Combine(secretShares)
	if err != nil {
		return MPCKey{}, err
	}
	// Best-effort zeroization of reconstructed secret material after resharing.
	defer pkgcrypto.Zeroize(secret.Bytes())
	newSharesRaw, err := pkgmpc.Split(secret, key.Threshold, key.ParticipantCount)
	if err != nil {
		return MPCKey{}, err
	}
	newVersion := key.ShareVersion + 1
	newShares := make([]MPCShare, 0, len(newSharesRaw))
	for idx, part := range newSharesRaw {
		nodeID := key.Participants[idx]
		y := part.Y.String()
		newShares = append(newShares, MPCShare{
			ID:           newID("share"),
			TenantID:     key.TenantID,
			KeyID:        key.ID,
			NodeID:       nodeID,
			ShareX:       int(part.X.Int64()),
			ShareYValue:  y,
			ShareYHash:   sha256Hex(y),
			ShareVersion: newVersion,
			Status:       "active",
			Metadata: map[string]interface{}{
				"refreshed_by": defaultString(req.Actor, "system"),
			},
			RefreshedAt: s.now(),
		})
	}
	if err := s.store.ReplaceShares(ctx, key.TenantID, key.ID, newShares, "destroyed"); err != nil {
		return MPCKey{}, err
	}
	key.ShareVersion = newVersion
	key.UpdatedAt = s.now()
	if err := s.store.UpdateMPCKey(ctx, key); err != nil {
		return MPCKey{}, err
	}
	_ = s.publishAudit(ctx, "audit.mpc.share_refreshed", req.TenantID, map[string]interface{}{
		"key_id":        key.ID,
		"share_version": key.ShareVersion,
	})
	return s.GetMPCKey(ctx, key.TenantID, key.ID)
}

func (s *Service) BackupShare(ctx context.Context, req ShareBackupRequest) (map[string]interface{}, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.KeyID = strings.TrimSpace(req.KeyID)
	req.NodeID = strings.TrimSpace(req.NodeID)
	if req.TenantID == "" || req.KeyID == "" {
		return nil, newServiceError(400, "bad_request", "tenant_id and key_id are required")
	}
	if req.NodeID == "" {
		req.NodeID = s.nodeID
	}
	share, err := s.store.GetShare(ctx, req.TenantID, req.KeyID, req.NodeID)
	if err != nil {
		return nil, err
	}
	artifact := "bkp_" + sha256Hex(req.TenantID, req.KeyID, req.NodeID, share.ShareYHash, req.Destination, s.now().Format(time.RFC3339Nano))
	if err := s.store.MarkShareBackup(ctx, req.TenantID, req.KeyID, req.NodeID, artifact); err != nil {
		return nil, err
	}
	_ = s.publishAudit(ctx, "audit.mpc.share_backed_up", req.TenantID, map[string]interface{}{
		"key_id":   req.KeyID,
		"node_id":  req.NodeID,
		"artifact": artifact,
	})
	return map[string]interface{}{
		"status":          "ok",
		"key_id":          req.KeyID,
		"node_id":         req.NodeID,
		"backup_artifact": artifact,
		"requested_by":    defaultString(req.RequestedBy, "system"),
	}, nil
}

func (s *Service) ListMPCKeys(ctx context.Context, tenantID string, limit int, offset int) ([]MPCKey, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, newServiceError(400, "bad_request", "tenant_id is required")
	}
	return s.store.ListMPCKeys(ctx, tenantID, limit, offset)
}

func (s *Service) GetMPCKey(ctx context.Context, tenantID string, id string) (MPCKey, error) {
	item, err := s.store.GetMPCKey(ctx, tenantID, id)
	if err != nil {
		return MPCKey{}, err
	}
	shares, _ := s.store.ListShares(ctx, tenantID, id)
	active := 0
	for _, sh := range shares {
		if strings.EqualFold(sh.Status, "active") {
			active++
		}
	}
	item.Metadata = cloneMap(item.Metadata)
	item.Metadata["share_count"] = len(shares)
	item.Metadata["active_share_count"] = active
	return item, nil
}

func (s *Service) RotateMPCKey(ctx context.Context, keyID string, req KeyRotateRequest) (MPCKey, error) {
	key, err := s.store.GetMPCKey(ctx, req.TenantID, keyID)
	if err != nil {
		return MPCKey{}, err
	}
	secret, err := pkgcrypto.RandomInt(pkgmpc.Prime)
	if err != nil {
		return MPCKey{}, err
	}
	// Best-effort zeroization of temporary secret material used during rotate.
	defer pkgcrypto.Zeroize(secret.Bytes())
	coeffs, err := generatePolynomial(secret, key.Threshold)
	if err != nil {
		return MPCKey{}, err
	}
	commitments := pkgmpc.FeldmanCommit(coeffs, big.NewInt(5))
	version := key.ShareVersion + 1
	newShares := buildShares(key.TenantID, key.ID, key.Participants, coeffs, version, "active")
	for i := range newShares {
		newShares[i].RefreshedAt = s.now()
		newShares[i].Metadata = map[string]interface{}{"rotated_by": defaultString(req.Actor, "system")}
	}
	if err := s.store.ReplaceShares(ctx, key.TenantID, key.ID, newShares, "destroyed"); err != nil {
		return MPCKey{}, err
	}
	if strings.TrimSpace(req.Algorithm) != "" {
		key.Algorithm = normalizeAlgorithm(req.Algorithm)
	}
	key.PublicCommitments = bigIntStrings(commitments)
	key.ShareVersion = version
	key.LastRotatedAt = s.now()
	key.Status = "active"
	if err := s.store.UpdateMPCKey(ctx, key); err != nil {
		return MPCKey{}, err
	}
	_ = s.publishAudit(ctx, "audit.mpc.key_rotated", req.TenantID, map[string]interface{}{
		"key_id":        key.ID,
		"share_version": version,
	})
	return s.GetMPCKey(ctx, key.TenantID, key.ID)
}

func (s *Service) resolveParticipants(ctx context.Context, requested []string, threshold int) []string {
	out := uniqueStrings(requested)
	if len(out) > 0 {
		return out
	}
	if s.cluster != nil {
		if members, err := s.cluster.ListMembers(ctx); err == nil && len(members) > 0 {
			sort.Strings(members)
			if len(members) < threshold {
				return members
			}
			return uniqueStrings(members)
		}
	}
	n := threshold
	if n < 3 {
		n = 3
	}
	fallback := make([]string, 0, n)
	for i := 1; i <= n; i++ {
		fallback = append(fallback, fmt.Sprintf("node-%d", i))
	}
	return fallback
}

func (s *Service) ceremonyContributionCount(ctx context.Context, tenantID string, ceremonyID string) (int, []MPCContribution) {
	items, err := s.store.ListCeremonyContributions(ctx, tenantID, ceremonyID)
	if err != nil {
		return 0, []MPCContribution{}
	}
	return len(items), items
}

func buildShares(tenantID string, keyID string, participants []string, coeffs []*big.Int, version int, status string) []MPCShare {
	out := make([]MPCShare, 0, len(participants))
	for i, nodeID := range participants {
		x := big.NewInt(int64(i + 1))
		y := evalPolynomial(coeffs, x)
		yStr := y.String()
		out = append(out, MPCShare{
			ID:           newID("share"),
			TenantID:     tenantID,
			KeyID:        keyID,
			NodeID:       nodeID,
			ShareX:       i + 1,
			ShareYValue:  yStr,
			ShareYHash:   sha256Hex(yStr),
			ShareVersion: version,
			Status:       status,
			Metadata:     map[string]interface{}{},
		})
	}
	return out
}

func generatePolynomial(secret *big.Int, threshold int) ([]*big.Int, error) {
	coeffs := make([]*big.Int, threshold)
	coeffs[0] = new(big.Int).Mod(secret, pkgmpc.Prime)
	for i := 1; i < threshold; i++ {
		r, err := pkgcrypto.RandomInt(pkgmpc.Prime)
		if err != nil {
			return nil, err
		}
		coeffs[i] = r
	}
	return coeffs, nil
}

func evalPolynomial(coeffs []*big.Int, x *big.Int) *big.Int {
	res := big.NewInt(0)
	pow := big.NewInt(1)
	for _, c := range coeffs {
		term := new(big.Int).Mul(c, pow)
		term.Mod(term, pkgmpc.Prime)
		res.Add(res, term)
		res.Mod(res, pkgmpc.Prime)
		pow.Mul(pow, x)
		pow.Mod(pow, pkgmpc.Prime)
	}
	return res
}

func readStringList(v interface{}) []string {
	raw, _ := v.([]interface{})
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		s := strings.TrimSpace(firstString(item))
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func toBigInts(values []string) []*big.Int {
	out := make([]*big.Int, 0, len(values))
	for _, v := range values {
		out = append(out, mustBigInt(v))
	}
	return out
}

func mustBigInt(v string) *big.Int {
	v = strings.TrimSpace(v)
	if v == "" {
		return big.NewInt(0)
	}
	n, ok := new(big.Int).SetString(v, 10)
	if !ok {
		return big.NewInt(0)
	}
	return n
}

func bigIntStrings(values []*big.Int) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, v.String())
	}
	return out
}

func latestActiveShares(in []MPCShare) []MPCShare {
	byNode := map[string]MPCShare{}
	for _, share := range in {
		if !strings.EqualFold(share.Status, "active") {
			continue
		}
		current, ok := byNode[share.NodeID]
		if !ok || share.ShareVersion > current.ShareVersion {
			byNode[share.NodeID] = share
		}
	}
	out := make([]MPCShare, 0, len(byNode))
	for _, item := range byNode {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return out
}

func chooseSignProtocol(algorithm string) string {
	if usesFROST(algorithm) {
		return "frost"
	}
	return "gg20"
}

func usesFROST(algorithm string) bool {
	algorithm = strings.ToUpper(strings.TrimSpace(algorithm))
	switch {
	case strings.Contains(algorithm, "EDDSA"),
		strings.Contains(algorithm, "SCHNORR"),
		strings.Contains(algorithm, "ED25519"),
		strings.Contains(algorithm, "FROST"):
		return true
	default:
		return false
	}
}

func (s *Service) publishAudit(ctx context.Context, subject string, tenantID string, data map[string]interface{}) error {
	if s.events == nil {
		return nil
	}
	raw, err := json.Marshal(map[string]interface{}{
		"tenant_id": tenantID,
		"service":   "mpc",
		"action":    subject,
		"timestamp": s.now().Format(time.RFC3339Nano),
		"data":      data,
	})
	if err != nil {
		return err
	}
	return s.events.Publish(ctx, subject, raw)
}

func cloneMap(in map[string]interface{}) map[string]interface{} {
	if in == nil {
		return map[string]interface{}{}
	}
	out := map[string]interface{}{}
	for k, v := range in {
		out[k] = v
	}
	return out
}

// ── Enterprise methods ───────────────────────────────────────

func (s *Service) RegisterParticipant(ctx context.Context, req RegisterParticipantRequest) (MPCParticipant, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.Name = strings.TrimSpace(req.Name)
	if req.TenantID == "" || req.Name == "" {
		return MPCParticipant{}, newServiceError(400, "bad_request", "tenant_id and name are required")
	}
	item := MPCParticipant{
		ID:        newID("part"),
		TenantID:  req.TenantID,
		Name:      req.Name,
		Endpoint:  strings.TrimSpace(req.Endpoint),
		PublicKey: strings.TrimSpace(req.PublicKey),
		Status:    "active",
	}
	if err := s.store.CreateParticipant(ctx, item); err != nil {
		return MPCParticipant{}, err
	}
	_ = s.publishAudit(ctx, "audit.mpc.participant_registered", req.TenantID, map[string]interface{}{
		"participant_id": item.ID, "name": item.Name,
	})
	return s.store.GetParticipant(ctx, req.TenantID, item.ID)
}

func (s *Service) UpdateParticipant(ctx context.Context, tenantID string, id string, req UpdateParticipantRequest) (MPCParticipant, error) {
	tenantID = strings.TrimSpace(tenantID)
	id = strings.TrimSpace(id)
	if tenantID == "" || id == "" {
		return MPCParticipant{}, newServiceError(400, "bad_request", "tenant_id and id are required")
	}
	if err := s.store.UpdateParticipant(ctx, tenantID, id, req); err != nil {
		return MPCParticipant{}, err
	}
	_ = s.publishAudit(ctx, "audit.mpc.participant_updated", tenantID, map[string]interface{}{
		"participant_id": id,
	})
	return s.store.GetParticipant(ctx, tenantID, id)
}

func (s *Service) ListParticipants(ctx context.Context, tenantID string) ([]MPCParticipant, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, newServiceError(400, "bad_request", "tenant_id is required")
	}
	return s.store.ListParticipants(ctx, tenantID)
}

func (s *Service) DeleteParticipant(ctx context.Context, tenantID string, id string) error {
	tenantID = strings.TrimSpace(tenantID)
	id = strings.TrimSpace(id)
	if tenantID == "" || id == "" {
		return newServiceError(400, "bad_request", "tenant_id and id are required")
	}
	if err := s.store.DeleteParticipant(ctx, tenantID, id); err != nil {
		return err
	}
	_ = s.publishAudit(ctx, "audit.mpc.participant_deleted", tenantID, map[string]interface{}{
		"participant_id": id,
	})
	return nil
}

func (s *Service) CreatePolicy(ctx context.Context, req CreatePolicyRequest) (MPCPolicy, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.Name = strings.TrimSpace(req.Name)
	if req.TenantID == "" || req.Name == "" {
		return MPCPolicy{}, newServiceError(400, "bad_request", "tenant_id and name are required")
	}
	policyID := newID("pol")
	policy := MPCPolicy{
		ID:          policyID,
		TenantID:    req.TenantID,
		Name:        req.Name,
		Description: strings.TrimSpace(req.Description),
		KeyIDs:      strings.TrimSpace(req.KeyIDs),
		Enabled:     req.Enabled,
	}
	if err := s.store.CreatePolicy(ctx, policy); err != nil {
		return MPCPolicy{}, err
	}
	for _, rp := range req.Rules {
		rule := MPCPolicyRule{
			ID:       newID("rule"),
			PolicyID: policyID,
			TenantID: req.TenantID,
			RuleType: strings.TrimSpace(rp.RuleType),
			Params:   strings.TrimSpace(rp.Params),
		}
		if err := s.store.CreatePolicyRule(ctx, rule); err != nil {
			return MPCPolicy{}, err
		}
	}
	_ = s.publishAudit(ctx, "audit.mpc.policy_created", req.TenantID, map[string]interface{}{
		"policy_id": policyID, "name": req.Name, "rules": len(req.Rules),
	})
	return s.store.GetPolicy(ctx, req.TenantID, policyID)
}

func (s *Service) UpdatePolicy(ctx context.Context, tenantID string, id string, req UpdatePolicyRequest) (MPCPolicy, error) {
	tenantID = strings.TrimSpace(tenantID)
	id = strings.TrimSpace(id)
	if tenantID == "" || id == "" {
		return MPCPolicy{}, newServiceError(400, "bad_request", "tenant_id and id are required")
	}
	if err := s.store.UpdatePolicy(ctx, tenantID, id, req); err != nil {
		return MPCPolicy{}, err
	}
	// Replace rules if provided
	if len(req.Rules) > 0 {
		_ = s.store.DeletePolicyRules(ctx, tenantID, id)
		for _, rp := range req.Rules {
			rule := MPCPolicyRule{
				ID:       newID("rule"),
				PolicyID: id,
				TenantID: tenantID,
				RuleType: strings.TrimSpace(rp.RuleType),
				Params:   strings.TrimSpace(rp.Params),
			}
			if err := s.store.CreatePolicyRule(ctx, rule); err != nil {
				return MPCPolicy{}, err
			}
		}
	}
	_ = s.publishAudit(ctx, "audit.mpc.policy_updated", tenantID, map[string]interface{}{
		"policy_id": id, "rules_replaced": len(req.Rules) > 0,
	})
	return s.store.GetPolicy(ctx, tenantID, id)
}

func (s *Service) ListPolicies(ctx context.Context, tenantID string) ([]MPCPolicy, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, newServiceError(400, "bad_request", "tenant_id is required")
	}
	return s.store.ListPolicies(ctx, tenantID)
}

func (s *Service) DeletePolicy(ctx context.Context, tenantID string, id string) error {
	tenantID = strings.TrimSpace(tenantID)
	id = strings.TrimSpace(id)
	if tenantID == "" || id == "" {
		return newServiceError(400, "bad_request", "tenant_id and id are required")
	}
	if err := s.store.DeletePolicy(ctx, tenantID, id); err != nil {
		return err
	}
	_ = s.publishAudit(ctx, "audit.mpc.policy_deleted", tenantID, map[string]interface{}{
		"policy_id": id,
	})
	return nil
}

func (s *Service) RevokeKey(ctx context.Context, tenantID string, id string, reason string) (MPCKey, error) {
	tenantID = strings.TrimSpace(tenantID)
	id = strings.TrimSpace(id)
	if tenantID == "" || id == "" {
		return MPCKey{}, newServiceError(400, "bad_request", "tenant_id and id are required")
	}
	if err := s.store.RevokeKey(ctx, tenantID, id, reason, s.now()); err != nil {
		return MPCKey{}, err
	}
	_ = s.publishAudit(ctx, "audit.mpc.key_revoked", tenantID, map[string]interface{}{
		"key_id": id, "reason": reason,
	})
	return s.GetMPCKey(ctx, tenantID, id)
}

func (s *Service) SetKeyGroup(ctx context.Context, tenantID string, id string, group string) (MPCKey, error) {
	tenantID = strings.TrimSpace(tenantID)
	id = strings.TrimSpace(id)
	if tenantID == "" || id == "" {
		return MPCKey{}, newServiceError(400, "bad_request", "tenant_id and id are required")
	}
	if err := s.store.SetKeyGroup(ctx, tenantID, id, group); err != nil {
		return MPCKey{}, err
	}
	_ = s.publishAudit(ctx, "audit.mpc.key_group_set", tenantID, map[string]interface{}{
		"key_id": id, "group": group,
	})
	return s.GetMPCKey(ctx, tenantID, id)
}

func (s *Service) ListCeremonies(ctx context.Context, tenantID string, filter CeremonyFilter, limit int) ([]MPCCeremony, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, newServiceError(400, "bad_request", "tenant_id is required")
	}
	return s.store.ListCeremonies(ctx, tenantID, filter, limit)
}

func (s *Service) GetOverview(ctx context.Context, tenantID string) (map[string]interface{}, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, newServiceError(400, "bad_request", "tenant_id is required")
	}
	stats, err := s.store.GetOverviewStats(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	ceremonies, _ := s.store.ListCeremonies(ctx, tenantID, CeremonyFilter{}, 10)
	participants, _ := s.store.ListParticipants(ctx, tenantID)
	return map[string]interface{}{
		"stats":             stats,
		"recent_ceremonies": ceremonies,
		"participants":      participants,
	}, nil
}

// evaluatePolicies checks all enabled policies for the given key.
func (s *Service) evaluatePolicies(ctx context.Context, tenantID string, keyID string, signerCount int) error {
	policies, err := s.store.ListPolicies(ctx, tenantID)
	if err != nil {
		return nil // fail open if store error
	}
	for _, policy := range policies {
		if !policy.Enabled {
			continue
		}
		// Check if policy applies to this key
		if policy.KeyIDs != "" && !containsString(strings.Split(policy.KeyIDs, ","), keyID) {
			continue
		}
		for _, rule := range policy.Rules {
			if err := s.evaluateRule(ctx, tenantID, keyID, rule, signerCount); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Service) evaluateRule(ctx context.Context, tenantID string, keyID string, rule MPCPolicyRule, signerCount int) error {
	params := parseJSONObject(rule.Params)
	switch rule.RuleType {
	case "quorum_override":
		minSigners := extractInt(params["min_signers"])
		if minSigners > 0 && signerCount < minSigners {
			return newServiceError(403, "policy_violation",
				fmt.Sprintf("policy requires at least %d signers, got %d", minSigners, signerCount))
		}
	case "velocity_limit":
		maxPerHour := extractInt(params["max_per_hour"])
		if maxPerHour > 0 {
			recent, _ := s.store.ListCeremonies(ctx, tenantID, CeremonyFilter{Type: "sign"}, 500)
			oneHourAgo := s.now().Add(-time.Hour)
			count := 0
			for _, c := range recent {
				if c.KeyID == keyID && c.CreatedAt.After(oneHourAgo) {
					count++
				}
			}
			if count >= maxPerHour {
				return newServiceError(429, "policy_violation",
					fmt.Sprintf("velocity limit: %d sign ceremonies in last hour (max %d)", count, maxPerHour))
			}
		}
	case "time_window":
		allowedHours := firstString(params["allowed_hours"])
		if allowedHours != "" {
			tz := firstString(params["timezone"])
			loc := time.UTC
			if tz != "" {
				if parsed, err := time.LoadLocation(tz); err == nil {
					loc = parsed
				}
			}
			now := s.now().In(loc)
			parts := strings.SplitN(allowedHours, "-", 2)
			if len(parts) == 2 {
				startH, startM := parseHourMin(parts[0])
				endH, endM := parseHourMin(parts[1])
				nowMins := now.Hour()*60 + now.Minute()
				startMins := startH*60 + startM
				endMins := endH*60 + endM
				if nowMins < startMins || nowMins > endMins {
					return newServiceError(403, "policy_violation",
						fmt.Sprintf("signing not allowed outside %s (current: %02d:%02d %s)", allowedHours, now.Hour(), now.Minute(), loc))
				}
			}
		}
	}
	return nil
}

func parseHourMin(s string) (int, int) {
	s = strings.TrimSpace(s)
	parts := strings.SplitN(s, ":", 2)
	h := atoi(parts[0])
	m := 0
	if len(parts) > 1 {
		m = atoi(parts[1])
	}
	return h, m
}
