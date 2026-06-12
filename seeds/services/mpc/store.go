package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	pkgdb "vecta-kms/pkg/db"
)

var errNotFound = errors.New("not found")

type SQLStore struct {
	db *pkgdb.DB
}

func NewSQLStore(db *pkgdb.DB) *SQLStore {
	return &SQLStore{db: db}
}

// ── Key columns (shared across queries) ──────────────────────

const mpcKeyColumns = `tenant_id, id, name, algorithm, threshold, participant_count, participants_json, keycore_key_id, public_commitments_json, status, share_version, metadata_json, key_group, expires_at, revoked_at, revocation_reason, created_at, updated_at, last_rotated_at`

func (s *SQLStore) CreateMPCKey(ctx context.Context, item MPCKey) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO mpc_keys (
	`+mpcKeyColumns+`
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,$17
)
`, item.TenantID, item.ID, item.Name, item.Algorithm, item.Threshold, item.ParticipantCount,
		mustJSON(item.Participants, "[]"), item.KeyCoreKeyID, mustJSON(item.PublicCommitments, "[]"),
		item.Status, item.ShareVersion, mustJSON(item.Metadata, "{}"),
		item.KeyGroup, nullableTime(item.ExpiresAt), nullableTime(item.RevokedAt), item.RevocationReason,
		nullableTime(item.LastRotatedAt))
	return err
}

func (s *SQLStore) UpdateMPCKey(ctx context.Context, item MPCKey) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE mpc_keys
SET name = $3,
	algorithm = $4,
	threshold = $5,
	participant_count = $6,
	participants_json = $7,
	keycore_key_id = $8,
	public_commitments_json = $9,
	status = $10,
	share_version = $11,
	metadata_json = $12,
	key_group = $13,
	expires_at = $14,
	revoked_at = $15,
	revocation_reason = $16,
	updated_at = CURRENT_TIMESTAMP,
	last_rotated_at = $17
WHERE tenant_id = $1 AND id = $2
`, item.TenantID, item.ID, item.Name, item.Algorithm, item.Threshold, item.ParticipantCount,
		mustJSON(item.Participants, "[]"), item.KeyCoreKeyID, mustJSON(item.PublicCommitments, "[]"),
		item.Status, item.ShareVersion, mustJSON(item.Metadata, "{}"),
		item.KeyGroup, nullableTime(item.ExpiresAt), nullableTime(item.RevokedAt), item.RevocationReason,
		nullableTime(item.LastRotatedAt))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) GetMPCKey(ctx context.Context, tenantID string, id string) (MPCKey, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT `+mpcKeyColumns+`
FROM mpc_keys
WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	item, err := scanMPCKey(row)
	if errors.Is(err, sql.ErrNoRows) {
		return MPCKey{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) ListMPCKeys(ctx context.Context, tenantID string, limit int, offset int) ([]MPCKey, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT `+mpcKeyColumns+`
FROM mpc_keys
WHERE tenant_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3
`, strings.TrimSpace(tenantID), limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]MPCKey, 0)
	for rows.Next() {
		item, err := scanMPCKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) RevokeKey(ctx context.Context, tenantID string, id string, reason string, revokedAt interface{}) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE mpc_keys
SET status = 'revoked', revoked_at = $3, revocation_reason = $4, updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id), revokedAt, strings.TrimSpace(reason))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) SetKeyGroup(ctx context.Context, tenantID string, id string, group string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE mpc_keys SET key_group = $3, updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id), strings.TrimSpace(group))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

// ── Shares ───────────────────────────────────────────────────

func (s *SQLStore) ReplaceShares(ctx context.Context, tenantID string, keyID string, shares []MPCShare, oldStatus string) error {
	tx, err := s.db.SQL().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	if strings.TrimSpace(oldStatus) != "" {
		if _, err := tx.ExecContext(ctx, `
UPDATE mpc_shares
SET status = $3, updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $1 AND key_id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(keyID), strings.TrimSpace(oldStatus)); err != nil {
			return err
		}
	}
	for _, share := range shares {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO mpc_shares (
	tenant_id, key_id, id, node_id, share_x, share_y_value, share_y_hash, share_version, status, metadata_json, created_at, updated_at, refreshed_at, last_backup_at, backup_artifact
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,$11,$12,$13
)
`, share.TenantID, share.KeyID, share.ID, share.NodeID, share.ShareX, share.ShareYValue, share.ShareYHash, share.ShareVersion, share.Status, mustJSON(share.Metadata, "{}"), nullableTime(share.RefreshedAt), nullableTime(share.LastBackupAt), share.BackupArtifact); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLStore) ListShares(ctx context.Context, tenantID string, keyID string) ([]MPCShare, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, key_id, id, node_id, share_x, share_y_value, share_y_hash, share_version, status, metadata_json, created_at, updated_at, refreshed_at, last_backup_at, backup_artifact
FROM mpc_shares
WHERE tenant_id = $1 AND key_id = $2
ORDER BY share_version DESC, node_id ASC
`, strings.TrimSpace(tenantID), strings.TrimSpace(keyID))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]MPCShare, 0)
	for rows.Next() {
		item, err := scanMPCShare(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) ListSharesByNode(ctx context.Context, tenantID string, nodeID string, limit int) ([]MPCShare, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, key_id, id, node_id, share_x, share_y_value, share_y_hash, share_version, status, metadata_json, created_at, updated_at, refreshed_at, last_backup_at, backup_artifact
FROM mpc_shares
WHERE tenant_id = $1 AND node_id = $2
ORDER BY updated_at DESC
LIMIT $3
`, strings.TrimSpace(tenantID), strings.TrimSpace(nodeID), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]MPCShare, 0)
	for rows.Next() {
		item, err := scanMPCShare(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetShare(ctx context.Context, tenantID string, keyID string, nodeID string) (MPCShare, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, key_id, id, node_id, share_x, share_y_value, share_y_hash, share_version, status, metadata_json, created_at, updated_at, refreshed_at, last_backup_at, backup_artifact
FROM mpc_shares
WHERE tenant_id = $1 AND key_id = $2 AND node_id = $3
ORDER BY share_version DESC
LIMIT 1
`, strings.TrimSpace(tenantID), strings.TrimSpace(keyID), strings.TrimSpace(nodeID))
	item, err := scanMPCShare(row)
	if errors.Is(err, sql.ErrNoRows) {
		return MPCShare{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) MarkShareBackup(ctx context.Context, tenantID string, keyID string, nodeID string, artifact string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE mpc_shares
SET backup_artifact = $4,
	last_backup_at = CURRENT_TIMESTAMP,
	updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $1 AND key_id = $2 AND node_id = $3 AND status = 'active'
`, strings.TrimSpace(tenantID), strings.TrimSpace(keyID), strings.TrimSpace(nodeID), strings.TrimSpace(artifact))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) UpdateShareStatus(ctx context.Context, tenantID string, keyID string, status string) error {
	_, err := s.db.SQL().ExecContext(ctx, `
UPDATE mpc_shares
SET status = $3, updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $1 AND key_id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(keyID), strings.TrimSpace(status))
	return err
}

// ── Ceremonies ───────────────────────────────────────────────

func (s *SQLStore) CreateCeremony(ctx context.Context, item MPCCeremony) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO mpc_ceremonies (
	tenant_id, id, type, key_id, algorithm, threshold, participant_count, participants_json, message_hash, ciphertext, status, result_json, created_by, required_contributors, created_at, updated_at, completed_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,$15
)
`, item.TenantID, item.ID, item.Type, item.KeyID, item.Algorithm, item.Threshold, item.ParticipantCount, mustJSON(item.Participants, "[]"), item.MessageHash, item.Ciphertext, item.Status, mustJSON(item.Result, "{}"), item.CreatedBy, item.RequiredContributors, nullableTime(item.CompletedAt))
	return err
}

func (s *SQLStore) UpdateCeremony(ctx context.Context, item MPCCeremony) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE mpc_ceremonies
SET status = $4,
	result_json = $5,
	updated_at = CURRENT_TIMESTAMP,
	completed_at = $6
WHERE tenant_id = $1 AND id = $2 AND type = $3
`, item.TenantID, item.ID, item.Type, item.Status, mustJSON(item.Result, "{}"), nullableTime(item.CompletedAt))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) GetCeremony(ctx context.Context, tenantID string, id string) (MPCCeremony, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, id, type, key_id, algorithm, threshold, participant_count, participants_json, message_hash, ciphertext, status, result_json, created_by, required_contributors, created_at, updated_at, completed_at
FROM mpc_ceremonies
WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	item, err := scanMPCCeremony(row)
	if errors.Is(err, sql.ErrNoRows) {
		return MPCCeremony{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) ListCeremonies(ctx context.Context, tenantID string, filter CeremonyFilter, limit int) ([]MPCCeremony, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	q := `SELECT tenant_id, id, type, key_id, algorithm, threshold, participant_count, participants_json, message_hash, ciphertext, status, result_json, created_by, required_contributors, created_at, updated_at, completed_at
FROM mpc_ceremonies WHERE tenant_id = $1`
	args := []interface{}{strings.TrimSpace(tenantID)}
	idx := 2
	if t := strings.TrimSpace(filter.Type); t != "" {
		q += fmt.Sprintf(` AND type = $%d`, idx)
		args = append(args, t)
		idx++
	}
	if st := strings.TrimSpace(filter.Status); st != "" {
		q += fmt.Sprintf(` AND status = $%d`, idx)
		args = append(args, st)
		idx++
	}
	q += fmt.Sprintf(` ORDER BY created_at DESC LIMIT $%d`, idx)
	args = append(args, limit)

	rows, err := s.db.SQL().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]MPCCeremony, 0)
	for rows.Next() {
		item, err := scanMPCCeremony(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) ListCeremonyContributions(ctx context.Context, tenantID string, ceremonyID string) ([]MPCContribution, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, ceremony_id, party_id, payload_json, submitted_at
FROM mpc_contributions
WHERE tenant_id = $1 AND ceremony_id = $2
ORDER BY submitted_at ASC
`, strings.TrimSpace(tenantID), strings.TrimSpace(ceremonyID))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]MPCContribution, 0)
	for rows.Next() {
		item, err := scanMPCContribution(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpsertCeremonyContribution(ctx context.Context, item MPCContribution) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO mpc_contributions (
	tenant_id, ceremony_id, party_id, payload_json, submitted_at
) VALUES (
	$1,$2,$3,$4,CURRENT_TIMESTAMP
)
ON CONFLICT (tenant_id, ceremony_id, party_id) DO UPDATE SET
	payload_json = EXCLUDED.payload_json,
	submitted_at = CURRENT_TIMESTAMP
`, item.TenantID, item.CeremonyID, item.PartyID, mustJSON(item.Payload, "{}"))
	return err
}

// ── Participants ─────────────────────────────────────────────

func (s *SQLStore) CreateParticipant(ctx context.Context, item MPCParticipant) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO mpc_participants (tenant_id, id, name, endpoint, public_key, status, last_seen_at, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)
`, item.TenantID, item.ID, item.Name, item.Endpoint, item.PublicKey, item.Status, nullableTime(item.LastSeenAt))
	return err
}

func (s *SQLStore) GetParticipant(ctx context.Context, tenantID string, id string) (MPCParticipant, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, id, name, endpoint, public_key, status, last_seen_at, created_at, updated_at
FROM mpc_participants WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	item, err := scanMPCParticipant(row)
	if errors.Is(err, sql.ErrNoRows) {
		return MPCParticipant{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) ListParticipants(ctx context.Context, tenantID string) ([]MPCParticipant, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, id, name, endpoint, public_key, status, last_seen_at, created_at, updated_at
FROM mpc_participants WHERE tenant_id = $1 ORDER BY created_at DESC
`, strings.TrimSpace(tenantID))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]MPCParticipant, 0)
	for rows.Next() {
		item, err := scanMPCParticipant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpdateParticipant(ctx context.Context, tenantID string, id string, req UpdateParticipantRequest) error {
	sets := []string{}
	args := []interface{}{strings.TrimSpace(tenantID), strings.TrimSpace(id)}
	idx := 3
	if req.Name != "" {
		sets = append(sets, fmt.Sprintf("name = $%d", idx))
		args = append(args, req.Name)
		idx++
	}
	if req.Endpoint != "" {
		sets = append(sets, fmt.Sprintf("endpoint = $%d", idx))
		args = append(args, req.Endpoint)
		idx++
	}
	if req.PublicKey != "" {
		sets = append(sets, fmt.Sprintf("public_key = $%d", idx))
		args = append(args, req.PublicKey)
		idx++
	}
	if req.Status != "" {
		sets = append(sets, fmt.Sprintf("status = $%d", idx))
		args = append(args, req.Status)
		idx++
	}
	if len(sets) == 0 {
		return nil
	}
	sets = append(sets, "updated_at = CURRENT_TIMESTAMP")
	q := fmt.Sprintf(`UPDATE mpc_participants SET %s WHERE tenant_id = $1 AND id = $2`, strings.Join(sets, ", "))
	res, err := s.db.SQL().ExecContext(ctx, q, args...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) DeleteParticipant(ctx context.Context, tenantID string, id string) error {
	res, err := s.db.SQL().ExecContext(ctx, `DELETE FROM mpc_participants WHERE tenant_id = $1 AND id = $2`,
		strings.TrimSpace(tenantID), strings.TrimSpace(id))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

// ── Policies ─────────────────────────────────────────────────

func (s *SQLStore) CreatePolicy(ctx context.Context, item MPCPolicy) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO mpc_policies (tenant_id, id, name, description, key_ids, enabled, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)
`, item.TenantID, item.ID, item.Name, item.Description, item.KeyIDs, boolToInt(item.Enabled))
	return err
}

func (s *SQLStore) GetPolicy(ctx context.Context, tenantID string, id string) (MPCPolicy, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, id, name, description, key_ids, enabled, created_at, updated_at
FROM mpc_policies WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	policy, err := scanMPCPolicy(row)
	if errors.Is(err, sql.ErrNoRows) {
		return MPCPolicy{}, errNotFound
	}
	if err != nil {
		return MPCPolicy{}, err
	}
	rules, _ := s.listPolicyRules(ctx, tenantID, id)
	policy.Rules = rules
	return policy, nil
}

func (s *SQLStore) ListPolicies(ctx context.Context, tenantID string) ([]MPCPolicy, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, id, name, description, key_ids, enabled, created_at, updated_at
FROM mpc_policies WHERE tenant_id = $1 ORDER BY created_at DESC
`, strings.TrimSpace(tenantID))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]MPCPolicy, 0)
	for rows.Next() {
		item, err := scanMPCPolicy(rows)
		if err != nil {
			return nil, err
		}
		rules, _ := s.listPolicyRules(ctx, tenantID, item.ID)
		item.Rules = rules
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpdatePolicy(ctx context.Context, tenantID string, id string, req UpdatePolicyRequest) error {
	sets := []string{}
	args := []interface{}{strings.TrimSpace(tenantID), strings.TrimSpace(id)}
	idx := 3
	if req.Name != "" {
		sets = append(sets, fmt.Sprintf("name = $%d", idx))
		args = append(args, req.Name)
		idx++
	}
	if req.Description != "" {
		sets = append(sets, fmt.Sprintf("description = $%d", idx))
		args = append(args, req.Description)
		idx++
	}
	if req.KeyIDs != "" {
		sets = append(sets, fmt.Sprintf("key_ids = $%d", idx))
		args = append(args, req.KeyIDs)
		idx++
	}
	if req.Enabled != nil {
		sets = append(sets, fmt.Sprintf("enabled = $%d", idx))
		args = append(args, boolToInt(*req.Enabled))
		idx++
	}
	if len(sets) == 0 {
		return nil
	}
	sets = append(sets, "updated_at = CURRENT_TIMESTAMP")
	q := fmt.Sprintf(`UPDATE mpc_policies SET %s WHERE tenant_id = $1 AND id = $2`, strings.Join(sets, ", "))
	res, err := s.db.SQL().ExecContext(ctx, q, args...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) DeletePolicy(ctx context.Context, tenantID string, id string) error {
	// Delete rules first, then policy
	_, _ = s.db.SQL().ExecContext(ctx, `DELETE FROM mpc_policy_rules WHERE tenant_id = $1 AND policy_id = $2`,
		strings.TrimSpace(tenantID), strings.TrimSpace(id))
	res, err := s.db.SQL().ExecContext(ctx, `DELETE FROM mpc_policies WHERE tenant_id = $1 AND id = $2`,
		strings.TrimSpace(tenantID), strings.TrimSpace(id))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) CreatePolicyRule(ctx context.Context, item MPCPolicyRule) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO mpc_policy_rules (id, policy_id, tenant_id, rule_type, params, created_at)
VALUES ($1,$2,$3,$4,$5,CURRENT_TIMESTAMP)
`, item.ID, item.PolicyID, item.TenantID, item.RuleType, item.Params)
	return err
}

func (s *SQLStore) DeletePolicyRules(ctx context.Context, tenantID string, policyID string) error {
	_, err := s.db.SQL().ExecContext(ctx, `DELETE FROM mpc_policy_rules WHERE tenant_id = $1 AND policy_id = $2`,
		strings.TrimSpace(tenantID), strings.TrimSpace(policyID))
	return err
}

func (s *SQLStore) listPolicyRules(ctx context.Context, tenantID string, policyID string) ([]MPCPolicyRule, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, policy_id, tenant_id, rule_type, params, created_at
FROM mpc_policy_rules WHERE tenant_id = $1 AND policy_id = $2 ORDER BY created_at ASC
`, strings.TrimSpace(tenantID), strings.TrimSpace(policyID))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]MPCPolicyRule, 0)
	for rows.Next() {
		var item MPCPolicyRule
		var createdRaw interface{}
		if err := rows.Scan(&item.ID, &item.PolicyID, &item.TenantID, &item.RuleType, &item.Params, &createdRaw); err != nil {
			return nil, err
		}
		item.CreatedAt = parseTimeValue(createdRaw)
		out = append(out, item)
	}
	return out, rows.Err()
}

// ── Overview stats ───────────────────────────────────────────

func (s *SQLStore) GetOverviewStats(ctx context.Context, tenantID string) (MPCOverviewStats, error) {
	tid := strings.TrimSpace(tenantID)
	var stats MPCOverviewStats

	// Keys
	_ = s.db.SQL().QueryRowContext(ctx, `SELECT COUNT(*) FROM mpc_keys WHERE tenant_id = $1`, tid).Scan(&stats.TotalKeys)
	_ = s.db.SQL().QueryRowContext(ctx, `SELECT COUNT(*) FROM mpc_keys WHERE tenant_id = $1 AND status = 'active'`, tid).Scan(&stats.ActiveKeys)
	_ = s.db.SQL().QueryRowContext(ctx, `SELECT COUNT(*) FROM mpc_keys WHERE tenant_id = $1 AND status = 'revoked'`, tid).Scan(&stats.RevokedKeys)

	// Ceremonies
	_ = s.db.SQL().QueryRowContext(ctx, `SELECT COUNT(*) FROM mpc_ceremonies WHERE tenant_id = $1`, tid).Scan(&stats.TotalCeremonies)
	_ = s.db.SQL().QueryRowContext(ctx, `SELECT COUNT(*) FROM mpc_ceremonies WHERE tenant_id = $1 AND status = 'pending'`, tid).Scan(&stats.PendingCeremonies)
	_ = s.db.SQL().QueryRowContext(ctx, `SELECT COUNT(*) FROM mpc_ceremonies WHERE tenant_id = $1 AND status = 'completed'`, tid).Scan(&stats.CompletedCeremonies)
	_ = s.db.SQL().QueryRowContext(ctx, `SELECT COUNT(*) FROM mpc_ceremonies WHERE tenant_id = $1 AND status = 'failed'`, tid).Scan(&stats.FailedCeremonies)

	// Participants
	_ = s.db.SQL().QueryRowContext(ctx, `SELECT COUNT(*) FROM mpc_participants WHERE tenant_id = $1`, tid).Scan(&stats.TotalParticipants)
	_ = s.db.SQL().QueryRowContext(ctx, `SELECT COUNT(*) FROM mpc_participants WHERE tenant_id = $1 AND status = 'active'`, tid).Scan(&stats.ActiveParticipants)

	// Policies
	_ = s.db.SQL().QueryRowContext(ctx, `SELECT COUNT(*) FROM mpc_policies WHERE tenant_id = $1 AND enabled = 1`, tid).Scan(&stats.ActivePolicies)

	return stats, nil
}

// ── Scanners ─────────────────────────────────────────────────

func scanMPCKey(scanner interface {
	Scan(dest ...interface{}) error
}) (MPCKey, error) {
	var (
		item             MPCKey
		participantsJS   string
		commitmentsJS    string
		metadataJS       string
		createdRaw       interface{}
		updatedRaw       interface{}
		lastRotatedAtRaw interface{}
		expiresAtRaw     interface{}
		revokedAtRaw     interface{}
	)
	if err := scanner.Scan(
		&item.TenantID,
		&item.ID,
		&item.Name,
		&item.Algorithm,
		&item.Threshold,
		&item.ParticipantCount,
		&participantsJS,
		&item.KeyCoreKeyID,
		&commitmentsJS,
		&item.Status,
		&item.ShareVersion,
		&metadataJS,
		&item.KeyGroup,
		&expiresAtRaw,
		&revokedAtRaw,
		&item.RevocationReason,
		&createdRaw,
		&updatedRaw,
		&lastRotatedAtRaw,
	); err != nil {
		return MPCKey{}, err
	}
	item.Participants = parseJSONArrayString(participantsJS)
	item.PublicCommitments = parseJSONArrayString(commitmentsJS)
	item.Metadata = parseJSONObject(metadataJS)
	item.ExpiresAt = parseTimeValue(expiresAtRaw)
	item.RevokedAt = parseTimeValue(revokedAtRaw)
	item.CreatedAt = parseTimeValue(createdRaw)
	item.UpdatedAt = parseTimeValue(updatedRaw)
	item.LastRotatedAt = parseTimeValue(lastRotatedAtRaw)
	return item, nil
}

func scanMPCShare(scanner interface {
	Scan(dest ...interface{}) error
}) (MPCShare, error) {
	var (
		item          MPCShare
		metadataJS    string
		createdRaw    interface{}
		updatedRaw    interface{}
		refreshedRaw  interface{}
		lastBackupRaw interface{}
	)
	if err := scanner.Scan(
		&item.TenantID,
		&item.KeyID,
		&item.ID,
		&item.NodeID,
		&item.ShareX,
		&item.ShareYValue,
		&item.ShareYHash,
		&item.ShareVersion,
		&item.Status,
		&metadataJS,
		&createdRaw,
		&updatedRaw,
		&refreshedRaw,
		&lastBackupRaw,
		&item.BackupArtifact,
	); err != nil {
		return MPCShare{}, err
	}
	item.Metadata = parseJSONObject(metadataJS)
	item.CreatedAt = parseTimeValue(createdRaw)
	item.UpdatedAt = parseTimeValue(updatedRaw)
	item.RefreshedAt = parseTimeValue(refreshedRaw)
	item.LastBackupAt = parseTimeValue(lastBackupRaw)
	return item, nil
}

func scanMPCCeremony(scanner interface {
	Scan(dest ...interface{}) error
}) (MPCCeremony, error) {
	var (
		item           MPCCeremony
		participantsJS string
		resultJS       string
		createdRaw     interface{}
		updatedRaw     interface{}
		completedAtRaw interface{}
	)
	if err := scanner.Scan(
		&item.TenantID,
		&item.ID,
		&item.Type,
		&item.KeyID,
		&item.Algorithm,
		&item.Threshold,
		&item.ParticipantCount,
		&participantsJS,
		&item.MessageHash,
		&item.Ciphertext,
		&item.Status,
		&resultJS,
		&item.CreatedBy,
		&item.RequiredContributors,
		&createdRaw,
		&updatedRaw,
		&completedAtRaw,
	); err != nil {
		return MPCCeremony{}, err
	}
	item.Participants = parseJSONArrayString(participantsJS)
	item.Result = parseJSONObject(resultJS)
	item.CreatedAt = parseTimeValue(createdRaw)
	item.UpdatedAt = parseTimeValue(updatedRaw)
	item.CompletedAt = parseTimeValue(completedAtRaw)
	return item, nil
}

func scanMPCContribution(scanner interface {
	Scan(dest ...interface{}) error
}) (MPCContribution, error) {
	var (
		item      MPCContribution
		payloadJS string
		submitRaw interface{}
	)
	if err := scanner.Scan(
		&item.TenantID,
		&item.CeremonyID,
		&item.PartyID,
		&payloadJS,
		&submitRaw,
	); err != nil {
		return MPCContribution{}, err
	}
	item.Payload = parseJSONObject(payloadJS)
	item.SubmittedAt = parseTimeValue(submitRaw)
	return item, nil
}

func scanMPCParticipant(scanner interface {
	Scan(dest ...interface{}) error
}) (MPCParticipant, error) {
	var (
		item        MPCParticipant
		lastSeenRaw interface{}
		createdRaw  interface{}
		updatedRaw  interface{}
	)
	if err := scanner.Scan(
		&item.TenantID, &item.ID, &item.Name, &item.Endpoint, &item.PublicKey,
		&item.Status, &lastSeenRaw, &createdRaw, &updatedRaw,
	); err != nil {
		return MPCParticipant{}, err
	}
	item.LastSeenAt = parseTimeValue(lastSeenRaw)
	item.CreatedAt = parseTimeValue(createdRaw)
	item.UpdatedAt = parseTimeValue(updatedRaw)
	return item, nil
}

func scanMPCPolicy(scanner interface {
	Scan(dest ...interface{}) error
}) (MPCPolicy, error) {
	var (
		item       MPCPolicy
		enabled    int
		createdRaw interface{}
		updatedRaw interface{}
	)
	if err := scanner.Scan(
		&item.TenantID, &item.ID, &item.Name, &item.Description, &item.KeyIDs,
		&enabled, &createdRaw, &updatedRaw,
	); err != nil {
		return MPCPolicy{}, err
	}
	item.Enabled = enabled != 0
	item.CreatedAt = parseTimeValue(createdRaw)
	item.UpdatedAt = parseTimeValue(updatedRaw)
	return item, nil
}

// ── Helpers ──────────────────────────────────────────────────

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func parseJSONArray(v string) []interface{} {
	v = strings.TrimSpace(v)
	if v == "" {
		return []interface{}{}
	}
	var out []interface{}
	_ = json.Unmarshal([]byte(v), &out)
	if out == nil {
		return []interface{}{}
	}
	return out
}
