package main

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

func (s *SQLStore) CreateInjectionTerminal(ctx context.Context, item PaymentInjectionTerminal) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO payment_injection_terminals (
	tenant_id, id, terminal_id, name, status, transport, key_algorithm,
	public_key_pem, public_key_fingerprint, registration_nonce, registration_nonce_expires_at,
	verified_at, auth_token_hash, auth_token_issued_at, last_seen_at, metadata_json, created_at, updated_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,
	$8,$9,$10,$11,
	$12,$13,$14,$15,$16,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP
)`,
		item.TenantID, item.ID, item.TerminalID, item.Name, item.Status, item.Transport, item.KeyAlgorithm,
		item.PublicKeyPEM, item.PublicKeyFingerprint, strings.TrimSpace(item.RegistrationNonce), nullableTime(item.RegistrationNonceExpiresAt),
		nullableTime(item.VerifiedAt), item.AuthTokenHash, nullableTime(item.AuthTokenIssuedAt), nullableTime(item.LastSeenAt), validJSONOr(item.MetadataJSON, "{}"))
	return err
}

func (s *SQLStore) GetInjectionTerminal(ctx context.Context, tenantID string, id string) (PaymentInjectionTerminal, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, id, terminal_id, name, status, transport, key_algorithm,
	   public_key_pem, public_key_fingerprint, registration_nonce, registration_nonce_expires_at,
	   verified_at, auth_token_hash, auth_token_issued_at, last_seen_at, metadata_json, created_at, updated_at
FROM payment_injection_terminals
WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	out, err := scanInjectionTerminal(row)
	if errors.Is(err, sql.ErrNoRows) {
		return PaymentInjectionTerminal{}, errNotFound
	}
	return out, err
}

func (s *SQLStore) GetInjectionTerminalByTerminalID(ctx context.Context, tenantID string, terminalID string) (PaymentInjectionTerminal, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, id, terminal_id, name, status, transport, key_algorithm,
	   public_key_pem, public_key_fingerprint, registration_nonce, registration_nonce_expires_at,
	   verified_at, auth_token_hash, auth_token_issued_at, last_seen_at, metadata_json, created_at, updated_at
FROM payment_injection_terminals
WHERE tenant_id = $1 AND terminal_id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(terminalID))
	out, err := scanInjectionTerminal(row)
	if errors.Is(err, sql.ErrNoRows) {
		return PaymentInjectionTerminal{}, errNotFound
	}
	return out, err
}

func (s *SQLStore) ListInjectionTerminals(ctx context.Context, tenantID string) ([]PaymentInjectionTerminal, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, id, terminal_id, name, status, transport, key_algorithm,
	   public_key_pem, public_key_fingerprint, registration_nonce, registration_nonce_expires_at,
	   verified_at, auth_token_hash, auth_token_issued_at, last_seen_at, metadata_json, created_at, updated_at
FROM payment_injection_terminals
WHERE tenant_id = $1
ORDER BY created_at DESC
`, strings.TrimSpace(tenantID))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]PaymentInjectionTerminal, 0)
	for rows.Next() {
		item, err := scanInjectionTerminal(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpdateInjectionTerminalChallenge(ctx context.Context, tenantID string, id string, nonce string, expiresAt time.Time) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE payment_injection_terminals
SET registration_nonce = $1,
	registration_nonce_expires_at = $2,
	updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $3 AND id = $4
`, strings.TrimSpace(nonce), nullableTime(expiresAt), strings.TrimSpace(tenantID), strings.TrimSpace(id))
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) MarkInjectionTerminalVerified(ctx context.Context, tenantID string, id string, verifiedAt time.Time, authTokenHash string, authTokenIssuedAt time.Time) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE payment_injection_terminals
SET status = 'active',
	verified_at = $1,
	auth_token_hash = $2,
	auth_token_issued_at = $3,
	registration_nonce = '',
	registration_nonce_expires_at = NULL,
	updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $4 AND id = $5
`, nullableTime(verifiedAt), strings.TrimSpace(authTokenHash), nullableTime(authTokenIssuedAt), strings.TrimSpace(tenantID), strings.TrimSpace(id))
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) UpdateInjectionTerminalLastSeen(ctx context.Context, tenantID string, id string, lastSeenAt time.Time) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE payment_injection_terminals
SET last_seen_at = $1, updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $2 AND id = $3
`, nullableTime(lastSeenAt), strings.TrimSpace(tenantID), strings.TrimSpace(id))
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) CreateInjectionJob(ctx context.Context, item PaymentInjectionJob) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO payment_injection_jobs (
	tenant_id, id, terminal_id, payment_key_id, key_id, tr31_version, tr31_usage_code, tr31_key_block, tr31_kcv,
	payload_ciphertext_b64, payload_iv_b64, wrapped_dek_b64, dek_wrap_alg, status, delivered_at, acked_at, ack_detail, created_at, updated_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,$9,
	$10,$11,$12,$13,$14,$15,$16,$17,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP
)
`, item.TenantID, item.ID, item.TerminalID, item.PaymentKeyID, item.KeyID, item.TR31Version, item.TR31UsageCode, item.TR31KeyBlock, item.TR31KCV,
		item.PayloadCiphertextB64, item.PayloadIVB64, item.WrappedDEKB64, item.DEKWrapAlg, item.Status, nullableTime(item.DeliveredAt), nullableTime(item.AckedAt), strings.TrimSpace(item.AckDetail))
	return err
}

func (s *SQLStore) GetInjectionJob(ctx context.Context, tenantID string, id string) (PaymentInjectionJob, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, id, terminal_id, payment_key_id, key_id, tr31_version, tr31_usage_code, tr31_key_block, tr31_kcv,
	   payload_ciphertext_b64, payload_iv_b64, wrapped_dek_b64, dek_wrap_alg, status, delivered_at, acked_at, ack_detail, created_at, updated_at
FROM payment_injection_jobs
WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	out, err := scanInjectionJob(row)
	if errors.Is(err, sql.ErrNoRows) {
		return PaymentInjectionJob{}, errNotFound
	}
	return out, err
}

func (s *SQLStore) ListInjectionJobs(ctx context.Context, tenantID string) ([]PaymentInjectionJob, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, id, terminal_id, payment_key_id, key_id, tr31_version, tr31_usage_code, tr31_key_block, tr31_kcv,
	   payload_ciphertext_b64, payload_iv_b64, wrapped_dek_b64, dek_wrap_alg, status, delivered_at, acked_at, ack_detail, created_at, updated_at
FROM payment_injection_jobs
WHERE tenant_id = $1
ORDER BY created_at DESC
`, strings.TrimSpace(tenantID))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]PaymentInjectionJob, 0)
	for rows.Next() {
		item, err := scanInjectionJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) ListInjectionJobsByTerminal(ctx context.Context, tenantID string, terminalID string) ([]PaymentInjectionJob, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, id, terminal_id, payment_key_id, key_id, tr31_version, tr31_usage_code, tr31_key_block, tr31_kcv,
	   payload_ciphertext_b64, payload_iv_b64, wrapped_dek_b64, dek_wrap_alg, status, delivered_at, acked_at, ack_detail, created_at, updated_at
FROM payment_injection_jobs
WHERE tenant_id = $1 AND terminal_id = $2
ORDER BY created_at DESC
`, strings.TrimSpace(tenantID), strings.TrimSpace(terminalID))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]PaymentInjectionJob, 0)
	for rows.Next() {
		item, err := scanInjectionJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetNextQueuedInjectionJob(ctx context.Context, tenantID string, terminalID string) (PaymentInjectionJob, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, id, terminal_id, payment_key_id, key_id, tr31_version, tr31_usage_code, tr31_key_block, tr31_kcv,
	   payload_ciphertext_b64, payload_iv_b64, wrapped_dek_b64, dek_wrap_alg, status, delivered_at, acked_at, ack_detail, created_at, updated_at
FROM payment_injection_jobs
WHERE tenant_id = $1 AND terminal_id = $2 AND status = 'queued'
ORDER BY created_at ASC
LIMIT 1
`, strings.TrimSpace(tenantID), strings.TrimSpace(terminalID))
	out, err := scanInjectionJob(row)
	if errors.Is(err, sql.ErrNoRows) {
		return PaymentInjectionJob{}, errNotFound
	}
	return out, err
}

func (s *SQLStore) MarkInjectionJobDelivered(ctx context.Context, tenantID string, id string, deliveredAt time.Time) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE payment_injection_jobs
SET status = 'delivered',
	delivered_at = $1,
	updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $2 AND id = $3
`, nullableTime(deliveredAt), strings.TrimSpace(tenantID), strings.TrimSpace(id))
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) MarkInjectionJobAck(ctx context.Context, tenantID string, id string, status string, detail string, ackedAt time.Time) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE payment_injection_jobs
SET status = $1,
	ack_detail = $2,
	acked_at = $3,
	updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $4 AND id = $5
`, strings.TrimSpace(status), strings.TrimSpace(detail), nullableTime(ackedAt), strings.TrimSpace(tenantID), strings.TrimSpace(id))
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func scanInjectionTerminal(scanner interface {
	Scan(dest ...interface{}) error
}) (PaymentInjectionTerminal, error) {
	var (
		out            PaymentInjectionTerminal
		regNonceRaw    interface{}
		verifiedRaw    interface{}
		tokenIssuedRaw interface{}
		lastSeenRaw    interface{}
		createdRaw     interface{}
		updatedRaw     interface{}
	)
	err := scanner.Scan(
		&out.TenantID,
		&out.ID,
		&out.TerminalID,
		&out.Name,
		&out.Status,
		&out.Transport,
		&out.KeyAlgorithm,
		&out.PublicKeyPEM,
		&out.PublicKeyFingerprint,
		&out.RegistrationNonce,
		&regNonceRaw,
		&verifiedRaw,
		&out.AuthTokenHash,
		&tokenIssuedRaw,
		&lastSeenRaw,
		&out.MetadataJSON,
		&createdRaw,
		&updatedRaw,
	)
	if err != nil {
		return PaymentInjectionTerminal{}, err
	}
	out.RegistrationNonceExpiresAt = parseTimeValue(regNonceRaw)
	out.VerifiedAt = parseTimeValue(verifiedRaw)
	out.AuthTokenIssuedAt = parseTimeValue(tokenIssuedRaw)
	out.LastSeenAt = parseTimeValue(lastSeenRaw)
	out.CreatedAt = parseTimeValue(createdRaw)
	out.UpdatedAt = parseTimeValue(updatedRaw)
	if strings.TrimSpace(out.MetadataJSON) == "" {
		out.MetadataJSON = "{}"
	}
	return out, nil
}

func scanInjectionJob(scanner interface {
	Scan(dest ...interface{}) error
}) (PaymentInjectionJob, error) {
	var (
		out          PaymentInjectionJob
		deliveredRaw interface{}
		ackedRaw     interface{}
		createdRaw   interface{}
		updatedRaw   interface{}
	)
	err := scanner.Scan(
		&out.TenantID,
		&out.ID,
		&out.TerminalID,
		&out.PaymentKeyID,
		&out.KeyID,
		&out.TR31Version,
		&out.TR31UsageCode,
		&out.TR31KeyBlock,
		&out.TR31KCV,
		&out.PayloadCiphertextB64,
		&out.PayloadIVB64,
		&out.WrappedDEKB64,
		&out.DEKWrapAlg,
		&out.Status,
		&deliveredRaw,
		&ackedRaw,
		&out.AckDetail,
		&createdRaw,
		&updatedRaw,
	)
	if err != nil {
		return PaymentInjectionJob{}, err
	}
	out.DeliveredAt = parseTimeValue(deliveredRaw)
	out.AckedAt = parseTimeValue(ackedRaw)
	out.CreatedAt = parseTimeValue(createdRaw)
	out.UpdatedAt = parseTimeValue(updatedRaw)
	return out, nil
}
