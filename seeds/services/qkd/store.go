package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	pkgdb "vecta-kms/pkg/db"
)

var errNotFound = errors.New("not found")

type Store interface {
	UpsertConfig(ctx context.Context, cfg QKDConfig) error
	GetConfig(ctx context.Context, tenantID string) (QKDConfig, error)

	UpsertDevice(ctx context.Context, d QKDDevice) error
	GetDevice(ctx context.Context, tenantID string, deviceID string) (QKDDevice, error)
	ListDevices(ctx context.Context, tenantID string) ([]QKDDevice, error)
	UpdateDeviceLinkStatus(ctx context.Context, tenantID string, deviceID string, status string, keyRate float64, qberAvg float64) error

	CreateKey(ctx context.Context, key QKDKey) error
	GetKey(ctx context.Context, tenantID string, keyID string) (QKDKey, error)
	GetKeysByIDs(ctx context.Context, tenantID string, keyIDs []string, allowedStatus []string) ([]QKDKey, error)
	ListAvailableKeysBySlave(ctx context.Context, tenantID string, slaveSAEID string, limit int) ([]QKDKey, error)
	UpdateKeysStatus(ctx context.Context, tenantID string, keyIDs []string, fromStatus []string, toStatus string) error
	SetKeyInjected(ctx context.Context, tenantID string, keyID string, keycoreKeyID string, status string) error
	CountAvailableKeys(ctx context.Context, tenantID string, slaveSAEID string) (int, error)
	CountTotalKeys(ctx context.Context, tenantID string, slaveSAEID string) (int, error)
	CountKeysCreatedToday(ctx context.Context, tenantID string, slaveSAEID string) (int, error)
	CountKeysUsedToday(ctx context.Context, tenantID string, slaveSAEID string) (int, error)
	ListKeys(ctx context.Context, tenantID string, slaveSAEID string, statuses []string, limit int) ([]QKDKey, error)
	GetDeviceQBERAvg(ctx context.Context, tenantID string, deviceID string) (float64, error)

	CreateSession(ctx context.Context, s QKDSession) error
	GetSession(ctx context.Context, tenantID string, sessionID string) (QKDSession, error)
	TouchSession(ctx context.Context, tenantID string, sessionID string) error
	CloseSession(ctx context.Context, tenantID string, sessionID string) error

	InsertLog(ctx context.Context, entry QKDLogEntry) error
	ListLogs(ctx context.Context, tenantID string, limit int) ([]QKDLogEntry, error)

	CreateSlaveSAE(ctx context.Context, sae SlaveSAE) error
	UpdateSlaveSAE(ctx context.Context, sae SlaveSAE) error
	GetSlaveSAE(ctx context.Context, tenantID string, id string) (SlaveSAE, error)
	ListSlaveSAEs(ctx context.Context, tenantID string) ([]SlaveSAE, error)
	DeleteSlaveSAE(ctx context.Context, tenantID string, id string) error
	IncrementSAEDistributed(ctx context.Context, tenantID string, id string, count int64) error

	CreateDistribution(ctx context.Context, d Distribution) error
	ListDistributions(ctx context.Context, tenantID string, slaveSAEID string, limit int) ([]Distribution, error)
}

type SQLStore struct {
	db *pkgdb.DB
}

func NewSQLStore(db *pkgdb.DB) *SQLStore {
	return &SQLStore{db: db}
}

func (s *SQLStore) UpsertConfig(ctx context.Context, cfg QKDConfig) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO qkd_config (
	tenant_id, qber_threshold, pool_low_threshold, pool_capacity, auto_inject,
	service_enabled, etsi_api_enabled, protocol, distance_km, updated_at
) VALUES (
	$1,$2,$3,$4,$5,
	$6,$7,$8,$9,$10
)
ON CONFLICT (tenant_id) DO UPDATE SET
	qber_threshold = excluded.qber_threshold,
	pool_low_threshold = excluded.pool_low_threshold,
	pool_capacity = excluded.pool_capacity,
	auto_inject = excluded.auto_inject,
	service_enabled = excluded.service_enabled,
	etsi_api_enabled = excluded.etsi_api_enabled,
	protocol = excluded.protocol,
	distance_km = excluded.distance_km,
	updated_at = excluded.updated_at
`, cfg.TenantID, cfg.QBERThreshold, cfg.PoolLowThreshold, cfg.PoolCapacity, cfg.AutoInject,
		cfg.ServiceEnabled, cfg.ETSIAPIEnabled, strings.TrimSpace(cfg.Protocol), cfg.DistanceKM, cfg.UpdatedAt.UTC())
	return err
}

func (s *SQLStore) GetConfig(ctx context.Context, tenantID string) (QKDConfig, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, qber_threshold, pool_low_threshold, pool_capacity, auto_inject,
	   service_enabled, etsi_api_enabled, protocol, distance_km, updated_at
FROM qkd_config
WHERE tenant_id = $1
`, tenantID)
	var (
		out         QKDConfig
		autoRaw     interface{}
		serviceRaw  interface{}
		etsiRaw     interface{}
		updatedRaw  interface{}
		protocolRaw interface{}
	)
	if err := row.Scan(
		&out.TenantID,
		&out.QBERThreshold,
		&out.PoolLowThreshold,
		&out.PoolCapacity,
		&autoRaw,
		&serviceRaw,
		&etsiRaw,
		&protocolRaw,
		&out.DistanceKM,
		&updatedRaw,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return QKDConfig{}, errNotFound
		}
		return QKDConfig{}, err
	}
	out.AutoInject = boolValue(autoRaw)
	out.ServiceEnabled = boolValue(serviceRaw)
	out.ETSIAPIEnabled = boolValue(etsiRaw)
	out.Protocol = strings.TrimSpace(toString(protocolRaw))
	out.UpdatedAt = parseTimeValue(updatedRaw)
	return out, nil
}

func (s *SQLStore) UpsertDevice(ctx context.Context, d QKDDevice) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO qkd_devices (
	id, tenant_id, name, role, slave_sae_id, link_status, key_rate, qber_avg, last_seen_at, created_at, updated_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,$9,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP
)
ON CONFLICT (tenant_id, id) DO UPDATE SET
	name = excluded.name,
	role = excluded.role,
	slave_sae_id = excluded.slave_sae_id,
	link_status = excluded.link_status,
	key_rate = excluded.key_rate,
	qber_avg = excluded.qber_avg,
	last_seen_at = excluded.last_seen_at,
	updated_at = excluded.updated_at
`, d.ID, d.TenantID, d.Name, d.Role, d.SlaveSAEID, d.LinkStatus, d.KeyRate, d.QBERAvg, nullableTime(d.LastSeenAt))
	return err
}

func (s *SQLStore) GetDevice(ctx context.Context, tenantID string, deviceID string) (QKDDevice, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, name, role, slave_sae_id, link_status, key_rate, qber_avg, last_seen_at, created_at, updated_at
FROM qkd_devices
WHERE tenant_id = $1 AND id = $2
`, tenantID, deviceID)
	out, err := scanDevice(row)
	if errors.Is(err, sql.ErrNoRows) {
		return QKDDevice{}, errNotFound
	}
	return out, err
}

func (s *SQLStore) ListDevices(ctx context.Context, tenantID string) ([]QKDDevice, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, name, role, slave_sae_id, link_status, key_rate, qber_avg, last_seen_at, created_at, updated_at
FROM qkd_devices
WHERE tenant_id = $1
ORDER BY id
`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]QKDDevice, 0)
	for rows.Next() {
		item, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpdateDeviceLinkStatus(ctx context.Context, tenantID string, deviceID string, status string, keyRate float64, qberAvg float64) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE qkd_devices
SET link_status = $1, key_rate = $2, qber_avg = $3, last_seen_at = $4, updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $5 AND id = $6
`, status, keyRate, qberAvg, time.Now().UTC(), tenantID, deviceID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) CreateKey(ctx context.Context, key QKDKey) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO qkd_keys (
	id, tenant_id, device_id, slave_sae_id, external_key_id, key_size_bits, qber, status,
	keycore_key_id, wrapped_dek, wrapped_dek_iv, ciphertext, data_iv, created_at, updated_at, injected_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,
	$9,$10,$11,$12,$13,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,$14
)
`, key.ID, key.TenantID, key.DeviceID, key.SlaveSAEID, key.ExternalKeyID, key.KeySizeBits, key.QBER, key.Status,
		key.KeyCoreKeyID, key.WrappedDEK, key.WrappedDEKIV, key.Ciphertext, key.DataIV, nullableTime(key.InjectedAt))
	return err
}

func (s *SQLStore) GetKey(ctx context.Context, tenantID string, keyID string) (QKDKey, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, device_id, slave_sae_id, external_key_id, key_size_bits, qber, status,
	   keycore_key_id, wrapped_dek, wrapped_dek_iv, ciphertext, data_iv, created_at, updated_at, injected_at
FROM qkd_keys
WHERE tenant_id = $1 AND id = $2
`, tenantID, keyID)
	out, err := scanQKDKey(row)
	if errors.Is(err, sql.ErrNoRows) {
		return QKDKey{}, errNotFound
	}
	return out, err
}

func (s *SQLStore) GetKeysByIDs(ctx context.Context, tenantID string, keyIDs []string, allowedStatus []string) ([]QKDKey, error) {
	if len(keyIDs) == 0 {
		return []QKDKey{}, nil
	}
	allowed := map[string]struct{}{}
	for _, st := range allowedStatus {
		n := normalizeKeyStatus(st)
		if n != "" {
			allowed[n] = struct{}{}
		}
	}
	keys := make([]QKDKey, 0, len(keyIDs))
	for _, id := range keyIDs {
		k, err := s.GetKey(ctx, tenantID, strings.TrimSpace(id))
		if err != nil {
			if errors.Is(err, errNotFound) {
				continue
			}
			return nil, err
		}
		if len(allowed) > 0 {
			if _, ok := allowed[k.Status]; !ok {
				continue
			}
		}
		keys = append(keys, k)
	}
	return keys, nil
}

func (s *SQLStore) ListAvailableKeysBySlave(ctx context.Context, tenantID string, slaveSAEID string, limit int) ([]QKDKey, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, device_id, slave_sae_id, external_key_id, key_size_bits, qber, status,
	   keycore_key_id, wrapped_dek, wrapped_dek_iv, ciphertext, data_iv, created_at, updated_at, injected_at
FROM qkd_keys
WHERE tenant_id = $1 AND slave_sae_id = $2 AND status = $3
ORDER BY created_at
LIMIT $4
`, tenantID, slaveSAEID, KeyStatusAvailable, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]QKDKey, 0)
	for rows.Next() {
		item, err := scanQKDKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpdateKeysStatus(ctx context.Context, tenantID string, keyIDs []string, fromStatus []string, toStatus string) error {
	toStatus = normalizeKeyStatus(toStatus)
	if len(keyIDs) == 0 || toStatus == "" {
		return nil
	}
	fromAllowed := map[string]struct{}{}
	for _, st := range fromStatus {
		n := normalizeKeyStatus(st)
		if n != "" {
			fromAllowed[n] = struct{}{}
		}
	}
	for _, id := range keyIDs {
		k, err := s.GetKey(ctx, tenantID, strings.TrimSpace(id))
		if err != nil {
			return err
		}
		if len(fromAllowed) > 0 {
			if _, ok := fromAllowed[k.Status]; !ok {
				continue
			}
		}
		if _, err := s.db.SQL().ExecContext(ctx, `
UPDATE qkd_keys
SET status = $1, updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $2 AND id = $3
`, toStatus, tenantID, k.ID); err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLStore) SetKeyInjected(ctx context.Context, tenantID string, keyID string, keycoreKeyID string, status string) error {
	if normalizeKeyStatus(status) == "" {
		status = KeyStatusInjected
	}
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE qkd_keys
SET keycore_key_id = $1, status = $2, injected_at = $3, updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $4 AND id = $5
`, keycoreKeyID, status, time.Now().UTC(), tenantID, keyID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) CountAvailableKeys(ctx context.Context, tenantID string, slaveSAEID string) (int, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT COUNT(*) FROM qkd_keys
WHERE tenant_id = $1 AND slave_sae_id = $2 AND status = $3
`, tenantID, slaveSAEID, KeyStatusAvailable)
	var n int
	if err := row.Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

func (s *SQLStore) CountTotalKeys(ctx context.Context, tenantID string, slaveSAEID string) (int, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT COUNT(*) FROM qkd_keys
WHERE tenant_id = $1 AND slave_sae_id = $2
`, tenantID, slaveSAEID)
	var n int
	if err := row.Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

func (s *SQLStore) CountKeysCreatedToday(ctx context.Context, tenantID string, slaveSAEID string) (int, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT COUNT(*) FROM qkd_keys
WHERE tenant_id = $1 AND slave_sae_id = $2 AND created_at >= CURRENT_DATE
`, tenantID, slaveSAEID)
	var n int
	if err := row.Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

func (s *SQLStore) CountKeysUsedToday(ctx context.Context, tenantID string, slaveSAEID string) (int, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT COUNT(*) FROM qkd_keys
WHERE tenant_id = $1 AND slave_sae_id = $2
  AND status IN ($3,$4,$5)
  AND updated_at >= CURRENT_DATE
`, tenantID, slaveSAEID, KeyStatusConsumed, KeyStatusInjected, KeyStatusReserved)
	var n int
	if err := row.Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

func (s *SQLStore) ListKeys(ctx context.Context, tenantID string, slaveSAEID string, statuses []string, limit int) ([]QKDKey, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	base := `
SELECT id, tenant_id, device_id, slave_sae_id, external_key_id, key_size_bits, qber, status,
	   keycore_key_id, wrapped_dek, wrapped_dek_iv, ciphertext, data_iv, created_at, updated_at, injected_at
FROM qkd_keys
WHERE tenant_id = $1 AND slave_sae_id = $2
ORDER BY created_at DESC
`
	args := []interface{}{tenantID, slaveSAEID}
	filtered := make([]string, 0, len(statuses))
	for _, st := range statuses {
		n := normalizeKeyStatus(st)
		if n != "" {
			filtered = append(filtered, n)
		}
	}
	rows, err := s.db.SQL().QueryContext(ctx, base, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	allowed := map[string]struct{}{}
	if len(filtered) > 0 {
		for _, st := range filtered {
			allowed[st] = struct{}{}
		}
	}
	out := make([]QKDKey, 0, limit)
	for rows.Next() {
		item, err := scanQKDKey(rows)
		if err != nil {
			return nil, err
		}
		if len(allowed) > 0 {
			if _, ok := allowed[item.Status]; !ok {
				continue
			}
		}
		out = append(out, item)
		if len(out) >= limit {
			break
		}
	}
	return out, rows.Err()
}

func (s *SQLStore) GetDeviceQBERAvg(ctx context.Context, tenantID string, deviceID string) (float64, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT COALESCE(AVG(qber), 0.0)
FROM qkd_keys
WHERE tenant_id = $1 AND device_id = $2
`, tenantID, deviceID)
	var avg float64
	if err := row.Scan(&avg); err != nil {
		return 0, err
	}
	return avg, nil
}

func (s *SQLStore) CreateSession(ctx context.Context, sess QKDSession) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO qkd_sessions (
	id, tenant_id, device_id, slave_sae_id, app_id, status, opened_at, last_used_at, closed_at, created_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,$9,CURRENT_TIMESTAMP
)
`, sess.ID, sess.TenantID, sess.DeviceID, sess.SlaveSAEID, sess.AppID, sess.Status, sess.OpenedAt.UTC(), nullableTime(sess.LastUsedAt), nullableTime(sess.ClosedAt))
	return err
}

func (s *SQLStore) GetSession(ctx context.Context, tenantID string, sessionID string) (QKDSession, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, device_id, slave_sae_id, app_id, status, opened_at, last_used_at, closed_at
FROM qkd_sessions
WHERE tenant_id = $1 AND id = $2
`, tenantID, sessionID)
	var (
		out       QKDSession
		openedRaw interface{}
		lastRaw   interface{}
		closedRaw interface{}
	)
	if err := row.Scan(&out.ID, &out.TenantID, &out.DeviceID, &out.SlaveSAEID, &out.AppID, &out.Status, &openedRaw, &lastRaw, &closedRaw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return QKDSession{}, errNotFound
		}
		return QKDSession{}, err
	}
	out.OpenedAt = parseTimeValue(openedRaw)
	out.LastUsedAt = parseTimeValue(lastRaw)
	out.ClosedAt = parseTimeValue(closedRaw)
	return out, nil
}

func (s *SQLStore) TouchSession(ctx context.Context, tenantID string, sessionID string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE qkd_sessions
SET last_used_at = $1
WHERE tenant_id = $2 AND id = $3
`, time.Now().UTC(), tenantID, sessionID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) CloseSession(ctx context.Context, tenantID string, sessionID string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE qkd_sessions
SET status = 'closed', closed_at = $1, last_used_at = $1
WHERE tenant_id = $2 AND id = $3
`, time.Now().UTC(), tenantID, sessionID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) InsertLog(ctx context.Context, entry QKDLogEntry) error {
	metaRaw := []byte("{}")
	if entry.Meta != nil {
		if b, err := json.Marshal(entry.Meta); err == nil {
			metaRaw = b
		}
	}
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO qkd_logs (
	id, tenant_id, action, level, message, meta_json, created_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7
)
`, entry.ID, entry.TenantID, entry.Action, strings.TrimSpace(entry.Level), strings.TrimSpace(entry.Message), string(metaRaw), nullableTime(entry.CreatedAt))
	return err
}

func (s *SQLStore) ListLogs(ctx context.Context, tenantID string, limit int) ([]QKDLogEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, action, level, message, meta_json, created_at
FROM qkd_logs
WHERE tenant_id = $1
ORDER BY created_at DESC
LIMIT $2
`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]QKDLogEntry, 0, limit)
	for rows.Next() {
		var (
			item      QKDLogEntry
			metaRaw   interface{}
			createdAt interface{}
		)
		if err := rows.Scan(&item.ID, &item.TenantID, &item.Action, &item.Level, &item.Message, &metaRaw, &createdAt); err != nil {
			return nil, err
		}
		item.CreatedAt = parseTimeValue(createdAt)
		item.Meta = map[string]interface{}{}
		if raw := strings.TrimSpace(toString(metaRaw)); raw != "" {
			_ = json.Unmarshal([]byte(raw), &item.Meta)
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func scanDevice(scanner interface {
	Scan(dest ...interface{}) error
}) (QKDDevice, error) {
	var (
		out        QKDDevice
		lastRaw    interface{}
		createdRaw interface{}
		updatedRaw interface{}
	)
	err := scanner.Scan(
		&out.ID, &out.TenantID, &out.Name, &out.Role, &out.SlaveSAEID, &out.LinkStatus, &out.KeyRate, &out.QBERAvg, &lastRaw, &createdRaw, &updatedRaw,
	)
	if err != nil {
		return QKDDevice{}, err
	}
	out.LastSeenAt = parseTimeValue(lastRaw)
	out.CreatedAt = parseTimeValue(createdRaw)
	out.UpdatedAt = parseTimeValue(updatedRaw)
	return out, nil
}

func scanQKDKey(scanner interface {
	Scan(dest ...interface{}) error
}) (QKDKey, error) {
	var (
		out         QKDKey
		createdRaw  interface{}
		updatedRaw  interface{}
		injectedRaw interface{}
	)
	err := scanner.Scan(
		&out.ID, &out.TenantID, &out.DeviceID, &out.SlaveSAEID, &out.ExternalKeyID, &out.KeySizeBits, &out.QBER, &out.Status,
		&out.KeyCoreKeyID, &out.WrappedDEK, &out.WrappedDEKIV, &out.Ciphertext, &out.DataIV, &createdRaw, &updatedRaw, &injectedRaw,
	)
	if err != nil {
		return QKDKey{}, err
	}
	out.CreatedAt = parseTimeValue(createdRaw)
	out.UpdatedAt = parseTimeValue(updatedRaw)
	out.InjectedAt = parseTimeValue(injectedRaw)
	return out, nil
}

func boolValue(v interface{}) bool {
	switch x := v.(type) {
	case bool:
		return x
	case int64:
		return x != 0
	case int:
		return x != 0
	case []byte:
		s := strings.TrimSpace(string(x))
		return s == "1" || strings.EqualFold(s, "true")
	case string:
		s := strings.TrimSpace(x)
		return s == "1" || strings.EqualFold(s, "true")
	default:
		return false
	}
}

func toString(v interface{}) string {
	switch x := v.(type) {
	case string:
		return x
	case []byte:
		return string(x)
	default:
		return ""
	}
}

// ── Slave SAE Store Methods ────────────────────────────────

func (s *SQLStore) CreateSlaveSAE(ctx context.Context, sae SlaveSAE) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO qkd_slave_sae (id, tenant_id, name, endpoint, auth_token, protocol, role, mode, status,
    max_key_rate, qber_threshold, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		sae.ID, sae.TenantID, sae.Name, sae.Endpoint, sae.AuthToken, sae.Protocol, sae.Role, sae.Mode,
		sae.Status, sae.MaxKeyRate, sae.QBERThreshold, sae.CreatedAt.UTC(), sae.UpdatedAt.UTC())
	return err
}

func (s *SQLStore) UpdateSlaveSAE(ctx context.Context, sae SlaveSAE) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE qkd_slave_sae SET name=$3, endpoint=$4, auth_token=$5, protocol=$6, role=$7, mode=$8,
    status=$9, max_key_rate=$10, qber_threshold=$11, updated_at=$12
WHERE tenant_id=$1 AND id=$2`,
		sae.TenantID, sae.ID, sae.Name, sae.Endpoint, sae.AuthToken, sae.Protocol, sae.Role, sae.Mode,
		sae.Status, sae.MaxKeyRate, sae.QBERThreshold, sae.UpdatedAt.UTC())
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) GetSlaveSAE(ctx context.Context, tenantID string, id string) (SlaveSAE, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, name, endpoint, auth_token, protocol, role, mode, status,
    last_sync_at, keys_distributed, keys_available, max_key_rate, qber_threshold, created_at, updated_at
FROM qkd_slave_sae WHERE tenant_id=$1 AND id=$2`, tenantID, id)
	var out SlaveSAE
	var lastSync sql.NullTime
	err := row.Scan(&out.ID, &out.TenantID, &out.Name, &out.Endpoint, &out.AuthToken,
		&out.Protocol, &out.Role, &out.Mode, &out.Status,
		&lastSync, &out.KeysDistributed, &out.KeysAvailable, &out.MaxKeyRate, &out.QBERThreshold,
		&out.CreatedAt, &out.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return SlaveSAE{}, errNotFound
	}
	if lastSync.Valid {
		out.LastSyncAt = lastSync.Time.UTC()
	}
	return out, err
}

func (s *SQLStore) ListSlaveSAEs(ctx context.Context, tenantID string) ([]SlaveSAE, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, name, endpoint, '', protocol, role, mode, status,
    last_sync_at, keys_distributed, keys_available, max_key_rate, qber_threshold, created_at, updated_at
FROM qkd_slave_sae WHERE tenant_id=$1 ORDER BY updated_at DESC`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SlaveSAE
	for rows.Next() {
		var item SlaveSAE
		var lastSync sql.NullTime
		if err := rows.Scan(&item.ID, &item.TenantID, &item.Name, &item.Endpoint, &item.AuthToken,
			&item.Protocol, &item.Role, &item.Mode, &item.Status,
			&lastSync, &item.KeysDistributed, &item.KeysAvailable, &item.MaxKeyRate, &item.QBERThreshold,
			&item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		if lastSync.Valid {
			item.LastSyncAt = lastSync.Time.UTC()
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) DeleteSlaveSAE(ctx context.Context, tenantID string, id string) error {
	res, err := s.db.SQL().ExecContext(ctx, `DELETE FROM qkd_slave_sae WHERE tenant_id=$1 AND id=$2`, tenantID, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) IncrementSAEDistributed(ctx context.Context, tenantID string, id string, count int64) error {
	_, err := s.db.SQL().ExecContext(ctx, `
UPDATE qkd_slave_sae SET keys_distributed = keys_distributed + $3, last_sync_at = $4, updated_at = $4
WHERE tenant_id=$1 AND id=$2`, tenantID, id, count, time.Now().UTC())
	return err
}

func (s *SQLStore) CreateDistribution(ctx context.Context, d Distribution) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO qkd_distributions (id, tenant_id, slave_sae_id, key_count, key_size_bits, status, error_message, distributed_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		d.ID, d.TenantID, d.SlaveSAEID, d.KeyCount, d.KeySizeBits, d.Status, d.ErrorMessage, d.DistributedAt.UTC())
	return err
}

func (s *SQLStore) ListDistributions(ctx context.Context, tenantID string, slaveSAEID string, limit int) ([]Distribution, error) {
	if limit <= 0 {
		limit = 50
	}
	q := `SELECT id, tenant_id, slave_sae_id, key_count, key_size_bits, status, error_message, distributed_at
FROM qkd_distributions WHERE tenant_id=$1`
	args := []interface{}{tenantID}
	if strings.TrimSpace(slaveSAEID) != "" {
		q += ` AND slave_sae_id=$2`
		args = append(args, slaveSAEID)
	}
	q += ` ORDER BY distributed_at DESC LIMIT ` + intToStr(limit)

	rows, err := s.db.SQL().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Distribution
	for rows.Next() {
		var d Distribution
		if err := rows.Scan(&d.ID, &d.TenantID, &d.SlaveSAEID, &d.KeyCount, &d.KeySizeBits,
			&d.Status, &d.ErrorMessage, &d.DistributedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func intToStr(n int) string {
	if n <= 0 {
		return "50"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}
