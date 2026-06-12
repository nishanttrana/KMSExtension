package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	pkgdb "vecta-kms/pkg/db"
)

var errNotFound = errors.New("not found")

type Store interface {
	CreateSource(ctx context.Context, s QRNGSource) error
	UpdateSource(ctx context.Context, s QRNGSource) error
	GetSource(ctx context.Context, tenantID, id string) (QRNGSource, error)
	ListSources(ctx context.Context, tenantID string) ([]QRNGSource, error)
	DeleteSource(ctx context.Context, tenantID, id string) error
	UpdateSourceStatus(ctx context.Context, tenantID, id, status, lastError string) error

	InsertSample(ctx context.Context, s QRNGPoolSample) error
	MarkSampleConsumed(ctx context.Context, tenantID, id string) error
	PoolStatus(ctx context.Context, tenantID string) (QRNGPoolStatus, error)

	InsertHealthEvent(ctx context.Context, h QRNGHealthEvent) error
	ListHealthEvents(ctx context.Context, tenantID string, limit int) ([]QRNGHealthEvent, error)
}

type SQLStore struct {
	db *pkgdb.DB
}

func NewSQLStore(db *pkgdb.DB) *SQLStore { return &SQLStore{db: db} }

// ── Source CRUD ──────────────────────────────────────────────

func (s *SQLStore) CreateSource(ctx context.Context, src QRNGSource) error {
	_, err := s.db.SQL().ExecContext(ctx,
		`INSERT INTO qrng_sources (id, tenant_id, name, vendor, endpoint, auth_token, mode, status, min_entropy_bpb, pull_interval_s, last_seen_at, last_error, created_at, updated_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		src.ID, src.TenantID, src.Name, src.Vendor, src.Endpoint, src.AuthToken,
		src.Mode, src.Status, src.MinEntropyBPB, src.PullIntervalS,
		nullableTime(src.LastSeenAt), src.LastError, src.CreatedAt, src.UpdatedAt)
	return err
}

func (s *SQLStore) UpdateSource(ctx context.Context, src QRNGSource) error {
	_, err := s.db.SQL().ExecContext(ctx,
		`UPDATE qrng_sources SET name=$1, vendor=$2, endpoint=$3, auth_token=$4, mode=$5, status=$6, min_entropy_bpb=$7, pull_interval_s=$8, updated_at=$9
		 WHERE tenant_id=$10 AND id=$11`,
		src.Name, src.Vendor, src.Endpoint, src.AuthToken, src.Mode, src.Status,
		src.MinEntropyBPB, src.PullIntervalS, time.Now().UTC(),
		src.TenantID, src.ID)
	return err
}

func (s *SQLStore) GetSource(ctx context.Context, tenantID, id string) (QRNGSource, error) {
	row := s.db.SQL().QueryRowContext(ctx,
		`SELECT id, tenant_id, name, vendor, endpoint, mode, status, min_entropy_bpb, pull_interval_s, last_seen_at, last_error, created_at, updated_at
		 FROM qrng_sources WHERE tenant_id=$1 AND id=$2`, tenantID, id)
	return scanSource(row)
}

func (s *SQLStore) ListSources(ctx context.Context, tenantID string) ([]QRNGSource, error) {
	rows, err := s.db.SQL().QueryContext(ctx,
		`SELECT id, tenant_id, name, vendor, endpoint, mode, status, min_entropy_bpb, pull_interval_s, last_seen_at, last_error, created_at, updated_at
		 FROM qrng_sources WHERE tenant_id=$1 AND status != 'removed' ORDER BY created_at DESC`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []QRNGSource
	for rows.Next() {
		src, err := scanSource(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, src)
	}
	return out, rows.Err()
}

func (s *SQLStore) DeleteSource(ctx context.Context, tenantID, id string) error {
	_, err := s.db.SQL().ExecContext(ctx,
		`UPDATE qrng_sources SET status='removed', updated_at=$1 WHERE tenant_id=$2 AND id=$3`,
		time.Now().UTC(), tenantID, id)
	return err
}

func (s *SQLStore) UpdateSourceStatus(ctx context.Context, tenantID, id, status, lastError string) error {
	_, err := s.db.SQL().ExecContext(ctx,
		`UPDATE qrng_sources SET status=$1, last_error=$2, last_seen_at=$3, updated_at=$3 WHERE tenant_id=$4 AND id=$5`,
		status, lastError, time.Now().UTC(), tenantID, id)
	return err
}

type scanner interface {
	Scan(dest ...interface{}) error
}

func scanSource(row scanner) (QRNGSource, error) {
	var s QRNGSource
	var lastSeen, created, updated interface{}
	err := row.Scan(&s.ID, &s.TenantID, &s.Name, &s.Vendor, &s.Endpoint,
		&s.Mode, &s.Status, &s.MinEntropyBPB, &s.PullIntervalS,
		&lastSeen, &s.LastError, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return QRNGSource{}, errNotFound
	}
	if err != nil {
		return QRNGSource{}, err
	}
	s.LastSeenAt = parseTimeValue(lastSeen)
	s.CreatedAt = parseTimeValue(created)
	s.UpdatedAt = parseTimeValue(updated)
	return s, nil
}

// ── Pool ─────────────────────────────────────────────────────

func (s *SQLStore) InsertSample(ctx context.Context, sample QRNGPoolSample) error {
	_, err := s.db.SQL().ExecContext(ctx,
		`INSERT INTO qrng_pool (id, tenant_id, source_id, sample_hash, byte_count, entropy_bpb, bias_score, passed_health, consumed, created_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		sample.ID, sample.TenantID, sample.SourceID, sample.SampleHash,
		sample.ByteCount, sample.EntropyBPB, sample.BiasScore,
		sample.PassedHealth, false, sample.CreatedAt)
	return err
}

func (s *SQLStore) MarkSampleConsumed(ctx context.Context, tenantID, id string) error {
	_, err := s.db.SQL().ExecContext(ctx,
		`UPDATE qrng_pool SET consumed=TRUE, consumed_at=$1 WHERE tenant_id=$2 AND id=$3`,
		time.Now().UTC(), tenantID, id)
	return err
}

func (s *SQLStore) PoolStatus(ctx context.Context, tenantID string) (QRNGPoolStatus, error) {
	ps := QRNGPoolStatus{TenantID: tenantID}

	row := s.db.SQL().QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(SUM(CASE WHEN consumed=FALSE AND passed_health=TRUE THEN 1 ELSE 0 END),0),
		        COALESCE(SUM(CASE WHEN consumed=TRUE THEN 1 ELSE 0 END),0),
		        COALESCE(AVG(entropy_bpb),0)
		 FROM qrng_pool WHERE tenant_id=$1`, tenantID)
	if err := row.Scan(&ps.TotalSamples, &ps.AvailableSamples, &ps.ConsumedSamples, &ps.AvgEntropyBPB); err != nil {
		return ps, err
	}

	var lastIngest interface{}
	_ = s.db.SQL().QueryRowContext(ctx,
		`SELECT created_at FROM qrng_pool WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 1`, tenantID).Scan(&lastIngest)
	ps.LastIngestAt = parseTimeValue(lastIngest)

	_ = s.db.SQL().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM qrng_sources WHERE tenant_id=$1 AND status='active'`, tenantID).Scan(&ps.ActiveSourceCount)

	ps.PoolHealthy = ps.AvailableSamples > 0 && ps.ActiveSourceCount > 0 && ps.AvgEntropyBPB >= MinAcceptableEntropyBPB
	return ps, nil
}

// ── Health Log ───────────────────────────────────────────────

func (s *SQLStore) InsertHealthEvent(ctx context.Context, h QRNGHealthEvent) error {
	detailJSON := "{}"
	if h.Detail != nil {
		if b, err := json.Marshal(h.Detail); err == nil {
			detailJSON = string(b)
		}
	}
	_, err := s.db.SQL().ExecContext(ctx,
		`INSERT INTO qrng_health_log (id, tenant_id, source_id, check_type, result, entropy_bpb, detail, created_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		h.ID, h.TenantID, h.SourceID, h.CheckType, h.Result, h.EntropyBPB, detailJSON, h.CreatedAt)
	return err
}

func (s *SQLStore) ListHealthEvents(ctx context.Context, tenantID string, limit int) ([]QRNGHealthEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.SQL().QueryContext(ctx,
		`SELECT id, tenant_id, source_id, check_type, result, entropy_bpb, detail, created_at
		 FROM qrng_health_log WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT `+strconv.Itoa(limit), tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []QRNGHealthEvent
	for rows.Next() {
		var h QRNGHealthEvent
		var detailStr string
		var created interface{}
		if err := rows.Scan(&h.ID, &h.TenantID, &h.SourceID, &h.CheckType, &h.Result, &h.EntropyBPB, &detailStr, &created); err != nil {
			return nil, err
		}
		h.CreatedAt = parseTimeValue(created)
		h.Detail = make(map[string]interface{})
		_ = json.Unmarshal([]byte(validJSONOr(detailStr, "{}")), &h.Detail)
		out = append(out, h)
	}
	return out, rows.Err()
}
