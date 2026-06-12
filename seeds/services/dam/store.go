package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
	pkgdb "vecta-kms/pkg/db"
)

var errNotFound = errors.New("not found")

// Store defines the storage interface for the DAM service.
type Store interface {
	IngestEvent(ctx context.Context, e ActivityEvent) (ActivityEvent, error)
	QueryEvents(ctx context.Context, q ActivityQuery) ([]ActivityEvent, error)
	GetStats(ctx context.Context, tenantID string) (ActivityStats, error)
	ListActors(ctx context.Context, tenantID string) ([]ActorSummary, error)
	ListSources(ctx context.Context, tenantID string) ([]SourceSummary, error)
}

// SQLStore implements Store backed by a SQL database.
type SQLStore struct {
	db *pkgdb.DB
}

// NewSQLStore creates a new SQLStore and ensures tables exist.
func NewSQLStore(db *pkgdb.DB) *SQLStore {
	s := &SQLStore{db: db}
	s.createTables(context.Background())
	return s
}

func (s *SQLStore) createTables(ctx context.Context) {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS activity_events (
			id TEXT NOT NULL,
			tenant_id TEXT NOT NULL,
			event_type TEXT NOT NULL,
			source TEXT NOT NULL DEFAULT '',
			actor TEXT NOT NULL DEFAULT '',
			actor_ip TEXT NOT NULL DEFAULT '',
			query TEXT NOT NULL DEFAULT '',
			rows_affected INTEGER NOT NULL DEFAULT 0,
			data_labels TEXT NOT NULL DEFAULT '[]',
			risk_level TEXT NOT NULL DEFAULT 'low',
			allowed BOOLEAN NOT NULL DEFAULT true,
			reason TEXT NOT NULL DEFAULT '',
			metadata TEXT NOT NULL DEFAULT '{}',
			occurred_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_activity_tenant_type ON activity_events(tenant_id, event_type)`,
		`CREATE INDEX IF NOT EXISTS idx_activity_tenant_risk ON activity_events(tenant_id, risk_level)`,
	}
	for _, stmt := range stmts {
		_, _ = s.db.SQL().ExecContext(ctx, stmt)
	}
}

// --- Events ---

func (s *SQLStore) IngestEvent(ctx context.Context, e ActivityEvent) (ActivityEvent, error) {
	labelsJSON, _ := json.Marshal(e.DataLabels)
	metaJSON, _ := json.Marshal(e.Metadata)
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO activity_events
    (id, tenant_id, event_type, source, actor, actor_ip, query, rows_affected,
     data_labels, risk_level, allowed, reason, metadata, occurred_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
`,
		e.ID, e.TenantID, e.EventType, e.Source, e.Actor, e.ActorIP,
		e.Query, e.RowsAffect, string(labelsJSON), e.RiskLevel, e.Allowed,
		e.Reason, string(metaJSON), e.OccurredAt.UTC(), e.CreatedAt.UTC(),
	)
	if err != nil {
		return ActivityEvent{}, err
	}
	return e, nil
}

func (s *SQLStore) QueryEvents(ctx context.Context, q ActivityQuery) ([]ActivityEvent, error) {
	query := `
SELECT id, tenant_id, event_type, source, actor, actor_ip, query, rows_affected,
       data_labels, risk_level, allowed, reason, metadata, occurred_at, created_at
FROM activity_events
WHERE tenant_id = $1`
	args := []interface{}{strings.TrimSpace(q.TenantID)}
	idx := 2

	if strings.TrimSpace(q.EventType) != "" {
		query += " AND event_type = $" + itoa(idx)
		args = append(args, strings.TrimSpace(q.EventType))
		idx++
	}
	if strings.TrimSpace(q.Source) != "" {
		query += " AND source = $" + itoa(idx)
		args = append(args, strings.TrimSpace(q.Source))
		idx++
	}
	if strings.TrimSpace(q.Actor) != "" {
		query += " AND actor = $" + itoa(idx)
		args = append(args, strings.TrimSpace(q.Actor))
		idx++
	}
	if strings.TrimSpace(q.RiskLevel) != "" {
		query += " AND risk_level = $" + itoa(idx)
		args = append(args, strings.TrimSpace(q.RiskLevel))
		idx++
	}
	if !q.Since.IsZero() {
		query += " AND occurred_at >= $" + itoa(idx)
		args = append(args, q.Since.UTC())
		idx++
	}
	query += " ORDER BY occurred_at DESC"
	limit := q.Limit
	if limit <= 0 {
		limit = 50
	}
	query += " LIMIT $" + itoa(idx)
	args = append(args, limit)
	idx++
	if q.Offset > 0 {
		query += " OFFSET $" + itoa(idx)
		args = append(args, q.Offset)
	}

	rows, err := s.db.SQL().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]ActivityEvent, 0)
	for rows.Next() {
		e, scanErr := scanEvent(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// --- Stats ---

func (s *SQLStore) GetStats(ctx context.Context, tenantID string) (ActivityStats, error) {
	tid := strings.TrimSpace(tenantID)
	stats := ActivityStats{
		TenantID:        tid,
		ByEventType:     make(map[string]int),
		ByRiskLevel:     make(map[string]int),
		HighRiskSources: []string{},
	}

	// Total and denied counts.
	_ = s.db.SQL().QueryRowContext(ctx, `
SELECT COUNT(*), SUM(CASE WHEN allowed = false THEN 1 ELSE 0 END)
FROM activity_events WHERE tenant_id = $1
`, tid).Scan(&stats.TotalEvents, &stats.DeniedEvents)

	// Unique actors.
	_ = s.db.SQL().QueryRowContext(ctx, `
SELECT COUNT(DISTINCT actor) FROM activity_events WHERE tenant_id = $1
`, tid).Scan(&stats.UniqueActors)

	// By event type.
	etRows, err := s.db.SQL().QueryContext(ctx, `
SELECT event_type, COUNT(*) FROM activity_events WHERE tenant_id = $1 GROUP BY event_type
`, tid)
	if err == nil {
		defer etRows.Close() //nolint:errcheck
		for etRows.Next() {
			var et string
			var cnt int
			if scanErr := etRows.Scan(&et, &cnt); scanErr == nil {
				stats.ByEventType[et] = cnt
			}
		}
	}

	// By risk level.
	rlRows, err := s.db.SQL().QueryContext(ctx, `
SELECT risk_level, COUNT(*) FROM activity_events WHERE tenant_id = $1 GROUP BY risk_level
`, tid)
	if err == nil {
		defer rlRows.Close() //nolint:errcheck
		for rlRows.Next() {
			var rl string
			var cnt int
			if scanErr := rlRows.Scan(&rl, &cnt); scanErr == nil {
				stats.ByRiskLevel[rl] = cnt
			}
		}
	}

	// High-risk sources (sources with any critical or high events).
	srcRows, err := s.db.SQL().QueryContext(ctx, `
SELECT DISTINCT source FROM activity_events
WHERE tenant_id = $1 AND risk_level IN ('high', 'critical')
ORDER BY source
`, tid)
	if err == nil {
		defer srcRows.Close() //nolint:errcheck
		for srcRows.Next() {
			var src string
			if scanErr := srcRows.Scan(&src); scanErr == nil && src != "" {
				stats.HighRiskSources = append(stats.HighRiskSources, src)
			}
		}
	}

	return stats, nil
}

// --- Actors ---

func (s *SQLStore) ListActors(ctx context.Context, tenantID string) ([]ActorSummary, error) {
	tid := strings.TrimSpace(tenantID)
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT actor,
       COUNT(*) AS event_count,
       SUM(CASE WHEN allowed = false THEN 1 ELSE 0 END) AS denied_count,
       MAX(occurred_at) AS last_seen
FROM activity_events
WHERE tenant_id = $1
GROUP BY actor
ORDER BY event_count DESC
`, tid)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]ActorSummary, 0)
	for rows.Next() {
		var a ActorSummary
		var lastSeenRaw interface{}
		if scanErr := rows.Scan(&a.Actor, &a.EventCount, &a.DeniedCount, &lastSeenRaw); scanErr != nil {
			return nil, scanErr
		}
		a.LastSeen = parseDAMTime(lastSeenRaw)
		out = append(out, a)
	}
	return out, rows.Err()
}

// --- Sources ---

func (s *SQLStore) ListSources(ctx context.Context, tenantID string) ([]SourceSummary, error) {
	tid := strings.TrimSpace(tenantID)
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT source,
       COUNT(*) AS event_count,
       SUM(CASE WHEN risk_level='critical' THEN 4
                WHEN risk_level='high' THEN 3
                WHEN risk_level='medium' THEN 2
                ELSE 1 END) AS risk_score,
       MAX(occurred_at) AS last_seen
FROM activity_events
WHERE tenant_id = $1
GROUP BY source
ORDER BY risk_score DESC
`, tid)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]SourceSummary, 0)
	for rows.Next() {
		var ss SourceSummary
		var lastSeenRaw interface{}
		if scanErr := rows.Scan(&ss.Source, &ss.EventCount, &ss.RiskScore, &lastSeenRaw); scanErr != nil {
			return nil, scanErr
		}
		ss.LastSeen = parseDAMTime(lastSeenRaw)
		out = append(out, ss)
	}
	return out, rows.Err()
}

// --- scan helpers ---

func scanEvent(row interface{ Scan(...interface{}) error }) (ActivityEvent, error) {
	var e ActivityEvent
	var dataLabelsRaw, metadataRaw string
	var occurredAtRaw, createdAtRaw interface{}
	err := row.Scan(
		&e.ID, &e.TenantID, &e.EventType, &e.Source, &e.Actor, &e.ActorIP,
		&e.Query, &e.RowsAffect, &dataLabelsRaw, &e.RiskLevel, &e.Allowed,
		&e.Reason, &metadataRaw, &occurredAtRaw, &createdAtRaw,
	)
	if err != nil {
		return ActivityEvent{}, err
	}
	e.OccurredAt = parseDAMTime(occurredAtRaw)
	e.CreatedAt = parseDAMTime(createdAtRaw)
	_ = json.Unmarshal([]byte(dataLabelsRaw), &e.DataLabels)
	_ = json.Unmarshal([]byte(metadataRaw), &e.Metadata)
	if e.DataLabels == nil {
		e.DataLabels = []string{}
	}
	if e.Metadata == nil {
		e.Metadata = map[string]interface{}{}
	}
	return e, nil
}

// --- utility ---

func parseDAMTime(v interface{}) time.Time {
	switch t := v.(type) {
	case time.Time:
		return t.UTC()
	case string:
		return parseDAMTimeString(t)
	case []byte:
		return parseDAMTimeString(string(t))
	default:
		return time.Time{}
	}
}

func parseDAMTimeString(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	formats := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
		"2006-01-02",
	}
	for _, f := range formats {
		if ts, err := time.Parse(f, s); err == nil {
			return ts.UTC()
		}
	}
	return time.Time{}
}

func newDAMID(prefix string) string {
	b := make([]byte, 8)
	_, _ = pkgcrypto.Reader.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

func itoa(n int) string {
	return strconv.Itoa(n)
}
