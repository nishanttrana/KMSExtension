package main

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
	pkgdb "vecta-kms/pkg/db"
)

var errNotFound = errors.New("not found")

// Store defines the storage interface for the TFE service.
type Store interface {
	// Agents
	CreateAgent(ctx context.Context, a TFEAgent) (TFEAgent, error)
	GetAgent(ctx context.Context, tenantID, id string) (TFEAgent, error)
	ListAgents(ctx context.Context, tenantID string) ([]TFEAgent, error)
	UpdateAgentHeartbeat(ctx context.Context, tenantID, id, status string, lastSeen time.Time) error
	DeleteAgent(ctx context.Context, tenantID, id string) error

	// Policies
	CreatePolicy(ctx context.Context, p TFEPolicy) (TFEPolicy, error)
	GetPolicy(ctx context.Context, tenantID, id string) (TFEPolicy, error)
	ListPolicies(ctx context.Context, tenantID, agentID string) ([]TFEPolicy, error)
	UpdatePolicy(ctx context.Context, tenantID, id string, req UpdateTFEPolicyRequest) (TFEPolicy, error)
	DeletePolicy(ctx context.Context, tenantID, id string) error

	// Summary
	GetSummary(ctx context.Context, tenantID string) (TFESummary, error)
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
		`CREATE TABLE IF NOT EXISTS tfe_agents (
			id TEXT NOT NULL,
			tenant_id TEXT NOT NULL,
			hostname TEXT NOT NULL,
			os TEXT NOT NULL DEFAULT 'linux',
			agent_version TEXT NOT NULL DEFAULT '1.0',
			status TEXT NOT NULL DEFAULT 'registered',
			last_seen TIMESTAMP,
			policy_count INTEGER NOT NULL DEFAULT 0,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		)`,
		`CREATE TABLE IF NOT EXISTS tfe_policies (
			id TEXT NOT NULL,
			tenant_id TEXT NOT NULL,
			agent_id TEXT NOT NULL,
			name TEXT NOT NULL,
			path TEXT NOT NULL,
			recursive BOOLEAN NOT NULL DEFAULT false,
			key_id TEXT NOT NULL DEFAULT '',
			algorithm TEXT NOT NULL DEFAULT 'AES-256-XTS',
			include_globs TEXT NOT NULL DEFAULT '[]',
			exclude_globs TEXT NOT NULL DEFAULT '[]',
			status TEXT NOT NULL DEFAULT 'active',
			files_encrypted INTEGER NOT NULL DEFAULT 0,
			last_activity TIMESTAMP,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		)`,
	}
	for _, stmt := range stmts {
		_, _ = s.db.SQL().ExecContext(ctx, stmt)
	}
}

// --- Agents ---

func (s *SQLStore) CreateAgent(ctx context.Context, a TFEAgent) (TFEAgent, error) {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO tfe_agents (id, tenant_id, hostname, os, agent_version, status, last_seen, policy_count, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
`,
		a.ID, a.TenantID, a.Hostname, a.OS, a.AgentVersion, a.Status,
		a.LastSeen.UTC(), a.PolicyCount, a.CreatedAt.UTC(),
	)
	if err != nil {
		return TFEAgent{}, err
	}
	return s.GetAgent(ctx, a.TenantID, a.ID)
}

func (s *SQLStore) GetAgent(ctx context.Context, tenantID, id string) (TFEAgent, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, hostname, os, agent_version, status, last_seen, policy_count, created_at
FROM tfe_agents
WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	a, err := scanAgent(row)
	if errors.Is(err, sql.ErrNoRows) {
		return TFEAgent{}, errNotFound
	}
	return a, err
}

func (s *SQLStore) ListAgents(ctx context.Context, tenantID string) ([]TFEAgent, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, hostname, os, agent_version, status, last_seen, policy_count, created_at
FROM tfe_agents
WHERE tenant_id = $1
ORDER BY created_at DESC
`, strings.TrimSpace(tenantID))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]TFEAgent, 0)
	for rows.Next() {
		a, scanErr := scanAgent(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpdateAgentHeartbeat(ctx context.Context, tenantID, id, status string, lastSeen time.Time) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE tfe_agents SET status = $1, last_seen = $2
WHERE tenant_id = $3 AND id = $4
`, strings.TrimSpace(status), lastSeen.UTC(), strings.TrimSpace(tenantID), strings.TrimSpace(id))
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) DeleteAgent(ctx context.Context, tenantID, id string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
DELETE FROM tfe_agents WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

// --- Policies ---

func (s *SQLStore) CreatePolicy(ctx context.Context, p TFEPolicy) (TFEPolicy, error) {
	includeJSON, _ := json.Marshal(p.IncludeGlobs)
	excludeJSON, _ := json.Marshal(p.ExcludeGlobs)
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO tfe_policies (id, tenant_id, agent_id, name, path, recursive, key_id, algorithm,
                          include_globs, exclude_globs, status, files_encrypted, last_activity, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
`,
		p.ID, p.TenantID, p.AgentID, p.Name, p.Path, p.Recursive, p.KeyID, p.Algorithm,
		string(includeJSON), string(excludeJSON), p.Status, p.FilesEncrypted,
		p.LastActivity.UTC(), p.CreatedAt.UTC(),
	)
	if err != nil {
		return TFEPolicy{}, err
	}
	return s.GetPolicy(ctx, p.TenantID, p.ID)
}

func (s *SQLStore) GetPolicy(ctx context.Context, tenantID, id string) (TFEPolicy, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, agent_id, name, path, recursive, key_id, algorithm,
       include_globs, exclude_globs, status, files_encrypted, last_activity, created_at
FROM tfe_policies
WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	p, err := scanPolicy(row)
	if errors.Is(err, sql.ErrNoRows) {
		return TFEPolicy{}, errNotFound
	}
	return p, err
}

func (s *SQLStore) ListPolicies(ctx context.Context, tenantID, agentID string) ([]TFEPolicy, error) {
	query := `
SELECT id, tenant_id, agent_id, name, path, recursive, key_id, algorithm,
       include_globs, exclude_globs, status, files_encrypted, last_activity, created_at
FROM tfe_policies
WHERE tenant_id = $1`
	args := []interface{}{strings.TrimSpace(tenantID)}
	if strings.TrimSpace(agentID) != "" {
		query += " AND agent_id = $2"
		args = append(args, strings.TrimSpace(agentID))
	}
	query += " ORDER BY created_at DESC"

	rows, err := s.db.SQL().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]TFEPolicy, 0)
	for rows.Next() {
		p, scanErr := scanPolicy(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpdatePolicy(ctx context.Context, tenantID, id string, req UpdateTFEPolicyRequest) (TFEPolicy, error) {
	existing, err := s.GetPolicy(ctx, tenantID, id)
	if err != nil {
		return TFEPolicy{}, err
	}
	if req.Status != nil {
		existing.Status = *req.Status
	}
	if req.Path != nil {
		existing.Path = *req.Path
	}
	if req.KeyID != nil {
		existing.KeyID = *req.KeyID
	}
	if req.Recursive != nil {
		existing.Recursive = *req.Recursive
	}
	if req.Algorithm != nil {
		existing.Algorithm = *req.Algorithm
	}
	if req.IncludeGlobs != nil {
		existing.IncludeGlobs = *req.IncludeGlobs
	}
	if req.ExcludeGlobs != nil {
		existing.ExcludeGlobs = *req.ExcludeGlobs
	}
	includeJSON, _ := json.Marshal(existing.IncludeGlobs)
	excludeJSON, _ := json.Marshal(existing.ExcludeGlobs)
	_, err = s.db.SQL().ExecContext(ctx, `
UPDATE tfe_policies
SET status = $1, path = $2, key_id = $3, recursive = $4, algorithm = $5,
    include_globs = $6, exclude_globs = $7
WHERE tenant_id = $8 AND id = $9
`,
		existing.Status, existing.Path, existing.KeyID, existing.Recursive, existing.Algorithm,
		string(includeJSON), string(excludeJSON),
		strings.TrimSpace(tenantID), strings.TrimSpace(id),
	)
	if err != nil {
		return TFEPolicy{}, err
	}
	return s.GetPolicy(ctx, tenantID, id)
}

func (s *SQLStore) DeletePolicy(ctx context.Context, tenantID, id string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
DELETE FROM tfe_policies WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

// --- Summary ---

func (s *SQLStore) GetSummary(ctx context.Context, tenantID string) (TFESummary, error) {
	sum := TFESummary{
		ByOS:     make(map[string]int),
		ByStatus: make(map[string]int),
	}
	tid := strings.TrimSpace(tenantID)

	// Total agents and active agents.
	_ = s.db.SQL().QueryRowContext(ctx, `
SELECT COUNT(*), SUM(CASE WHEN status='active' THEN 1 ELSE 0 END)
FROM tfe_agents WHERE tenant_id = $1
`, tid).Scan(&sum.TotalAgents, &sum.ActiveAgents)

	// Total policies.
	_ = s.db.SQL().QueryRowContext(ctx, `
SELECT COUNT(*), COALESCE(SUM(files_encrypted), 0) FROM tfe_policies WHERE tenant_id = $1
`, tid).Scan(&sum.TotalPolicies, &sum.TotalEncrypted)

	// By OS.
	osRows, err := s.db.SQL().QueryContext(ctx, `
SELECT os, COUNT(*) FROM tfe_agents WHERE tenant_id = $1 GROUP BY os
`, tid)
	if err == nil {
		defer osRows.Close() //nolint:errcheck
		for osRows.Next() {
			var osName string
			var cnt int
			if scanErr := osRows.Scan(&osName, &cnt); scanErr == nil {
				sum.ByOS[osName] = cnt
			}
		}
	}

	// By status.
	stRows, err := s.db.SQL().QueryContext(ctx, `
SELECT status, COUNT(*) FROM tfe_agents WHERE tenant_id = $1 GROUP BY status
`, tid)
	if err == nil {
		defer stRows.Close() //nolint:errcheck
		for stRows.Next() {
			var st string
			var cnt int
			if scanErr := stRows.Scan(&st, &cnt); scanErr == nil {
				sum.ByStatus[st] = cnt
			}
		}
	}

	return sum, nil
}

// --- scan helpers ---

func scanAgent(row interface{ Scan(...interface{}) error }) (TFEAgent, error) {
	var a TFEAgent
	var lastSeenRaw, createdAtRaw interface{}
	err := row.Scan(
		&a.ID, &a.TenantID, &a.Hostname, &a.OS, &a.AgentVersion,
		&a.Status, &lastSeenRaw, &a.PolicyCount, &createdAtRaw,
	)
	if err != nil {
		return TFEAgent{}, err
	}
	a.CreatedAt = parseTFETime(createdAtRaw)
	a.LastSeen = parseTFETime(lastSeenRaw)
	return a, nil
}

func scanPolicy(row interface{ Scan(...interface{}) error }) (TFEPolicy, error) {
	var p TFEPolicy
	var includeGlobsRaw, excludeGlobsRaw string
	var lastActivityRaw, createdAtRaw interface{}
	err := row.Scan(
		&p.ID, &p.TenantID, &p.AgentID, &p.Name, &p.Path, &p.Recursive,
		&p.KeyID, &p.Algorithm, &includeGlobsRaw, &excludeGlobsRaw,
		&p.Status, &p.FilesEncrypted, &lastActivityRaw, &createdAtRaw,
	)
	if err != nil {
		return TFEPolicy{}, err
	}
	p.CreatedAt = parseTFETime(createdAtRaw)
	p.LastActivity = parseTFETime(lastActivityRaw)
	_ = json.Unmarshal([]byte(includeGlobsRaw), &p.IncludeGlobs)
	_ = json.Unmarshal([]byte(excludeGlobsRaw), &p.ExcludeGlobs)
	if p.IncludeGlobs == nil {
		p.IncludeGlobs = []string{}
	}
	if p.ExcludeGlobs == nil {
		p.ExcludeGlobs = []string{}
	}
	return p, nil
}

// --- utility ---

func parseTFETime(v interface{}) time.Time {
	switch t := v.(type) {
	case time.Time:
		return t.UTC()
	case string:
		return parseTFETimeString(t)
	case []byte:
		return parseTFETimeString(string(t))
	default:
		return time.Time{}
	}
}

func parseTFETimeString(s string) time.Time {
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

func newTFEID(prefix string) string {
	b := make([]byte, 8)
	_, _ = pkgcrypto.Reader.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}
