package main

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

func (s *SQLStore) ListAIProtectPolicies(ctx context.Context, tenantID string) ([]AIProtectPolicy, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, name, description, patterns_json, action, scope, enabled, created_at, updated_at
FROM ai_protect_policies
WHERE tenant_id = $1
ORDER BY created_at DESC
`, strings.TrimSpace(tenantID))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	out := make([]AIProtectPolicy, 0)
	for rows.Next() {
		item, err := scanAIProtectPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) CreateAIProtectPolicy(ctx context.Context, p AIProtectPolicy) (AIProtectPolicy, error) {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO ai_protect_policies (
	id, tenant_id, name, description, patterns_json, action, scope, enabled, created_at, updated_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP
)
`, p.ID, p.TenantID, p.Name, p.Description, mustJSON(p.Patterns, "[]"), p.Action, p.Scope, p.Enabled)
	if err != nil {
		return AIProtectPolicy{}, err
	}

	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, name, description, patterns_json, action, scope, enabled, created_at, updated_at
FROM ai_protect_policies
WHERE tenant_id = $1 AND id = $2
`, p.TenantID, p.ID)
	return scanAIProtectPolicy(row)
}

func (s *SQLStore) DeleteAIProtectPolicy(ctx context.Context, tenantID, id string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
DELETE FROM ai_protect_policies
WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) InsertAIProtectAuditEntry(ctx context.Context, e AIProtectAuditEntry) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO ai_protect_audit (
	id, tenant_id, action, finding_count, patterns_json, context, policy_id, created_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,CURRENT_TIMESTAMP
)
`, e.ID, e.TenantID, e.Action, e.FindingCount, mustJSON(e.Patterns, "[]"), e.Context, e.PolicyID)
	return err
}

func (s *SQLStore) ListAIProtectAuditEntries(ctx context.Context, tenantID string, limit int) ([]AIProtectAuditEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, action, finding_count, patterns_json, context, policy_id, created_at
FROM ai_protect_audit
WHERE tenant_id = $1
ORDER BY created_at DESC
LIMIT $2
`, strings.TrimSpace(tenantID), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	out := make([]AIProtectAuditEntry, 0)
	for rows.Next() {
		item, err := scanAIProtectAuditEntry(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func scanAIProtectPolicy(scanner interface {
	Scan(dest ...interface{}) error
}) (AIProtectPolicy, error) {
	var (
		item        AIProtectPolicy
		patternsJS  string
		createdRaw  interface{}
		updatedRaw  interface{}
	)
	if err := scanner.Scan(
		&item.ID,
		&item.TenantID,
		&item.Name,
		&item.Description,
		&patternsJS,
		&item.Action,
		&item.Scope,
		&item.Enabled,
		&createdRaw,
		&updatedRaw,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AIProtectPolicy{}, errNotFound
		}
		return AIProtectPolicy{}, err
	}
	item.Patterns = parseJSONArrayString(patternsJS)
	item.CreatedAt = parseTimeValue(createdRaw)
	item.UpdatedAt = parseTimeValue(updatedRaw)
	return item, nil
}

func scanAIProtectAuditEntry(scanner interface {
	Scan(dest ...interface{}) error
}) (AIProtectAuditEntry, error) {
	var (
		item       AIProtectAuditEntry
		patternsJS string
		createdRaw interface{}
	)
	if err := scanner.Scan(
		&item.ID,
		&item.TenantID,
		&item.Action,
		&item.FindingCount,
		&patternsJS,
		&item.Context,
		&item.PolicyID,
		&createdRaw,
	); err != nil {
		return AIProtectAuditEntry{}, err
	}
	item.Patterns = parseJSONArrayString(patternsJS)
	item.CreatedAt = parseTimeValue(createdRaw)
	return item, nil
}
