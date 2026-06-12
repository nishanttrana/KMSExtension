package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	pkgdb "vecta-kms/pkg/db"
)

type nopAIPublisher struct {
	mu       sync.Mutex
	subjects []string
}

func (p *nopAIPublisher) Publish(_ context.Context, subject string, _ []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.subjects = append(p.subjects, subject)
	return nil
}

func (p *nopAIPublisher) Count(subject string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, s := range p.subjects {
		if s == subject {
			n++
		}
	}
	return n
}

type fakeAIKeyCore struct {
	items []map[string]interface{}
	err   error
}

func (f *fakeAIKeyCore) ListKeys(_ context.Context, _ string, _ int) ([]map[string]interface{}, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.items, nil
}

type fakeAIPolicy struct {
	items []map[string]interface{}
	err   error
}

func (f *fakeAIPolicy) ListPolicies(_ context.Context, _ string, _ int) ([]map[string]interface{}, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.items, nil
}

type fakeAIAudit struct {
	items []map[string]interface{}
	err   error
}

func (f *fakeAIAudit) ListEvents(_ context.Context, _ string, _ int) ([]map[string]interface{}, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.items, nil
}

type fakeAICompliance struct {
	item map[string]interface{}
	err  error
}

func (f *fakeAICompliance) GetPosture(_ context.Context, _ string) (map[string]interface{}, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.item, nil
}

type fakeAIReporting struct {
	items []map[string]interface{}
	err   error
}

func (f *fakeAIReporting) ListAlerts(_ context.Context, _ string, _ int) ([]map[string]interface{}, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.items, nil
}

type fakeAISecrets struct {
	value string
	err   error
}

func (f *fakeAISecrets) GetSecretValue(_ context.Context, _ string, _ string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return f.value, nil
}

type fakeAILLM struct {
	text string
	err  error
}

func (f *fakeAILLM) Generate(_ context.Context, _ AIConfig, _ string, _ string) (LLMResult, error) {
	if f.err != nil {
		return LLMResult{}, f.err
	}
	return LLMResult{Text: f.text}, nil
}

func newAIService(t *testing.T) (*Service, *SQLStore, *fakeAILLM, *nopAIPublisher) {
	t.Helper()
	conn, err := pkgdb.Open(context.Background(), pkgdb.Config{
		UseSQLite:  true,
		SQLitePath: ":memory:",
		MaxOpen:    1,
		MaxIdle:    1,
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := createAISchemaForTest(conn); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	store := NewSQLStore(conn)
	llm := &fakeAILLM{text: "analysis complete"}
	pub := &nopAIPublisher{}
	svc := NewService(
		store,
		&fakeAIKeyCore{items: []map[string]interface{}{
			{"id": "k1", "name": "primary", "algorithm": "AES-256", "status": "active", "encrypted_material": "deadbeef"},
		}},
		&fakeAIPolicy{items: []map[string]interface{}{
			{"id": "p1", "name": "rotate-90d", "status": "active"},
		}},
		&fakeAIAudit{items: []map[string]interface{}{
			{"id": "e1", "action": "key.created", "timestamp": time.Now().UTC().Format(time.RFC3339)},
		}},
		&fakeAICompliance{item: map[string]interface{}{"overall_score": 78}},
		&fakeAIReporting{items: []map[string]interface{}{
			{"id": "a1", "status": "new", "title": "test"},
			{"id": "a2", "status": "resolved", "title": "old"},
		}},
		&fakeAISecrets{value: "sk-test-key"},
		llm,
		pub,
	)
	return svc, store, llm, pub
}

func newAIHandler(t *testing.T) (*Handler, *Service, *fakeAILLM, *nopAIPublisher) {
	t.Helper()
	svc, _, llm, pub := newAIService(t)
	return NewHandler(svc), svc, llm, pub
}

func createAISchemaForTest(conn *pkgdb.DB) error {
	stmts := []string{
		`CREATE TABLE ai_configs (
			tenant_id TEXT PRIMARY KEY,
			backend TEXT NOT NULL DEFAULT 'claude',
			endpoint TEXT NOT NULL DEFAULT '',
			model TEXT NOT NULL DEFAULT 'claude-sonnet-4-20250514',
			api_key_secret TEXT NOT NULL DEFAULT 'ai-api-key',
			auth_json TEXT NOT NULL DEFAULT '{}',
			mcp_json TEXT NOT NULL DEFAULT '{}',
			max_context_tokens INTEGER NOT NULL DEFAULT 100000,
			temperature REAL NOT NULL DEFAULT 0.1,
			context_sources_json TEXT NOT NULL DEFAULT '{}',
			redaction_fields_json TEXT NOT NULL DEFAULT '[]',
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE ai_interactions (
			tenant_id TEXT NOT NULL,
			id TEXT NOT NULL,
			action TEXT NOT NULL,
			request_json TEXT NOT NULL DEFAULT '{}',
			context_summary_json TEXT NOT NULL DEFAULT '{}',
			response_json TEXT NOT NULL DEFAULT '{}',
			redaction_count INTEGER NOT NULL DEFAULT 0,
			backend TEXT NOT NULL DEFAULT '',
			model TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		);`,
	}
	for _, stmt := range stmts {
		if _, err := conn.SQL().Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

func errUnavailable() error {
	return errors.New("unavailable")
}
