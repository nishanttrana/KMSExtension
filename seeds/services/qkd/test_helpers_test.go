package main

import (
	"context"
	"sync"
	"testing"

	pkgdb "vecta-kms/pkg/db"
)

type nopQKDPublisher struct {
	mu       sync.Mutex
	subjects []string
}

func (p *nopQKDPublisher) Publish(_ context.Context, subject string, _ []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.subjects = append(p.subjects, subject)
	return nil
}

func (p *nopQKDPublisher) Count(subject string) int {
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

type fakeQKDKeyCore struct {
	mu      sync.Mutex
	counter int
	keys    map[string]string
}

func newFakeQKDKeyCore() *fakeQKDKeyCore {
	return &fakeQKDKeyCore{keys: map[string]string{}}
}

func (f *fakeQKDKeyCore) ImportAES256Key(_ context.Context, tenantID string, _ string, _ string, _ string, _ map[string]string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.counter++
	id := "keycore_" + strconvItoa(f.counter)
	f.keys[tenantID+":"+id] = "AES-256"
	return id, nil
}

func newQKDService(t *testing.T) (*Service, *SQLStore, *fakeQKDKeyCore, *nopQKDPublisher) {
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
	if err := createQKDSchemaForTest(conn); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	store := NewSQLStore(conn)
	keycore := newFakeQKDKeyCore()
	pub := &nopQKDPublisher{}
	mek := []byte("0123456789ABCDEF0123456789ABCDEF")
	svc := NewService(store, keycore, pub, mek)
	return svc, store, keycore, pub
}

func newQKDHandler(t *testing.T) (*Handler, *Service, *fakeQKDKeyCore, *nopQKDPublisher) {
	t.Helper()
	svc, _, keycore, pub := newQKDService(t)
	return NewHandler(svc), svc, keycore, pub
}

func createQKDSchemaForTest(conn *pkgdb.DB) error {
	stmts := []string{
		`CREATE TABLE qkd_config (
			tenant_id TEXT PRIMARY KEY,
			qber_threshold REAL NOT NULL DEFAULT 0.11,
			pool_low_threshold INTEGER NOT NULL DEFAULT 10,
			pool_capacity INTEGER NOT NULL DEFAULT 1250000,
			auto_inject BOOLEAN NOT NULL DEFAULT 0,
			service_enabled BOOLEAN NOT NULL DEFAULT 1,
			etsi_api_enabled BOOLEAN NOT NULL DEFAULT 1,
			protocol TEXT NOT NULL DEFAULT 'ETSI GS QKD 014',
			distance_km REAL NOT NULL DEFAULT 47,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE qkd_devices (
			id TEXT NOT NULL,
			tenant_id TEXT NOT NULL,
			name TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'peer',
			slave_sae_id TEXT NOT NULL,
			link_status TEXT NOT NULL DEFAULT 'up',
			key_rate REAL NOT NULL DEFAULT 0,
			qber_avg REAL NOT NULL DEFAULT 0,
			last_seen_at TIMESTAMP,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		);`,
		`CREATE TABLE qkd_keys (
			id TEXT NOT NULL,
			tenant_id TEXT NOT NULL,
			device_id TEXT NOT NULL,
			slave_sae_id TEXT NOT NULL,
			external_key_id TEXT NOT NULL DEFAULT '',
			key_size_bits INTEGER NOT NULL,
			qber REAL NOT NULL DEFAULT 0,
			status TEXT NOT NULL,
			keycore_key_id TEXT NOT NULL DEFAULT '',
			wrapped_dek BLOB NOT NULL,
			wrapped_dek_iv BLOB NOT NULL,
			ciphertext BLOB NOT NULL,
			data_iv BLOB NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			injected_at TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		);`,
		`CREATE TABLE qkd_sessions (
			id TEXT NOT NULL,
			tenant_id TEXT NOT NULL,
			device_id TEXT NOT NULL,
			slave_sae_id TEXT NOT NULL,
			app_id TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'open',
			opened_at TIMESTAMP NOT NULL,
			last_used_at TIMESTAMP,
			closed_at TIMESTAMP,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		);`,
		`CREATE TABLE qkd_logs (
			id TEXT NOT NULL,
			tenant_id TEXT NOT NULL,
			action TEXT NOT NULL,
			level TEXT NOT NULL DEFAULT 'info',
			message TEXT NOT NULL DEFAULT '',
			meta_json TEXT NOT NULL DEFAULT '{}',
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
