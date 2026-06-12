package main

import (
	"context"
	"sync"
	"testing"

	pkgdb "vecta-kms/pkg/db"
)

type nopMPCPublisher struct {
	mu       sync.Mutex
	subjects []string
}

func (p *nopMPCPublisher) Publish(_ context.Context, subject string, _ []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.subjects = append(p.subjects, subject)
	return nil
}

func (p *nopMPCPublisher) Count(subject string) int {
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

type fakeMPCKeyCore struct {
	items map[string]map[string]interface{}
}

func (f *fakeMPCKeyCore) GetKey(_ context.Context, _ string, keyID string) (map[string]interface{}, error) {
	if item, ok := f.items[keyID]; ok {
		return item, nil
	}
	return map[string]interface{}{}, nil
}

type fakeMPCCluster struct {
	members []string
}

func (f *fakeMPCCluster) ListMembers(_ context.Context) ([]string, error) {
	return append([]string{}, f.members...), nil
}

func newMPCService(t *testing.T) (*Service, *SQLStore, *nopMPCPublisher) {
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
	if err := createMPCSchemaForTest(conn); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	store := NewSQLStore(conn)
	pub := &nopMPCPublisher{}
	svc := NewService(
		store,
		&fakeMPCKeyCore{items: map[string]map[string]interface{}{
			"kc-1": {"id": "kc-1", "algorithm": "AES-256"},
		}},
		&fakeMPCCluster{members: []string{"node-1", "node-2", "node-3"}},
		pub,
	)
	return svc, store, pub
}

func newMPCHandler(t *testing.T) (*Handler, *Service, *nopMPCPublisher) {
	t.Helper()
	svc, _, pub := newMPCService(t)
	return NewHandler(svc), svc, pub
}

func createMPCSchemaForTest(conn *pkgdb.DB) error {
	stmts := []string{
		`CREATE TABLE mpc_keys (
			tenant_id TEXT NOT NULL,
			id TEXT NOT NULL,
			name TEXT NOT NULL DEFAULT 'mpc-key',
			algorithm TEXT NOT NULL,
			threshold INTEGER NOT NULL,
			participant_count INTEGER NOT NULL,
			participants_json TEXT NOT NULL DEFAULT '[]',
			keycore_key_id TEXT NOT NULL DEFAULT '',
			public_commitments_json TEXT NOT NULL DEFAULT '[]',
			status TEXT NOT NULL DEFAULT 'pending_dkg',
			share_version INTEGER NOT NULL DEFAULT 1,
			metadata_json TEXT NOT NULL DEFAULT '{}',
			key_group TEXT NOT NULL DEFAULT '',
			expires_at TIMESTAMP,
			revoked_at TIMESTAMP,
			revocation_reason TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_rotated_at TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		);`,
		`CREATE TABLE mpc_shares (
			tenant_id TEXT NOT NULL,
			key_id TEXT NOT NULL,
			id TEXT NOT NULL,
			node_id TEXT NOT NULL,
			share_x INTEGER NOT NULL,
			share_y_value TEXT NOT NULL,
			share_y_hash TEXT NOT NULL,
			share_version INTEGER NOT NULL DEFAULT 1,
			status TEXT NOT NULL DEFAULT 'active',
			metadata_json TEXT NOT NULL DEFAULT '{}',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			refreshed_at TIMESTAMP,
			last_backup_at TIMESTAMP,
			backup_artifact TEXT NOT NULL DEFAULT '',
			PRIMARY KEY (tenant_id, key_id, id)
		);`,
		`CREATE TABLE mpc_ceremonies (
			tenant_id TEXT NOT NULL,
			id TEXT NOT NULL,
			type TEXT NOT NULL,
			key_id TEXT NOT NULL DEFAULT '',
			algorithm TEXT NOT NULL DEFAULT '',
			threshold INTEGER NOT NULL DEFAULT 2,
			participant_count INTEGER NOT NULL DEFAULT 0,
			participants_json TEXT NOT NULL DEFAULT '[]',
			message_hash TEXT NOT NULL DEFAULT '',
			ciphertext TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'pending',
			result_json TEXT NOT NULL DEFAULT '{}',
			created_by TEXT NOT NULL DEFAULT '',
			required_contributors INTEGER NOT NULL DEFAULT 2,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			completed_at TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		);`,
		`CREATE TABLE mpc_contributions (
			tenant_id TEXT NOT NULL,
			ceremony_id TEXT NOT NULL,
			party_id TEXT NOT NULL,
			payload_json TEXT NOT NULL DEFAULT '{}',
			submitted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, ceremony_id, party_id)
		);`,
	}
	for _, stmt := range stmts {
		if _, err := conn.SQL().Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}
