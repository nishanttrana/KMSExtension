package dltaudit

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const dltauditMigrationSQL = `
CREATE TABLE IF NOT EXISTS dltaudit_anchor_records (
	id TEXT PRIMARY KEY,
	merkle_root TEXT NOT NULL,
	tx_id TEXT NOT NULL,
	block_number INTEGER NOT NULL DEFAULT 0,
	event_count INTEGER NOT NULL,
	event_ids TEXT NOT NULL DEFAULT '[]',
	anchored_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_dltaudit_anchors_tx ON dltaudit_anchor_records(tx_id);

CREATE TABLE IF NOT EXISTS dltaudit_event_mappings (
	event_id TEXT PRIMARY KEY,
	anchor_id TEXT NOT NULL,
	leaf_index INTEGER NOT NULL,
	event_hash TEXT NOT NULL,
	merkle_proof TEXT NOT NULL DEFAULT '[]',
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_dltaudit_mappings_anchor ON dltaudit_event_mappings(anchor_id);
`

// EventMapping links an audit event to its anchor record and Merkle proof.
type EventMapping struct {
	EventID   string   `json:"event_id"`
	AnchorID  string   `json:"anchor_id"`
	LeafIndex int      `json:"leaf_index"`
	EventHash []byte   `json:"event_hash"`
	Proof     [][]byte `json:"proof"`
}

// SQLStore persists DLT anchor records and event mappings.
type SQLStore struct {
	db *sql.DB
}

// NewSQLStore creates a new DLT audit SQL store and runs migrations.
func NewSQLStore(db *sql.DB) (*SQLStore, error) {
	s := &SQLStore{db: db}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("dltaudit/store: migration failed: %w", err)
	}
	return s, nil
}

func (s *SQLStore) migrate() error {
	_, err := s.db.Exec(dltauditMigrationSQL)
	return err
}

// CreateAnchorRecord stores a new anchor record.
func (s *SQLStore) CreateAnchorRecord(ctx context.Context, record *AnchorRecord) error {
	eventIDsJSON, err := json.Marshal(record.EventIDs)
	if err != nil {
		eventIDsJSON = []byte("[]")
	}

	merkleRootHex := hex.EncodeToString(record.MerkleRoot)

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO dltaudit_anchor_records (id, merkle_root, tx_id, block_number, event_count, event_ids, anchored_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		record.ID, merkleRootHex, record.TxID, record.BlockNumber,
		record.EventCount, string(eventIDsJSON), record.AnchoredAt,
	)
	if err != nil {
		return fmt.Errorf("dltaudit/store: create anchor: %w", err)
	}
	return nil
}

// GetAnchorRecord retrieves an anchor record by ID.
func (s *SQLStore) GetAnchorRecord(ctx context.Context, id string) (*AnchorRecord, error) {
	var record AnchorRecord
	var merkleRootHex string
	var eventIDsJSON string

	err := s.db.QueryRowContext(ctx,
		`SELECT id, merkle_root, tx_id, block_number, event_count, event_ids, anchored_at
		 FROM dltaudit_anchor_records WHERE id = $1`, id).
		Scan(&record.ID, &merkleRootHex, &record.TxID, &record.BlockNumber,
			&record.EventCount, &eventIDsJSON, &record.AnchoredAt)
	if err != nil {
		return nil, fmt.Errorf("dltaudit/store: get anchor: %w", err)
	}

	record.MerkleRoot, _ = hex.DecodeString(merkleRootHex)
	_ = json.Unmarshal([]byte(eventIDsJSON), &record.EventIDs)

	return &record, nil
}

// GetAnchorRecordByTxID retrieves an anchor record by transaction ID.
func (s *SQLStore) GetAnchorRecordByTxID(ctx context.Context, txID string) (*AnchorRecord, error) {
	var record AnchorRecord
	var merkleRootHex string
	var eventIDsJSON string

	err := s.db.QueryRowContext(ctx,
		`SELECT id, merkle_root, tx_id, block_number, event_count, event_ids, anchored_at
		 FROM dltaudit_anchor_records WHERE tx_id = $1`, txID).
		Scan(&record.ID, &merkleRootHex, &record.TxID, &record.BlockNumber,
			&record.EventCount, &eventIDsJSON, &record.AnchoredAt)
	if err != nil {
		return nil, fmt.Errorf("dltaudit/store: get anchor by tx: %w", err)
	}

	record.MerkleRoot, _ = hex.DecodeString(merkleRootHex)
	_ = json.Unmarshal([]byte(eventIDsJSON), &record.EventIDs)

	return &record, nil
}

// ListAnchorRecords returns recent anchor records, newest first.
func (s *SQLStore) ListAnchorRecords(ctx context.Context, limit int) ([]AnchorRecord, error) {
	if limit <= 0 {
		limit = 100
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, merkle_root, tx_id, block_number, event_count, event_ids, anchored_at
		 FROM dltaudit_anchor_records ORDER BY anchored_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("dltaudit/store: list anchors: %w", err)
	}
	defer rows.Close()

	var records []AnchorRecord
	for rows.Next() {
		var r AnchorRecord
		var merkleRootHex, eventIDsJSON string
		if err := rows.Scan(&r.ID, &merkleRootHex, &r.TxID, &r.BlockNumber,
			&r.EventCount, &eventIDsJSON, &r.AnchoredAt); err != nil {
			return nil, fmt.Errorf("dltaudit/store: scan anchor: %w", err)
		}
		r.MerkleRoot, _ = hex.DecodeString(merkleRootHex)
		_ = json.Unmarshal([]byte(eventIDsJSON), &r.EventIDs)
		records = append(records, r)
	}
	return records, rows.Err()
}

// CreateEventMapping stores the mapping from an event to its anchor and Merkle proof.
func (s *SQLStore) CreateEventMapping(ctx context.Context, anchorID, eventID string, leafIndex int, eventHash []byte, proof [][]byte) error {
	hashHex := hex.EncodeToString(eventHash)

	// Encode proof as JSON array of hex strings
	proofHexes := make([]string, len(proof))
	for i, p := range proof {
		proofHexes[i] = hex.EncodeToString(p)
	}
	proofJSON, err := json.Marshal(proofHexes)
	if err != nil {
		proofJSON = []byte("[]")
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO dltaudit_event_mappings (event_id, anchor_id, leaf_index, event_hash, merkle_proof, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		eventID, anchorID, leafIndex, hashHex, string(proofJSON), time.Now(),
	)
	if err != nil {
		return fmt.Errorf("dltaudit/store: create event mapping: %w", err)
	}
	return nil
}

// GetEventMapping retrieves the anchor mapping for an audit event.
func (s *SQLStore) GetEventMapping(ctx context.Context, eventID string) (*EventMapping, error) {
	var m EventMapping
	var hashHex, proofJSON string

	err := s.db.QueryRowContext(ctx,
		`SELECT event_id, anchor_id, leaf_index, event_hash, merkle_proof
		 FROM dltaudit_event_mappings WHERE event_id = $1`, eventID).
		Scan(&m.EventID, &m.AnchorID, &m.LeafIndex, &hashHex, &proofJSON)
	if err != nil {
		return nil, fmt.Errorf("dltaudit/store: get event mapping: %w", err)
	}

	m.EventHash, _ = hex.DecodeString(hashHex)

	var proofHexes []string
	if err := json.Unmarshal([]byte(proofJSON), &proofHexes); err == nil {
		for _, ph := range proofHexes {
			b, _ := hex.DecodeString(strings.TrimSpace(ph))
			if len(b) > 0 {
				m.Proof = append(m.Proof, b)
			}
		}
	}

	return &m, nil
}
