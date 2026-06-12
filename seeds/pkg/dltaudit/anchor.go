package dltaudit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"time"
)

// Backend is the interface for blockchain/DLT submission and verification.
type Backend interface {
	// Submit anchors a hash on the distributed ledger and returns the transaction ID.
	Submit(ctx context.Context, hash []byte, metadata map[string]string) (txID string, err error)
	// Verify checks that the given hash was anchored in the specified transaction.
	Verify(ctx context.Context, txID string, expectedHash []byte) (bool, error)
}

// AuditEvent represents a single audit log entry to be anchored.
type AuditEvent struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
	ActorID   string    `json:"actor_id"`
	Resource  string    `json:"resource"`
	Detail    string    `json:"detail"`
	Hash      []byte    `json:"hash"`
}

// AnchorRecord represents a batch of events anchored to a DLT.
type AnchorRecord struct {
	ID          string    `json:"id"`
	MerkleRoot  []byte    `json:"merkle_root"`
	TxID        string    `json:"tx_id"`
	BlockNumber uint64    `json:"block_number"`
	EventCount  int       `json:"event_count"`
	EventIDs    []string  `json:"event_ids"`
	AnchoredAt  time.Time `json:"anchored_at"`
}

// VerificationResult contains the outcome of verifying an event against its anchor.
type VerificationResult struct {
	Verified     bool         `json:"verified"`
	MerkleProof  [][]byte     `json:"merkle_proof"`
	AnchorRecord *AnchorRecord `json:"anchor_record"`
	TxID         string       `json:"tx_id"`
	EventHash    []byte       `json:"event_hash"`
}

// EventCollector provides audit events that have not yet been anchored.
type EventCollector interface {
	// CollectUnanchored returns audit events that haven't been anchored yet.
	CollectUnanchored(ctx context.Context) ([]AuditEvent, error)
	// MarkAnchored marks events as anchored with the given anchor record ID.
	MarkAnchored(ctx context.Context, eventIDs []string, anchorID string) error
}

// Anchor manages the anchoring of audit events to a distributed ledger.
type Anchor struct {
	backend       Backend
	store         *SQLStore
	collector     EventCollector
	batchInterval time.Duration
	logf          func(string, ...interface{})
}

// NewAnchor creates a new DLT audit anchor.
func NewAnchor(backend Backend, store *SQLStore, collector EventCollector, batchInterval time.Duration, logf func(string, ...interface{})) *Anchor {
	if batchInterval <= 0 {
		batchInterval = 60 * time.Second
	}
	if logf == nil {
		logf = log.Printf
	}
	return &Anchor{
		backend:       backend,
		store:         store,
		collector:     collector,
		batchInterval: batchInterval,
		logf:          logf,
	}
}

// Start runs a background goroutine that periodically collects and anchors audit events.
func (a *Anchor) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(a.batchInterval)
		defer ticker.Stop()

		a.logf("[dltaudit] anchor loop started (interval=%s)", a.batchInterval)
		for {
			select {
			case <-ctx.Done():
				a.logf("[dltaudit] anchor loop stopped")
				return
			case <-ticker.C:
				a.anchorCycle(ctx)
			}
		}
	}()
}

// anchorCycle collects unanchored events and anchors them.
func (a *Anchor) anchorCycle(ctx context.Context) {
	if a.collector == nil {
		return
	}

	events, err := a.collector.CollectUnanchored(ctx)
	if err != nil {
		a.logf("[dltaudit] collect unanchored events: %v", err)
		return
	}

	if len(events) == 0 {
		return
	}

	record, err := a.AnchorBatch(ctx, events)
	if err != nil {
		a.logf("[dltaudit] anchor batch failed: %v", err)
		return
	}

	// Mark events as anchored
	var eventIDs []string
	for _, e := range events {
		eventIDs = append(eventIDs, e.ID)
	}
	if err := a.collector.MarkAnchored(ctx, eventIDs, record.ID); err != nil {
		a.logf("[dltaudit] mark anchored failed: %v", err)
	}

	a.logf("[dltaudit] anchored %d events, tx=%s merkle_root=%x", len(events), record.TxID, record.MerkleRoot)
}

// AnchorBatch manually anchors a batch of audit events to the DLT.
func (a *Anchor) AnchorBatch(ctx context.Context, events []AuditEvent) (*AnchorRecord, error) {
	if len(events) == 0 {
		return nil, fmt.Errorf("dltaudit: no events to anchor")
	}

	// Build event hashes
	hashes := make([][]byte, len(events))
	eventIDs := make([]string, len(events))
	for i, event := range events {
		if len(event.Hash) > 0 {
			hashes[i] = event.Hash
		} else {
			hashes[i] = HashEvent(event.ID, []byte(event.Detail))
		}
		eventIDs[i] = event.ID
	}

	// Build Merkle tree
	merkleRoot, tree := BuildMerkleTree(hashes)
	if merkleRoot == nil {
		return nil, fmt.Errorf("dltaudit: failed to build merkle tree")
	}

	// Submit Merkle root to blockchain backend
	metadata := map[string]string{
		"event_count": fmt.Sprintf("%d", len(events)),
		"batch_time":  time.Now().UTC().Format(time.RFC3339),
	}

	txID, err := a.backend.Submit(ctx, merkleRoot, metadata)
	if err != nil {
		return nil, fmt.Errorf("dltaudit: submit to backend: %w", err)
	}

	record := &AnchorRecord{
		ID:         generateID(),
		MerkleRoot: merkleRoot,
		TxID:       txID,
		EventCount: len(events),
		EventIDs:   eventIDs,
		AnchoredAt: time.Now(),
	}

	// Store anchor record and the tree for later proof generation
	if err := a.store.CreateAnchorRecord(ctx, record); err != nil {
		return nil, fmt.Errorf("dltaudit: store anchor record: %w", err)
	}

	// Store individual event-to-anchor mappings with their position in the tree
	for i, eventID := range eventIDs {
		proof := GenerateProof(tree, i)
		if err := a.store.CreateEventMapping(ctx, record.ID, eventID, i, hashes[i], proof); err != nil {
			a.logf("[dltaudit] store event mapping failed for %s: %v", eventID, err)
		}
	}

	return record, nil
}

// VerifyEvent proves that a specific audit event is included in an anchored Merkle tree
// and that the Merkle root was submitted to the blockchain.
func (a *Anchor) VerifyEvent(ctx context.Context, eventID string) (*VerificationResult, error) {
	// Look up the event mapping
	mapping, err := a.store.GetEventMapping(ctx, eventID)
	if err != nil {
		return nil, fmt.Errorf("dltaudit: get event mapping: %w", err)
	}

	// Get the anchor record
	record, err := a.store.GetAnchorRecord(ctx, mapping.AnchorID)
	if err != nil {
		return nil, fmt.Errorf("dltaudit: get anchor record: %w", err)
	}

	// Verify Merkle proof locally
	proofValid := VerifyProof(record.MerkleRoot, mapping.EventHash, mapping.Proof, mapping.LeafIndex)

	// Verify on blockchain
	blockchainValid, err := a.backend.Verify(ctx, record.TxID, record.MerkleRoot)
	if err != nil {
		return &VerificationResult{
			Verified:     false,
			MerkleProof:  mapping.Proof,
			AnchorRecord: record,
			TxID:         record.TxID,
			EventHash:    mapping.EventHash,
		}, fmt.Errorf("dltaudit: blockchain verification failed: %w", err)
	}

	return &VerificationResult{
		Verified:     proofValid && blockchainValid,
		MerkleProof:  mapping.Proof,
		AnchorRecord: record,
		TxID:         record.TxID,
		EventHash:    mapping.EventHash,
	}, nil
}

func generateID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
