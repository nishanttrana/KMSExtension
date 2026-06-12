package main

import "time"

const (
	SourceStatusActive  = "active"
	SourceStatusPaused  = "paused"
	SourceStatusError   = "error"
	SourceStatusRemoved = "removed"

	SourceModePush = "push"
	SourceModePull = "pull"

	// NIST SP 800-90B minimum acceptable min-entropy in bits-per-byte
	MinAcceptableEntropyBPB = 7.0
	MaxBiasScore            = 0.05
	MaxIngestBytes          = 4096
	MinIngestBytes          = 32
)

type QRNGSource struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	Name          string    `json:"name"`
	Vendor        string    `json:"vendor"`
	Endpoint      string    `json:"endpoint,omitempty"`
	AuthToken     string    `json:"-"`
	Mode          string    `json:"mode"`
	Status        string    `json:"status"`
	MinEntropyBPB float64   `json:"min_entropy_bpb"`
	PullIntervalS int       `json:"pull_interval_s"`
	LastSeenAt    time.Time `json:"last_seen_at"`
	LastError     string    `json:"last_error,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type QRNGPoolSample struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	SourceID     string    `json:"source_id"`
	SampleHash   string    `json:"sample_hash"`
	ByteCount    int       `json:"byte_count"`
	EntropyBPB   float64   `json:"entropy_bpb"`
	BiasScore    float64   `json:"bias_score"`
	PassedHealth bool      `json:"passed_health"`
	Consumed     bool      `json:"consumed"`
	ConsumedAt   time.Time `json:"consumed_at,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

type QRNGHealthEvent struct {
	ID         string                 `json:"id"`
	TenantID   string                 `json:"tenant_id"`
	SourceID   string                 `json:"source_id,omitempty"`
	CheckType  string                 `json:"check_type"`
	Result     string                 `json:"result"`
	EntropyBPB float64                `json:"entropy_bpb,omitempty"`
	Detail     map[string]interface{} `json:"detail,omitempty"`
	CreatedAt  time.Time              `json:"created_at"`
}

type QRNGPoolStatus struct {
	TenantID          string    `json:"tenant_id"`
	TotalSamples      int       `json:"total_samples"`
	AvailableSamples  int       `json:"available_samples"`
	ConsumedSamples   int       `json:"consumed_samples"`
	AvgEntropyBPB     float64   `json:"avg_entropy_bpb"`
	PoolHealthy       bool      `json:"pool_healthy"`
	LastIngestAt      time.Time `json:"last_ingest_at"`
	ActiveSourceCount int       `json:"active_source_count"`
}

// ── Requests / Responses ─────────────────────────────────────

type RegisterSourceRequest struct {
	TenantID      string  `json:"tenant_id"`
	Name          string  `json:"name"`
	Vendor        string  `json:"vendor"`
	Endpoint      string  `json:"endpoint"`
	AuthToken     string  `json:"auth_token"`
	Mode          string  `json:"mode"`
	MinEntropyBPB float64 `json:"min_entropy_bpb"`
	PullIntervalS int     `json:"pull_interval_s"`
}

type IngestRequest struct {
	TenantID   string `json:"tenant_id"`
	SourceID   string `json:"source_id"`
	EntropyB64 string `json:"entropy"`
}

type IngestResponse struct {
	SampleID     string  `json:"sample_id"`
	ByteCount    int     `json:"byte_count"`
	EntropyBPB   float64 `json:"entropy_bpb"`
	Accepted     bool    `json:"accepted"`
	RejectReason string  `json:"reject_reason,omitempty"`
}

type DrawRequest struct {
	TenantID string `json:"tenant_id"`
	Bytes    int    `json:"bytes"`
}

type DrawResponse struct {
	EntropyB64 string  `json:"entropy"`
	ByteCount  int     `json:"byte_count"`
	SourceID   string  `json:"source_id"`
	EntropyBPB float64 `json:"entropy_bpb"`
}

type QRNGOverview struct {
	TenantID string         `json:"tenant_id"`
	Pool     QRNGPoolStatus `json:"pool"`
	Sources  []QRNGSource   `json:"sources"`
}
