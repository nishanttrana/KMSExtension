package main

import "time"

// ActivityEvent represents a single monitored data activity event.
type ActivityEvent struct {
	ID          string                 `json:"id"`
	TenantID    string                 `json:"tenant_id"`
	EventType   string                 `json:"event_type"` // db_query, db_write, file_read, file_write, file_delete
	Source      string                 `json:"source"`     // database name or file path
	Actor       string                 `json:"actor"`      // user/service/role
	ActorIP     string                 `json:"actor_ip"`
	Query       string                 `json:"query,omitempty"`        // SQL query (sanitized)
	RowsAffect  int                    `json:"rows_affected,omitempty"`
	DataLabels  []string               `json:"data_labels"` // PII, PAN, PHI, etc.
	RiskLevel   string                 `json:"risk_level"`  // low, medium, high, critical
	Allowed     bool                   `json:"allowed"`
	Reason      string                 `json:"reason,omitempty"` // if denied
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	OccurredAt  time.Time              `json:"occurred_at"`
	CreatedAt   time.Time              `json:"created_at"`
}

// ActivityQuery holds query parameters for filtering activity events.
type ActivityQuery struct {
	TenantID  string
	EventType string
	Source    string
	Actor     string
	RiskLevel string
	Limit     int
	Offset    int
	Since     time.Time
}

// ActivityStats contains aggregated statistics for activity events.
type ActivityStats struct {
	TenantID        string         `json:"tenant_id"`
	TotalEvents     int64          `json:"total_events"`
	ByEventType     map[string]int `json:"by_event_type"`
	ByRiskLevel     map[string]int `json:"by_risk_level"`
	DeniedEvents    int64          `json:"denied_events"`
	UniqueActors    int            `json:"unique_actors"`
	HighRiskSources []string       `json:"high_risk_sources"`
}

// ActorSummary holds event counts for a single actor.
type ActorSummary struct {
	Actor      string `json:"actor"`
	EventCount int    `json:"event_count"`
	DeniedCount int   `json:"denied_count"`
	LastSeen   time.Time `json:"last_seen"`
}

// SourceSummary holds risk information for a single monitored source.
type SourceSummary struct {
	Source     string `json:"source"`
	EventCount int    `json:"event_count"`
	RiskScore  int    `json:"risk_score"`
	LastSeen   time.Time `json:"last_seen"`
}

// IngestEventRequest is the request body for ingesting an activity event.
type IngestEventRequest struct {
	TenantID   string                 `json:"tenant_id"`
	EventType  string                 `json:"event_type"`
	Source     string                 `json:"source"`
	Actor      string                 `json:"actor"`
	ActorIP    string                 `json:"actor_ip"`
	Query      string                 `json:"query"`
	RowsAffect int                    `json:"rows_affected"`
	DataLabels []string               `json:"data_labels"`
	RiskLevel  string                 `json:"risk_level"`
	Allowed    bool                   `json:"allowed"`
	Reason     string                 `json:"reason"`
	Metadata   map[string]interface{} `json:"metadata"`
	OccurredAt time.Time              `json:"occurred_at"`
}
