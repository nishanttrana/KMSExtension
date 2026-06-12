package main

import (
	"context"
	"time"
)

type EventPublisher interface {
	Publish(ctx context.Context, subject string, payload []byte) error
}

type KeyCoreClient interface {
	GetKey(ctx context.Context, tenantID string, keyID string) (map[string]interface{}, error)
}

type ClusterClient interface {
	ListMembers(ctx context.Context) ([]string, error)
}

type Store interface {
	CreateMPCKey(ctx context.Context, item MPCKey) error
	UpdateMPCKey(ctx context.Context, item MPCKey) error
	GetMPCKey(ctx context.Context, tenantID string, id string) (MPCKey, error)
	ListMPCKeys(ctx context.Context, tenantID string, limit int, offset int) ([]MPCKey, error)
	RevokeKey(ctx context.Context, tenantID string, id string, reason string, revokedAt interface{}) error
	SetKeyGroup(ctx context.Context, tenantID string, id string, group string) error

	ReplaceShares(ctx context.Context, tenantID string, keyID string, shares []MPCShare, oldStatus string) error
	ListShares(ctx context.Context, tenantID string, keyID string) ([]MPCShare, error)
	ListSharesByNode(ctx context.Context, tenantID string, nodeID string, limit int) ([]MPCShare, error)
	GetShare(ctx context.Context, tenantID string, keyID string, nodeID string) (MPCShare, error)
	MarkShareBackup(ctx context.Context, tenantID string, keyID string, nodeID string, artifact string) error
	UpdateShareStatus(ctx context.Context, tenantID string, keyID string, status string) error

	CreateCeremony(ctx context.Context, item MPCCeremony) error
	UpdateCeremony(ctx context.Context, item MPCCeremony) error
	GetCeremony(ctx context.Context, tenantID string, id string) (MPCCeremony, error)
	ListCeremonies(ctx context.Context, tenantID string, filter CeremonyFilter, limit int) ([]MPCCeremony, error)
	ListCeremonyContributions(ctx context.Context, tenantID string, ceremonyID string) ([]MPCContribution, error)
	UpsertCeremonyContribution(ctx context.Context, item MPCContribution) error

	CreateParticipant(ctx context.Context, item MPCParticipant) error
	GetParticipant(ctx context.Context, tenantID string, id string) (MPCParticipant, error)
	ListParticipants(ctx context.Context, tenantID string) ([]MPCParticipant, error)
	UpdateParticipant(ctx context.Context, tenantID string, id string, req UpdateParticipantRequest) error
	DeleteParticipant(ctx context.Context, tenantID string, id string) error

	CreatePolicy(ctx context.Context, item MPCPolicy) error
	GetPolicy(ctx context.Context, tenantID string, id string) (MPCPolicy, error)
	ListPolicies(ctx context.Context, tenantID string) ([]MPCPolicy, error)
	UpdatePolicy(ctx context.Context, tenantID string, id string, req UpdatePolicyRequest) error
	DeletePolicy(ctx context.Context, tenantID string, id string) error
	CreatePolicyRule(ctx context.Context, item MPCPolicyRule) error
	DeletePolicyRules(ctx context.Context, tenantID string, policyID string) error

	GetOverviewStats(ctx context.Context, tenantID string) (MPCOverviewStats, error)
}

type MPCKey struct {
	ID                string                 `json:"id"`
	TenantID          string                 `json:"tenant_id"`
	Name              string                 `json:"name"`
	Algorithm         string                 `json:"algorithm"`
	Threshold         int                    `json:"threshold"`
	ParticipantCount  int                    `json:"participant_count"`
	Participants      []string               `json:"participants"`
	KeyCoreKeyID      string                 `json:"keycore_key_id"`
	PublicCommitments []string               `json:"public_commitments"`
	Status            string                 `json:"status"`
	ShareVersion      int                    `json:"share_version"`
	Metadata          map[string]interface{} `json:"metadata"`
	KeyGroup          string                 `json:"key_group"`
	ExpiresAt         time.Time              `json:"expires_at,omitempty"`
	RevokedAt         time.Time              `json:"revoked_at,omitempty"`
	RevocationReason  string                 `json:"revocation_reason,omitempty"`
	CreatedAt         time.Time              `json:"created_at"`
	UpdatedAt         time.Time              `json:"updated_at"`
	LastRotatedAt     time.Time              `json:"last_rotated_at"`
}

type MPCShare struct {
	ID             string                 `json:"id"`
	TenantID       string                 `json:"tenant_id"`
	KeyID          string                 `json:"key_id"`
	NodeID         string                 `json:"node_id"`
	ShareX         int                    `json:"share_x"`
	ShareYValue    string                 `json:"-"`
	ShareYHash     string                 `json:"share_y_hash"`
	ShareVersion   int                    `json:"share_version"`
	Status         string                 `json:"status"`
	Metadata       map[string]interface{} `json:"metadata"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
	RefreshedAt    time.Time              `json:"refreshed_at"`
	LastBackupAt   time.Time              `json:"last_backup_at"`
	BackupArtifact string                 `json:"backup_artifact,omitempty"`
}

type MPCCeremony struct {
	ID                   string                 `json:"id"`
	TenantID             string                 `json:"tenant_id"`
	Type                 string                 `json:"type"`
	KeyID                string                 `json:"key_id"`
	Algorithm            string                 `json:"algorithm"`
	Threshold            int                    `json:"threshold"`
	ParticipantCount     int                    `json:"participant_count"`
	Participants         []string               `json:"participants"`
	MessageHash          string                 `json:"message_hash"`
	Ciphertext           string                 `json:"ciphertext"`
	Status               string                 `json:"status"`
	Result               map[string]interface{} `json:"result"`
	CreatedBy            string                 `json:"created_by"`
	CreatedAt            time.Time              `json:"created_at"`
	UpdatedAt            time.Time              `json:"updated_at"`
	CompletedAt          time.Time              `json:"completed_at"`
	RequiredContributors int                    `json:"required_contributors"`
}

type MPCContribution struct {
	TenantID    string                 `json:"tenant_id"`
	CeremonyID  string                 `json:"ceremony_id"`
	PartyID     string                 `json:"party_id"`
	Payload     map[string]interface{} `json:"payload"`
	SubmittedAt time.Time              `json:"submitted_at"`
}

type DKGInitiateRequest struct {
	TenantID     string   `json:"tenant_id"`
	KeyName      string   `json:"key_name"`
	Algorithm    string   `json:"algorithm"`
	Threshold    int      `json:"threshold"`
	Participants []string `json:"participants"`
	CreatedBy    string   `json:"created_by"`
	KeyCoreKeyID string   `json:"keycore_key_id"`
}

type DKGContributeRequest struct {
	TenantID string                 `json:"tenant_id"`
	PartyID  string                 `json:"party_id"`
	Payload  map[string]interface{} `json:"payload"`
}

type SignInitiateRequest struct {
	TenantID     string   `json:"tenant_id"`
	KeyID        string   `json:"key_id"`
	MessageHash  string   `json:"message_hash"`
	Participants []string `json:"participants"`
	CreatedBy    string   `json:"created_by"`
}

type SignContributeRequest struct {
	TenantID         string `json:"tenant_id"`
	PartyID          string `json:"party_id"`
	PartialSignature string `json:"partial_signature"`
}

type DecryptInitiateRequest struct {
	TenantID     string   `json:"tenant_id"`
	KeyID        string   `json:"key_id"`
	Ciphertext   string   `json:"ciphertext"`
	Participants []string `json:"participants"`
	CreatedBy    string   `json:"created_by"`
}

type DecryptContributeRequest struct {
	TenantID string `json:"tenant_id"`
	PartyID  string `json:"party_id"`
}

type ShareRefreshRequest struct {
	TenantID string `json:"tenant_id"`
	Actor    string `json:"actor"`
}

type ShareBackupRequest struct {
	TenantID     string `json:"tenant_id"`
	KeyID        string `json:"key_id"`
	NodeID       string `json:"node_id"`
	Destination  string `json:"destination"`
	RequestedBy  string `json:"requested_by"`
	IncludeProof bool   `json:"include_proof"`
}

type KeyRotateRequest struct {
	TenantID  string `json:"tenant_id"`
	Actor     string `json:"actor"`
	Algorithm string `json:"algorithm"`
}

// ── Enterprise types ──────────────────────────────────────────

type MPCParticipant struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id"`
	Name       string    `json:"name"`
	Endpoint   string    `json:"endpoint"`
	PublicKey  string    `json:"public_key"`
	Status     string    `json:"status"`
	LastSeenAt time.Time `json:"last_seen_at,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type MPCPolicy struct {
	ID          string          `json:"id"`
	TenantID    string          `json:"tenant_id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	KeyIDs      string          `json:"key_ids"`
	Enabled     bool            `json:"enabled"`
	Rules       []MPCPolicyRule `json:"rules,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

type MPCPolicyRule struct {
	ID        string    `json:"id"`
	PolicyID  string    `json:"policy_id"`
	TenantID  string    `json:"tenant_id"`
	RuleType  string    `json:"rule_type"`
	Params    string    `json:"params"`
	CreatedAt time.Time `json:"created_at"`
}

type MPCOverviewStats struct {
	TotalKeys           int `json:"total_keys"`
	ActiveKeys          int `json:"active_keys"`
	RevokedKeys         int `json:"revoked_keys"`
	TotalCeremonies     int `json:"total_ceremonies"`
	PendingCeremonies   int `json:"pending_ceremonies"`
	CompletedCeremonies int `json:"completed_ceremonies"`
	FailedCeremonies    int `json:"failed_ceremonies"`
	ActiveParticipants  int `json:"active_participants"`
	TotalParticipants   int `json:"total_participants"`
	ActivePolicies      int `json:"active_policies"`
}

type RegisterParticipantRequest struct {
	TenantID  string `json:"tenant_id"`
	Name      string `json:"name"`
	Endpoint  string `json:"endpoint"`
	PublicKey string `json:"public_key"`
}

type UpdateParticipantRequest struct {
	Name      string `json:"name,omitempty"`
	Endpoint  string `json:"endpoint,omitempty"`
	PublicKey string `json:"public_key,omitempty"`
	Status    string `json:"status,omitempty"`
}

type CreatePolicyRequest struct {
	TenantID    string                   `json:"tenant_id"`
	Name        string                   `json:"name"`
	Description string                   `json:"description"`
	KeyIDs      string                   `json:"key_ids"`
	Enabled     bool                     `json:"enabled"`
	Rules       []CreatePolicyRuleParams `json:"rules"`
}

type CreatePolicyRuleParams struct {
	RuleType string `json:"rule_type"`
	Params   string `json:"params"`
}

type UpdatePolicyRequest struct {
	Name        string                   `json:"name,omitempty"`
	Description string                   `json:"description,omitempty"`
	KeyIDs      string                   `json:"key_ids,omitempty"`
	Enabled     *bool                    `json:"enabled,omitempty"`
	Rules       []CreatePolicyRuleParams `json:"rules,omitempty"`
}

type RevokeKeyRequest struct {
	Reason string `json:"reason"`
}

type SetKeyGroupRequest struct {
	Group string `json:"group"`
}

type CeremonyFilter struct {
	Type   string
	Status string
}
