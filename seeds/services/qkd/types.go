package main

import "time"

const (
	KeyStatusAvailable = "available"
	KeyStatusReserved  = "reserved"
	KeyStatusConsumed  = "consumed"
	KeyStatusDiscarded = "discarded"
	KeyStatusInjected  = "injected"
)

const (
	LinkStatusUp   = "up"
	LinkStatusDown = "down"
)

type QKDDevice struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id"`
	Name       string    `json:"name"`
	Role       string    `json:"role"`
	SlaveSAEID string    `json:"slave_sae_id"`
	LinkStatus string    `json:"link_status"`
	KeyRate    float64   `json:"key_rate"`
	QBERAvg    float64   `json:"qber_avg"`
	LastSeenAt time.Time `json:"last_seen_at"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type QKDKey struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	DeviceID      string    `json:"device_id"`
	SlaveSAEID    string    `json:"slave_sae_id"`
	ExternalKeyID string    `json:"external_key_id"`
	KeySizeBits   int       `json:"key_size_bits"`
	QBER          float64   `json:"qber"`
	Status        string    `json:"status"`
	KeyCoreKeyID  string    `json:"keycore_key_id"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	InjectedAt    time.Time `json:"injected_at"`

	WrappedDEK   []byte `json:"-"`
	WrappedDEKIV []byte `json:"-"`
	Ciphertext   []byte `json:"-"`
	DataIV       []byte `json:"-"`
}

type QKDSession struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id"`
	DeviceID   string    `json:"device_id"`
	SlaveSAEID string    `json:"slave_sae_id"`
	AppID      string    `json:"app_id"`
	Status     string    `json:"status"`
	OpenedAt   time.Time `json:"opened_at"`
	LastUsedAt time.Time `json:"last_used_at"`
	ClosedAt   time.Time `json:"closed_at"`
}

type QKDConfig struct {
	TenantID         string    `json:"tenant_id"`
	QBERThreshold    float64   `json:"qber_threshold"`
	PoolLowThreshold int       `json:"pool_low_threshold"`
	PoolCapacity     int       `json:"pool_capacity"`
	AutoInject       bool      `json:"auto_inject"`
	ServiceEnabled   bool      `json:"service_enabled"`
	ETSIAPIEnabled   bool      `json:"etsi_api_enabled"`
	Protocol         string    `json:"protocol"`
	DistanceKM       float64   `json:"distance_km"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type QKDLogEntry struct {
	ID        string                 `json:"id"`
	TenantID  string                 `json:"tenant_id"`
	Action    string                 `json:"action"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	Meta      map[string]interface{} `json:"meta"`
	CreatedAt time.Time              `json:"created_at"`
}

type ReceivedKey struct {
	KeyID       string  `json:"key_id"`
	MaterialB64 string  `json:"key"`
	QBER        float64 `json:"qber"`
}

type ReceiveKeysRequest struct {
	TenantID   string        `json:"tenant_id"`
	DeviceID   string        `json:"device_id"`
	DeviceName string        `json:"device_name"`
	Role       string        `json:"role"`
	LinkStatus string        `json:"link_status"`
	Keys       []ReceivedKey `json:"keys"`
}

type ReceiveKeysResponse struct {
	SlaveSAEID      string   `json:"slave_sae_id"`
	AcceptedKeyIDs  []string `json:"accepted_key_ids"`
	DiscardedKeyIDs []string `json:"discarded_key_ids"`
	AcceptedCount   int      `json:"accepted_count"`
	DiscardedCount  int      `json:"discarded_count"`
}

type RetrieveKeysRequest struct {
	TenantID   string   `json:"tenant_id"`
	DeviceID   string   `json:"device_id"`
	KeyIDs     []string `json:"key_ids"`
	Count      int      `json:"count"`
	MarkStatus string   `json:"mark_status"`
}

type RetrievedKey struct {
	KeyID       string  `json:"key_id"`
	KeyB64      string  `json:"key"`
	QBER        float64 `json:"qber"`
	KeySizeBits int     `json:"key_size_bits"`
}

type RetrieveKeysResponse struct {
	SlaveSAEID string         `json:"slave_sae_id"`
	Keys       []RetrievedKey `json:"keys"`
}

type OpenConnectRequest struct {
	TenantID   string `json:"tenant_id"`
	DeviceID   string `json:"device_id"`
	SlaveSAEID string `json:"slave_sae_id"`
	AppID      string `json:"app_id"`
}

type OpenConnectResponse struct {
	SessionID string `json:"session_id"`
	Status    string `json:"status"`
}

type GetKeyRequest struct {
	TenantID  string `json:"tenant_id"`
	SessionID string `json:"session_id"`
	Count     int    `json:"count"`
}

type GetKeyResponse struct {
	SessionID string         `json:"session_id"`
	Keys      []RetrievedKey `json:"keys"`
}

type CloseConnectRequest struct {
	TenantID  string `json:"tenant_id"`
	SessionID string `json:"session_id"`
}

type CloseConnectResponse struct {
	SessionID string `json:"session_id"`
	Status    string `json:"status"`
}

type InjectRequest struct {
	TenantID string `json:"tenant_id"`
	Name     string `json:"name"`
	Purpose  string `json:"purpose"`
	Consume  bool   `json:"consume"`
}

type InjectResponse struct {
	QKDKeyID     string `json:"qkd_key_id"`
	KeyCoreKeyID string `json:"keycore_key_id"`
	Status       string `json:"status"`
}

type TestGenerateRequest struct {
	TenantID    string  `json:"tenant_id"`
	SlaveSAEID  string  `json:"slave_sae_id"`
	DeviceID    string  `json:"device_id"`
	DeviceName  string  `json:"device_name"`
	Role        string  `json:"role"`
	LinkStatus  string  `json:"link_status"`
	Count       int     `json:"count"`
	KeySizeBits int     `json:"key_size_bits"`
	QBERMin     float64 `json:"qber_min"`
	QBERMax     float64 `json:"qber_max"`
}

// ── Slave SAE Registry ─────────────────────────────────────

const (
	SAEStatusActive   = "active"
	SAEStatusInactive = "inactive"
	SAEStatusError    = "error"

	SAEModeETSI  = "etsi"
	SAEModeCisco = "cisco-ckm"
	SAEModeRelay = "relay"
)

type SlaveSAE struct {
	ID               string    `json:"id"`
	TenantID         string    `json:"tenant_id"`
	Name             string    `json:"name"`
	Endpoint         string    `json:"endpoint"`
	AuthToken        string    `json:"auth_token,omitempty"`
	Protocol         string    `json:"protocol"`
	Role             string    `json:"role"`
	Mode             string    `json:"mode"`
	Status           string    `json:"status"`
	LastSyncAt       time.Time `json:"last_sync_at"`
	KeysDistributed  int64     `json:"keys_distributed"`
	KeysAvailable    int64     `json:"keys_available"`
	MaxKeyRate       float64   `json:"max_key_rate"`
	QBERThreshold    float64   `json:"qber_threshold"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type Distribution struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	SlaveSAEID    string    `json:"slave_sae_id"`
	KeyCount      int       `json:"key_count"`
	KeySizeBits   int       `json:"key_size_bits"`
	Status        string    `json:"status"`
	ErrorMessage  string    `json:"error_message,omitempty"`
	DistributedAt time.Time `json:"distributed_at"`
}

type RegisterSAERequest struct {
	TenantID      string  `json:"tenant_id"`
	Name          string  `json:"name"`
	Endpoint      string  `json:"endpoint"`
	AuthToken     string  `json:"auth_token"`
	Protocol      string  `json:"protocol"`
	Role          string  `json:"role"`
	Mode          string  `json:"mode"`
	MaxKeyRate    float64 `json:"max_key_rate"`
	QBERThreshold float64 `json:"qber_threshold"`
}

type DistributeKeysRequest struct {
	TenantID    string `json:"tenant_id"`
	SlaveSAEID  string `json:"slave_sae_id"`
	Count       int    `json:"count"`
	KeySizeBits int    `json:"key_size_bits"`
}

type DistributeKeysResponse struct {
	DistributionID string   `json:"distribution_id"`
	SlaveSAEID     string   `json:"slave_sae_id"`
	KeyCount       int      `json:"key_count"`
	KeyIDs         []string `json:"key_ids"`
	Status         string   `json:"status"`
}
