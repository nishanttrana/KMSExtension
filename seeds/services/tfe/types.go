package main

import "time"

// TFEAgent represents a Transparent File Encryption agent registered with the KMS.
type TFEAgent struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	Hostname     string    `json:"hostname"`
	OS           string    `json:"os"`           // linux, windows
	AgentVersion string    `json:"agent_version"`
	Status       string    `json:"status"` // registered, active, inactive, error
	LastSeen     time.Time `json:"last_seen"`
	PolicyCount  int       `json:"policy_count"`
	CreatedAt    time.Time `json:"created_at"`
}

// TFEPolicy defines a file encryption policy applied by an agent.
type TFEPolicy struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"`
	AgentID        string    `json:"agent_id"`
	Name           string    `json:"name"`
	Path           string    `json:"path"`      // e.g. /var/data or C:\SensitiveData
	Recursive      bool      `json:"recursive"`
	KeyID          string    `json:"key_id"`
	Algorithm      string    `json:"algorithm"`     // AES-256-CBC, AES-256-XTS
	IncludeGlobs   []string  `json:"include_globs"` // e.g. ["*.pii", "*.csv"]
	ExcludeGlobs   []string  `json:"exclude_globs"`
	Status         string    `json:"status"` // active, paused, error
	FilesEncrypted int       `json:"files_encrypted"`
	LastActivity   time.Time `json:"last_activity"`
	CreatedAt      time.Time `json:"created_at"`
}

// TFESummary contains aggregated statistics for the TFE service.
type TFESummary struct {
	TotalAgents    int            `json:"total_agents"`
	ActiveAgents   int            `json:"active_agents"`
	TotalPolicies  int            `json:"total_policies"`
	TotalEncrypted int            `json:"total_encrypted"`
	ByOS           map[string]int `json:"by_os"`
	ByStatus       map[string]int `json:"by_status"`
}

// RegisterAgentRequest is the request body for registering a TFE agent.
type RegisterAgentRequest struct {
	TenantID     string `json:"tenant_id"`
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	AgentVersion string `json:"agent_version"`
}

// HeartbeatRequest is the request body for updating an agent heartbeat.
type HeartbeatRequest struct {
	Status string `json:"status"`
}

// CreatePolicyRequest is the request body for creating a TFE policy.
type CreateTFEPolicyRequest struct {
	TenantID     string   `json:"tenant_id"`
	AgentID      string   `json:"agent_id"`
	Name         string   `json:"name"`
	Path         string   `json:"path"`
	Recursive    bool     `json:"recursive"`
	KeyID        string   `json:"key_id"`
	Algorithm    string   `json:"algorithm"`
	IncludeGlobs []string `json:"include_globs"`
	ExcludeGlobs []string `json:"exclude_globs"`
}

// UpdateTFEPolicyRequest is the request body for updating a TFE policy.
type UpdateTFEPolicyRequest struct {
	Status    *string  `json:"status,omitempty"`
	Path      *string  `json:"path,omitempty"`
	KeyID     *string  `json:"key_id,omitempty"`
	Recursive *bool    `json:"recursive,omitempty"`
	Algorithm *string  `json:"algorithm,omitempty"`
	IncludeGlobs *[]string `json:"include_globs,omitempty"`
	ExcludeGlobs *[]string `json:"exclude_globs,omitempty"`
}

// FileEncryptDownloadRequest is the request for generating a TFE agent package.
type FileEncryptDownloadRequest struct {
	TenantID     string
	TargetOS     string
	Distro       string
	KeyID        string
	WatchDirs    string
	FilePatterns string
	RotationDays int
	APIBaseURL   string
}

// FileEncryptPackageFile is a single file in the agent package.
type FileEncryptPackageFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Mode    string `json:"mode"`
}

// FileEncryptPackage is the generated agent package.
type FileEncryptPackage struct {
	TargetOS     string                   `json:"target_os"`
	Distro       string                   `json:"distro"`
	CreatedAt    string                   `json:"created_at"`
	Algorithm    string                   `json:"algorithm"`
	Mode         string                   `json:"mode"`
	KeyID        string                   `json:"key_id"`
	RotationDays int                      `json:"rotation_days"`
	Files        []FileEncryptPackageFile `json:"files"`
}

// FileEncryptAuditRequest is the body for the agent audit POST.
type FileEncryptAuditRequest struct {
	TenantID       string `json:"tenant_id"`
	KeyID          string `json:"key_id"`
	Operation      string `json:"operation"`
	FilesProcessed int    `json:"files_processed"`
	Timestamp      string `json:"timestamp"`
	Hostname       string `json:"hostname"`
	AgentVersion   string `json:"agent_version"`
}
