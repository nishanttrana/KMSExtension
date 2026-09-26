package featureforge

import "time"

// Mode is the operating mode of an intent. The two modes have very different
// risk profiles and therefore different guardrail paths.
type Mode string

const (
	// ModeConfig: admin types an intent that maps to a FIXED, allow-listed
	// action from the catalog. The LLM only classifies + fills a schema.
	// It NEVER produces code. This is the safely-automatable path.
	ModeConfig Mode = "config"

	// ModeScaffold: engineer types a feature; the system scaffolds code
	// (service/handler/proto/migration/tests) following repo conventions,
	// runs it in a sandbox, and can deploy to STAGING only. Prod promotion
	// is always a human + governance decision.
	ModeScaffold Mode = "scaffold"
)

// Stage represents how far an intent has progressed through the pipeline.
type Stage string

const (
	StageReceived   Stage = "received"
	StageClassified Stage = "classified"
	StageValidated  Stage = "validated"
	StagePolicyOK   Stage = "policy_ok"
	StageDryRunOK   Stage = "dryrun_ok"
	StageTestedOK   Stage = "tested_ok"
	StageStaged     Stage = "staged"        // applied to staging
	StageAwaitProd  Stage = "awaiting_prod" // gated on governance quorum
	StageProd       Stage = "deployed_prod"
	StageRejected   Stage = "rejected"
	StageFailed     Stage = "failed"
)

// Env is a deployment target.
type Env string

const (
	EnvStaging Env = "staging"
	EnvProd    Env = "prod"
)

// Intent is a single natural-language request flowing through the forge.
type Intent struct {
	ID         string                 `json:"id"`
	TenantID   string                 `json:"tenant_id"`
	Actor      string                 `json:"actor"`    // who typed it
	RawText    string                 `json:"raw_text"` // "/spell ..." style input
	Mode       Mode                   `json:"mode"`
	Stage      Stage                  `json:"stage"`
	Action     string                 `json:"action"` // resolved catalog action (config mode)
	Params     map[string]interface{} `json:"params"` // schema-validated params
	Confidence float64                `json:"confidence"`
	Reasons    []string               `json:"reasons"` // human-readable guardrail trail
	CreatedAt  time.Time              `json:"created_at"`
	UpdatedAt  time.Time              `json:"updated_at"`

	// approvalID is the governance approval opened for prod promotion, if any.
	// Unexported so it stays internal to the forge; persisted via the
	// ff_prod_approvals table in the real store.
	approvalID string
}

// CatalogAction is one allow-listed thing the config mode is permitted to do.
// The space of outcomes is bounded by this catalog — nothing outside it.
type CatalogAction struct {
	Name    string `json:"name"`
	Summary string `json:"summary"`
	// RequiredParams maps param name -> human description; all required.
	RequiredParams map[string]string `json:"required_params"`
	// RequiresQuorum: true => prod application needs a governance quorum.
	RequiresQuorum bool `json:"requires_quorum"`
	// Sensitive: destructive / high-blast-radius actions.
	Sensitive bool `json:"sensitive"`
}

// GuardrailResult is the outcome of a single guardrail layer.
type GuardrailResult struct {
	Layer  string `json:"layer"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

// AuditEvent mirrors the shape consumed by the existing `audit` service:
// every step in the pipeline emits one, producing a tamper-evident trail.
type AuditEvent struct {
	IntentID  string    `json:"intent_id"`
	TenantID  string    `json:"tenant_id"`
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	Stage     Stage     `json:"stage"`
	Outcome   string    `json:"outcome"`
	Detail    string    `json:"detail"`
	Timestamp time.Time `json:"timestamp"`
}

// Classifier turns raw text into a structured, catalog-bound intent.
// In production this is backed by an LLM with a constrained tool/JSON schema;
// the prototype ships a deterministic keyword classifier so it is testable
// and so behavior is reproducible (important for a KMS).
type Classifier interface {
	Classify(raw string, catalog []CatalogAction) (mode Mode, action string, params map[string]interface{}, confidence float64, err error)
}

// PolicyClient checks a resolved action against the existing `policy` service.
type PolicyClient interface {
	Evaluate(tenantID, action string, params map[string]interface{}) (GuardrailResult, error)
}

// GovernanceClient opens a quorum-gated approval against the existing
// `governance` service for prod promotion.
type GovernanceClient interface {
	RequestApproval(intent *Intent) (approvalID string, err error)
	ApprovalState(approvalID string) (approved bool, err error)
}

// AuditClient emits events to the existing `audit` service.
type AuditClient interface {
	Emit(ev AuditEvent) error
}

// Sandbox runs scaffolded code / dry-runs config in an isolated env.
type Sandbox interface {
	// DryRunConfig validates a config action would apply cleanly (no writes).
	DryRunConfig(action string, params map[string]interface{}) (GuardrailResult, error)
	// BuildAndTest scaffolds + builds + tests code in isolation (staging path).
	BuildAndTest(intent *Intent) (GuardrailResult, error)
}
