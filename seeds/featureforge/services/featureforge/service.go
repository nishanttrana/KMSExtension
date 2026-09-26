package featureforge

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// MinConfidence is the floor below which an intent is auto-rejected. A KMS
// should refuse to act on an ambiguous instruction.
const MinConfidence = 0.65

// Service orchestrates the guardrail pipeline. It is the heart of the PoC.
//
// Pipeline (every intent passes ALL applicable layers in order; failing any
// layer halts progression and is audited):
//
//	L1 Classify        -> map raw text to mode + catalog action (untrusted)
//	L2 Validate        -> confidence floor + schema/required-param check
//	L3 Policy          -> existing `policy` service must permit the action
//	L4 Dry-run / Test  -> sandbox: config dry-run, or scaffold build+test
//	L5 Stage           -> auto-apply to STAGING
//	L6 Governance gate -> quorum approval required before PROD
//
// Audit events are emitted at every stage, giving a tamper-evident trail.
type Service struct {
	catalog    []CatalogAction
	classifier Classifier
	policy     PolicyClient
	gov        GovernanceClient
	audit      AuditClient
	sandbox    Sandbox

	mu      sync.Mutex
	intents map[string]*Intent
	seq     int
	now     func() time.Time
}

// Config holds Service dependencies.
type Config struct {
	Catalog    []CatalogAction
	Classifier Classifier
	Policy     PolicyClient
	Governance GovernanceClient
	Audit      AuditClient
	Sandbox    Sandbox
	Now        func() time.Time // injectable clock for tests
}

// NewService builds a Service, filling sensible defaults for anything omitted.
func NewService(c Config) *Service {
	if c.Catalog == nil {
		c.Catalog = DefaultCatalog()
	}
	if c.Classifier == nil {
		c.Classifier = NewKeywordClassifier()
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return &Service{
		catalog:    c.Catalog,
		classifier: c.Classifier,
		policy:     c.Policy,
		gov:        c.Governance,
		audit:      c.Audit,
		sandbox:    c.Sandbox,
		intents:    map[string]*Intent{},
		now:        c.Now,
	}
}

func (s *Service) emit(in *Intent, outcome, detail string) {
	if s.audit == nil {
		return
	}
	_ = s.audit.Emit(AuditEvent{
		IntentID:  in.ID,
		TenantID:  in.TenantID,
		Actor:     in.Actor,
		Action:    in.Action,
		Stage:     in.Stage,
		Outcome:   outcome,
		Detail:    detail,
		Timestamp: s.now(),
	})
}

func (s *Service) reject(in *Intent, reason string) (*Intent, error) {
	in.Stage = StageRejected
	in.Reasons = append(in.Reasons, reason)
	in.UpdatedAt = s.now()
	s.emit(in, "rejected", reason)
	return in, fmt.Errorf("rejected: %s", reason)
}

// Submit runs an intent through the full pipeline up to (and including) the
// STAGING apply. Prod promotion is a separate, explicitly-gated call
// (PromoteToProd). This separation is the "auto-to-staging, gated-to-prod"
// guarantee in code: there is no path from Submit to prod.
func (s *Service) Submit(tenantID, actor, rawText string) (*Intent, error) {
	s.mu.Lock()
	s.seq++
	in := &Intent{
		ID:        fmt.Sprintf("ff-%d", s.seq),
		TenantID:  tenantID,
		Actor:     actor,
		RawText:   rawText,
		Stage:     StageReceived,
		CreatedAt: s.now(),
		UpdatedAt: s.now(),
		Params:    map[string]interface{}{},
	}
	s.intents[in.ID] = in
	s.mu.Unlock()

	s.emit(in, "received", rawText)

	// --- L1: classify (untrusted output) ---
	mode, action, params, conf, err := s.classifier.Classify(rawText, s.catalog)
	if err != nil {
		in.Stage = StageFailed
		s.emit(in, "failed", "classify error: "+err.Error())
		return in, err
	}
	in.Mode, in.Action, in.Params, in.Confidence = mode, action, params, conf
	in.Stage = StageClassified
	in.Reasons = append(in.Reasons, fmt.Sprintf("classified mode=%s action=%q confidence=%.2f", mode, action, conf))
	s.emit(in, "classified", in.Reasons[len(in.Reasons)-1])

	// --- L2: validate ---
	if r := s.validate(in); !r.Passed {
		return s.reject(in, "validation: "+r.Detail)
	}
	in.Stage = StageValidated
	s.emit(in, "validated", "schema + confidence ok")

	// --- L3: policy ---
	if s.policy != nil {
		r, perr := s.policy.Evaluate(tenantID, in.Action, in.Params)
		if perr != nil {
			in.Stage = StageFailed
			s.emit(in, "failed", "policy error: "+perr.Error())
			return in, perr
		}
		if !r.Passed {
			return s.reject(in, "policy: "+r.Detail)
		}
	}
	in.Stage = StagePolicyOK
	in.Reasons = append(in.Reasons, "policy: permitted")
	s.emit(in, "policy_ok", "permitted")

	// --- L4: dry-run / build+test in sandbox ---
	if s.sandbox != nil {
		var r GuardrailResult
		var serr error
		if in.Mode == ModeScaffold {
			r, serr = s.sandbox.BuildAndTest(in)
		} else {
			r, serr = s.sandbox.DryRunConfig(in.Action, in.Params)
		}
		if serr != nil {
			in.Stage = StageFailed
			s.emit(in, "failed", "sandbox error: "+serr.Error())
			return in, serr
		}
		if !r.Passed {
			return s.reject(in, "sandbox: "+r.Detail)
		}
		if in.Mode == ModeScaffold {
			in.Stage = StageTestedOK
			s.emit(in, "tested_ok", r.Detail)
		} else {
			in.Stage = StageDryRunOK
			s.emit(in, "dryrun_ok", r.Detail)
		}
	}

	// --- L5: auto-apply to STAGING ---
	in.Stage = StageStaged
	in.Reasons = append(in.Reasons, "applied to staging")
	in.UpdatedAt = s.now()
	s.emit(in, "staged", "applied to staging env")

	return in, nil
}

func (s *Service) validate(in *Intent) GuardrailResult {
	if in.Confidence < MinConfidence {
		return GuardrailResult{Layer: "validate", Passed: false,
			Detail: fmt.Sprintf("confidence %.2f below floor %.2f", in.Confidence, MinConfidence)}
	}
	if in.Mode == ModeScaffold {
		// Scaffold intents don't bind to a catalog action; the build+test
		// layer is their gate. Still require non-empty text.
		if len(in.RawText) < 8 {
			return GuardrailResult{Layer: "validate", Passed: false, Detail: "scaffold intent too vague"}
		}
		return GuardrailResult{Layer: "validate", Passed: true, Detail: "scaffold ok"}
	}
	// Config mode: action must be in the catalog and all required params present.
	act := FindAction(s.catalog, in.Action)
	if act == nil {
		return GuardrailResult{Layer: "validate", Passed: false,
			Detail: fmt.Sprintf("action %q not in allow-list catalog", in.Action)}
	}
	for p, desc := range act.RequiredParams {
		v, ok := in.Params[p]
		if !ok || v == nil || v == "" {
			return GuardrailResult{Layer: "validate", Passed: false,
				Detail: fmt.Sprintf("missing required param %q (%s)", p, desc)}
		}
	}
	return GuardrailResult{Layer: "validate", Passed: true, Detail: "catalog + schema ok"}
}

// PromoteToProd is the ONLY path to production. It requires the intent to be
// staged, opens a governance quorum approval (for quorum-bound actions), and
// only applies once approval is granted.
func (s *Service) PromoteToProd(intentID string) (*Intent, error) {
	s.mu.Lock()
	in := s.intents[intentID]
	s.mu.Unlock()
	if in == nil {
		return nil, errors.New("unknown intent")
	}
	if in.Stage != StageStaged && in.Stage != StageAwaitProd {
		return in, fmt.Errorf("intent not eligible for prod (stage=%s)", in.Stage)
	}

	needsQuorum := in.Mode == ModeScaffold // all code changes need a human gate
	if act := FindAction(s.catalog, in.Action); act != nil && act.RequiresQuorum {
		needsQuorum = true
	}

	if needsQuorum {
		if s.gov == nil {
			return s.reject(in, "prod requires governance but no governance client configured")
		}
		// Reuse an existing approval if one was already opened for this intent,
		// so re-polling after a quorum is granted doesn't open a fresh request.
		approvalID := in.approvalID
		if approvalID == "" {
			var err error
			approvalID, err = s.gov.RequestApproval(in)
			if err != nil {
				in.Stage = StageFailed
				s.emit(in, "failed", "governance request error: "+err.Error())
				return in, err
			}
			in.approvalID = approvalID
		}
		approved, err := s.gov.ApprovalState(approvalID)
		if err != nil {
			return in, err
		}
		if !approved {
			in.Stage = StageAwaitProd
			in.Reasons = append(in.Reasons, "awaiting governance quorum approval "+approvalID)
			in.UpdatedAt = s.now()
			s.emit(in, "awaiting_prod", "approval "+approvalID+" pending")
			return in, nil // not an error: legitimately waiting
		}
		in.Reasons = append(in.Reasons, "governance approved "+approvalID)
	}

	in.Stage = StageProd
	in.UpdatedAt = s.now()
	s.emit(in, "deployed_prod", "applied to prod env")
	return in, nil
}

// Get returns an intent by ID.
func (s *Service) Get(id string) (*Intent, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	in, ok := s.intents[id]
	return in, ok
}

// Catalog exposes the active allow-list (for the dashboard / API).
func (s *Service) Catalog() []CatalogAction { return s.catalog }
