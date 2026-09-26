package featureforge

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
)

// These stubs stand in for the real `policy`, `governance`, `audit` services
// and the sandbox runner. In production each is an RPC/HTTP client to the
// corresponding Vecta KMS service. The interfaces (types.go) are what you'd
// keep; only the bodies change.

// --- Policy stub ---------------------------------------------------------

// StubPolicy permits everything except a small deny-list, demonstrating the
// layer. The real client calls /svc/policy/evaluate.
type StubPolicy struct {
	// DenyActions: action names that are always denied.
	DenyActions map[string]bool
}

func NewStubPolicy() *StubPolicy {
	return &StubPolicy{DenyActions: map[string]bool{}}
}

func (p *StubPolicy) Evaluate(tenantID, action string, params map[string]interface{}) (GuardrailResult, error) {
	if p.DenyActions[action] {
		return GuardrailResult{Layer: "policy", Passed: false, Detail: "action denied by tenant policy"}, nil
	}
	// Example real rule: refuse to RAISE risk. Blocking weak algos is fine;
	// "blocking" a strong modern algo would be suspicious.
	if action == "policy.restrict_algorithm" {
		if alg, _ := params["algorithm"].(string); strings.HasPrefix(strings.ToUpper(alg), "ML-") {
			return GuardrailResult{Layer: "policy", Passed: false,
				Detail: "refusing to block a PQC algorithm (" + alg + ")"}, nil
		}
	}
	return GuardrailResult{Layer: "policy", Passed: true, Detail: "permitted"}, nil
}

// --- Governance stub -----------------------------------------------------

// StubGovernance simulates quorum approvals. AutoApprove controls whether the
// first ApprovalState read returns approved (handy for tests of both paths).
type StubGovernance struct {
	mu          sync.Mutex
	AutoApprove bool
	seq         int
	approved    map[string]bool
}

func NewStubGovernance(autoApprove bool) *StubGovernance {
	return &StubGovernance{AutoApprove: autoApprove, approved: map[string]bool{}}
}

func (g *StubGovernance) RequestApproval(in *Intent) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.seq++
	id := fmt.Sprintf("gov-%d", g.seq)
	g.approved[id] = g.AutoApprove
	return id, nil
}

func (g *StubGovernance) ApprovalState(id string) (bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	v, ok := g.approved[id]
	if !ok {
		return false, fmt.Errorf("unknown approval %s", id)
	}
	return v, nil
}

// Approve lets a test/operator grant a pending approval (simulating quorum).
func (g *StubGovernance) Approve(id string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.approved[id] = true
}

// --- Audit stub ----------------------------------------------------------

// StubAudit records events in memory. The real client appends to the
// tamper-evident `audit` service.
type StubAudit struct {
	mu     sync.Mutex
	Events []AuditEvent
}

func NewStubAudit() *StubAudit { return &StubAudit{} }

func (a *StubAudit) Emit(ev AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.Events = append(a.Events, ev)
	return nil
}

func (a *StubAudit) Trail() []AuditEvent {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]AuditEvent, len(a.Events))
	copy(out, a.Events)
	return out
}

// --- Sandbox stub --------------------------------------------------------

// StubSandbox simulates dry-run + build/test. It enforces a couple of real
// invariants so the guardrail demonstrably catches bad input.
type StubSandbox struct {
	// FailScaffold forces BuildAndTest to fail (simulate failing go test).
	FailScaffold bool
}

func NewStubSandbox() *StubSandbox { return &StubSandbox{} }

func (s *StubSandbox) DryRunConfig(action string, params map[string]interface{}) (GuardrailResult, error) {
	// Example invariant: min_bits must parse and be sane.
	if action == "policy.set_min_key_size" {
		bits, _ := params["min_bits"].(string)
		n, err := strconv.Atoi(bits)
		if err != nil || n < 1024 {
			return GuardrailResult{Layer: "sandbox", Passed: false,
				Detail: "min_bits invalid or below 1024"}, nil
		}
	}
	return GuardrailResult{Layer: "sandbox", Passed: true, Detail: "dry-run clean"}, nil
}

func (s *StubSandbox) BuildAndTest(in *Intent) (GuardrailResult, error) {
	if s.FailScaffold {
		return GuardrailResult{Layer: "sandbox", Passed: false, Detail: "go test failed in sandbox"}, nil
	}
	return GuardrailResult{Layer: "sandbox", Passed: true,
		Detail: "scaffolded, go build ok, go test ok (sandbox)"}, nil
}
