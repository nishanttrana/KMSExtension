package featureforge

import (
	"testing"
	"time"
)

func newTestService(autoApprove, failScaffold bool) (*Service, *StubAudit, *StubGovernance) {
	audit := NewStubAudit()
	gov := NewStubGovernance(autoApprove)
	sb := NewStubSandbox()
	sb.FailScaffold = failScaffold
	svc := NewService(Config{
		Policy:     NewStubPolicy(),
		Governance: gov,
		Audit:      audit,
		Sandbox:    sb,
		Now:        func() time.Time { return time.Unix(0, 0) },
	})
	return svc, audit, gov
}

func TestConfigIntent_BlockRSA1024_ReachesStaging(t *testing.T) {
	svc, audit, _ := newTestService(false, false)
	in, err := svc.Submit("tenant-a", "alice", "block RSA-1024 for this tenant")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if in.Action != "policy.restrict_algorithm" {
		t.Fatalf("wrong action: %s", in.Action)
	}
	if in.Params["algorithm"] != "RSA-1024" {
		t.Fatalf("wrong algorithm param: %v", in.Params["algorithm"])
	}
	if in.Stage != StageStaged {
		t.Fatalf("expected staged, got %s", in.Stage)
	}
	// must NOT have auto-deployed to prod
	for _, ev := range audit.Trail() {
		if ev.Stage == StageProd {
			t.Fatal("intent reached prod via Submit — staging boundary violated")
		}
	}
}

func TestConfigIntent_NonQuorum_PromotesToProd(t *testing.T) {
	svc, _, _ := newTestService(false, false)
	in, _ := svc.Submit("t", "alice", "block RSA-1024")
	out, err := svc.PromoteToProd(in.ID)
	if err != nil {
		t.Fatalf("promote error: %v", err)
	}
	if out.Stage != StageProd {
		t.Fatalf("expected prod (non-quorum action), got %s", out.Stage)
	}
}

func TestQuorumAction_WaitsForApproval(t *testing.T) {
	svc, _, gov := newTestService(false, false) // do not auto-approve
	in, _ := svc.Submit("t", "alice", "require approval for key delete")
	if in.Stage != StageStaged {
		t.Fatalf("expected staged, got %s (reasons=%v)", in.Stage, in.Reasons)
	}
	// First promotion attempt: quorum pending -> awaiting_prod, NOT prod.
	out, err := svc.PromoteToProd(in.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Stage != StageAwaitProd {
		t.Fatalf("expected awaiting_prod, got %s", out.Stage)
	}
	// Operator grants quorum, retry -> prod.
	// find the pending approval id from reasons isn't needed: approve all.
	gov.AutoApprove = true
	gov.Approve("gov-1")
	out2, err := svc.PromoteToProd(in.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out2.Stage != StageProd {
		t.Fatalf("expected prod after approval, got %s", out2.Stage)
	}
}

func TestLowConfidence_Rejected(t *testing.T) {
	svc, _, _ := newTestService(false, false)
	in, err := svc.Submit("t", "alice", "do something vague please")
	if err == nil {
		t.Fatal("expected rejection")
	}
	if in.Stage != StageRejected {
		t.Fatalf("expected rejected, got %s", in.Stage)
	}
}

func TestUnknownAlgorithm_MissingParam_Rejected(t *testing.T) {
	svc, _, _ := newTestService(false, false)
	// "block" with no recognized algorithm -> confidence 0.4 -> rejected at L2.
	in, err := svc.Submit("t", "alice", "block the weak thing")
	if err == nil {
		t.Fatal("expected rejection")
	}
	if in.Stage != StageRejected {
		t.Fatalf("expected rejected, got %s", in.Stage)
	}
}

func TestPolicyRefusesBlockingPQC(t *testing.T) {
	svc, _, _ := newTestService(false, false)
	// Force the classifier output by submitting recognizable text, then the
	// policy layer should refuse blocking an ML- algorithm. We simulate by
	// crafting params via a direct classify+policy path.
	in := &Intent{ID: "x", TenantID: "t", Action: "policy.restrict_algorithm",
		Params: map[string]interface{}{"algorithm": "ML-KEM-768"}, Confidence: 1, Mode: ModeConfig}
	r, _ := svc.policy.Evaluate(in.TenantID, in.Action, in.Params)
	if r.Passed {
		t.Fatal("policy should refuse blocking a PQC algorithm")
	}
}

func TestScaffold_FailingTests_Rejected(t *testing.T) {
	svc, _, _ := newTestService(false, true) // sandbox fails build+test
	in, err := svc.Submit("t", "bob", "build a new EdDSA signing endpoint service")
	if err == nil {
		t.Fatal("expected rejection due to failing sandbox tests")
	}
	if in.Stage != StageRejected {
		t.Fatalf("expected rejected, got %s", in.Stage)
	}
}

func TestScaffold_AlwaysNeedsQuorumForProd(t *testing.T) {
	svc, _, gov := newTestService(false, false)
	in, err := svc.Submit("t", "bob", "build a new EdDSA signing endpoint service")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if in.Stage != StageStaged {
		t.Fatalf("expected staged, got %s", in.Stage)
	}
	// scaffold prod must be gated even though no catalog action requires quorum
	out, _ := svc.PromoteToProd(in.ID)
	if out.Stage != StageAwaitProd {
		t.Fatalf("scaffold prod must be quorum-gated, got %s", out.Stage)
	}
	gov.Approve("gov-1")
	out2, _ := svc.PromoteToProd(in.ID)
	if out2.Stage != StageProd {
		t.Fatalf("expected prod after approval, got %s", out2.Stage)
	}
}

func TestAuditTrailCoversEveryStage(t *testing.T) {
	svc, audit, _ := newTestService(true, false)
	in, _ := svc.Submit("t", "alice", "block RSA-1024")
	_, _ = svc.PromoteToProd(in.ID)
	seen := map[Stage]bool{}
	for _, ev := range audit.Trail() {
		seen[ev.Stage] = true
	}
	for _, want := range []Stage{StageReceived, StageClassified, StageValidated, StagePolicyOK, StageDryRunOK, StageStaged, StageProd} {
		if !seen[want] {
			t.Errorf("missing audit event for stage %s", want)
		}
	}
}
