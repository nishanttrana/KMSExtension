// Package main runs the featureforge prototype as a standalone HTTP service
// plus a self-contained demo of the full pipeline. Build with:
//
//	go run ./cmd/featureforge demo   # run the pipeline demo
//	go run ./cmd/featureforge        # start the HTTP service on :8099
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	ff "vecta-kms/services/featureforge"
)

func main() {
	audit := ff.NewStubAudit()
	svc := ff.NewService(ff.Config{
		Policy:     ff.NewStubPolicy(),
		Governance: ff.NewStubGovernance(false), // require explicit approval
		Audit:      audit,
		Sandbox:    ff.NewStubSandbox(),
	})

	if len(os.Args) > 1 && os.Args[1] == "demo" {
		runDemo(svc, audit)
		return
	}

	h := ff.NewHandler(svc)
	addr := ":8099"
	log.Printf("featureforge listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, h.Routes()))
}

func runDemo(svc *ff.Service, audit *ff.StubAudit) {
	cases := []string{
		"block RSA-1024 for this tenant",
		"require approval for key delete",
		"build a new EdDSA signing endpoint service",
		"do something vague please",
	}
	for _, c := range cases {
		fmt.Printf("\n=== INTENT: %q ===\n", c)
		in, err := svc.Submit("tenant-a", "alice", c)
		dump(in)
		if err != nil {
			fmt.Printf("  -> stopped: %v\n", err)
			continue
		}
		out, perr := svc.PromoteToProd(in.ID)
		fmt.Printf("  -> promote: stage=%s err=%v\n", out.Stage, perr)
	}
	fmt.Printf("\n=== AUDIT TRAIL (%d events) ===\n", len(audit.Trail()))
	for _, ev := range audit.Trail() {
		fmt.Printf("  [%s] %s/%s %s: %s\n", ev.IntentID, ev.Stage, ev.Outcome, ev.Action, ev.Detail)
	}
}

func dump(in *ff.Intent) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetIndent("  ", "  ")
	_ = enc.Encode(map[string]interface{}{
		"id": in.ID, "mode": in.Mode, "action": in.Action,
		"params": in.Params, "confidence": in.Confidence, "stage": in.Stage,
	})
	fmt.Print("  " + b.String())
}
