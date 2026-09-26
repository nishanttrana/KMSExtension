# FeatureForge (prototype)

Intent-to-feature capability for Vecta KMS. An admin or engineer types what they
want; the forge turns it into a **guardrailed** change that auto-applies to
**staging** and is **gated on governance approval before prod**.

This is a runnable proof-of-concept that mirrors the vecta-kms service layout
(`handler.go` / `service.go` / `types.go` / `migrations/` / `Dockerfile`). The
external services (`policy`, `governance`, `audit`) and the sandbox runner are
represented by interfaces with in-memory stubs so the whole pipeline runs on its
own.

## Two modes

- **config** — admin intent maps to a FIXED, allow-listed action from the
  catalog (`catalog.go`). The classifier only fills a schema; it never writes
  code. This is the safely-automatable path.
- **scaffold** — engineer feature request; code is scaffolded + built + tested
  in a sandbox and deployed to staging only. Prod always needs a human +
  governance quorum.

## Six guardrail layers (every intent)

1. **Classify** — raw text → mode + catalog action (treated as untrusted)
2. **Validate** — confidence floor + schema / required-param check
3. **Policy** — existing `policy` service must permit it
4. **Dry-run / Test** — sandbox: config dry-run, or scaffold build+test
5. **Stage** — auto-apply to staging
6. **Governance gate** — quorum approval required before prod

Every step emits an event to `audit` → tamper-evident trail.

There is **no code path from `Submit()` to prod**. Prod is only reachable via the
separate, explicitly-gated `PromoteToProd()`.

## Run it

```bash
go test ./...                    # 9 tests, covers every guardrail path
go run ./cmd/featureforge demo   # prints the pipeline + audit trail for 4 intents
go run ./cmd/featureforge        # HTTP service on :8099
```

### HTTP API

```
GET  /svc/featureforge/catalog
POST /svc/featureforge/intents                 {tenant_id, actor, text}
GET  /svc/featureforge/intents/{id}
POST /svc/featureforge/intents/{id}/promote
```

## Dropping into the real repo

1. Copy `services/featureforge/` into your repo's `services/`.
2. Copy `cmd/featureforge/` into your repo's `cmd/` (or wire main into your
   existing service-runner pattern).
3. Delete the standalone `go.mod` here — the code already imports
   `vecta-kms/services/featureforge`.
4. Replace the four stubs in `stubs.go` with real clients to `policy`,
   `governance`, `audit`, and your sandbox/CI runner.
5. Swap `keywordClassifier` for an LLM classifier constrained to emit JSON
   matching the catalog schema. The rest of the pipeline is unchanged — and
   that pipeline, not the model, is what keeps it safe.

See `DESIGN.docx` for the full architecture and rollout plan.
