# Seeds — recovered sources from Vecta KMS

These are the original sources of features cut from the core KMS
(KMSBeta commit `7f8aea7d1`, "remove speculative and redundant features"),
recovered verbatim from git history as starting material for KMS Extension
services. They do **not** compile here (they import `vecta-kms/...` packages
from the core repo); the nested `go.mod` keeps them out of the root build.

| Seed | What it was | Promotion notes |
|---|---|---|
| `services/qkd` | Quantum key distribution interface (ETSI GS QKD 014 style) | Needs real hardware partner before promotion |
| `services/qrng` | Quantum RNG source service | Core KMS now uses its FIPS CSPRNG; promote only with hardware |
| `services/mpc` + `pkg/mpc` | Threshold signing / Shamir + Feldman MPC engine | Crypto must move behind the core KMS crypto boundary or a vetted lib |
| `services/dam` | Database activity monitoring | Overlapped core audit + reporting; differentiate before promotion |
| `services/tfe` | Transparent file encryption | Overlapped core dataprotect; differentiate before promotion |
| `services/ai` | LLM assistant + DLP engine | The assistant surface; pair with the `ai-gateway` seed |
| `pkg/dltaudit` | Blockchain (Ethereum/Hyperledger) audit anchoring | Core audit hash chain + Merkle epochs cover transparency; promote only for external-anchor demand |
| `services/software-vault` | "Software HSM" vault (moved from KMSBeta `691a524ec`, 2026-09-26) | Nothing in the core called it. The core integrates real HSMs through its PKCS#11 hsm-connector; there is no Vecta HSM. Promote only as a clearly labelled software key store, never presented as an HSM |
| `featureforge` | Intent-to-feature automation prototype (cut in KMSBeta `7f8aea7`, recovered from the pre-rewrite `agents/kms-system-update-and-hardening` branch `bec7288`, 2026-09-26) | Standalone module (own `go.mod`, builds and tests on its own). Contains `stubs.go`: any promotion must replace stubs with real integrations or label it a preview (`409 feature_preview`), and route through `pkg/route` audit |
| `services/payment` + `pkg/payment` | Payment HSM functions: TR-31 key blocks, PIN translation, PVV/offset/CVV, retail MAC, LAU, ISO 20022 sign/verify/encrypt, AP2, key injection, PCI payment policy; dashboard tab and client in `services/payment/dashboard`, gRPC contract in `services/payment/proto`, API in `services/payment/API_REFERENCE.md` (moved from KMSBeta at `4146dc70c`, removed in KMSBeta 7.0.0-beta, 2026-09-29) | Payment implements its own cryptography on raw key material, which the extension contract forbids: key operations must go through the core KMS. Known defect: every operation naming a key by ID fetched material with keycore `POST /keys/{id}/export` and read a plaintext `material` field keycore never returns (it only exports under a `wrapping_key_id`), so only inline `material_b64` ever worked; its tests hid this with a fake. Its user delegation (`pkg/delegation`, usages `translate-*`, `mac`, `export`) came from KMSBeta 6.0.0-beta. `pkg/payment` stays in the core too: keycore imports TR-31 key blocks with it |
| `services/ai-gateway` | OpenAI-compatible LLM proxy (OpenAI, Anthropic, Azure, Bedrock, Vertex, Ollama) with prompt-injection, toxicity, topic-guardrail and source-code filters, token/cost budgets, cloud NER DLP; dashboard tab and client in `services/ai-gateway/dashboard` (moved from KMSBeta at `6f55c2a66`, removed in KMSBeta 7.5.0-beta, 2026-09-30) | Content inspection is not a KMS job. Known defects: the injection, toxicity and guardrail detectors are keyword regexes (trivially bypassed, false positives on `fetch(`), so any promotion must use a real classifier or be labelled a preview; provider API keys were stored in plaintext despite the schema comment `encrypted at rest`, and the list API returned their first and last four characters; AWS SigV4 used `crypto/hmac` directly; raw `ServeMux` with one generic audit event and no audited refusals; the dashboard's DLP Policies view called a non-existent `ai` service; cloud NER sends prompts to AWS, Google and Azure. Provider credentials must come from the core KMS secrets service, not a local table |

The edge/IoT device registry is **not** a seed — it is already live as the
first extension service in `services/edge`, ported from keycore.

Promotion checklist for any seed:
1. Rewrite imports against `vecta-kms-extension/pkg/...`; all key operations and
   crypto go through `pkg/kmsclient` to the core KMS — no local key material.
2. Add a tenant-scoped store (see `services/edge/migrations` RLS pattern in core).
3. Emit audit events to the core audit stream via the KMS API.
4. Move the directory from `seeds/` to `services/` and delete the seed.
