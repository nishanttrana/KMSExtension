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
| `services/ai` | LLM assistant + DLP engine | Core kept ai-gateway (LLM DLP); this is the assistant surface |
| `pkg/dltaudit` | Blockchain (Ethereum/Hyperledger) audit anchoring | Core audit hash chain + Merkle epochs cover transparency; promote only for external-anchor demand |
| `services/software-vault` | "Software HSM" vault (moved from KMSBeta `691a524ec`, 2026-09-26) | Nothing in the core called it. The core integrates real HSMs through its PKCS#11 hsm-connector; there is no Vecta HSM. Promote only as a clearly labelled software key store, never presented as an HSM |
| `featureforge` | Intent-to-feature automation prototype (cut in KMSBeta `7f8aea7`, recovered from the pre-rewrite `agents/kms-system-update-and-hardening` branch `bec7288`, 2026-09-26) | Standalone module (own `go.mod`, builds and tests on its own). Contains `stubs.go`: any promotion must replace stubs with real integrations or label it a preview (`409 feature_preview`), and route through `pkg/route` audit |

The edge/IoT device registry is **not** a seed — it is already live as the
first extension service in `services/edge`, ported from keycore.

Promotion checklist for any seed:
1. Rewrite imports against `vecta-kms-extension/pkg/...`; all key operations and
   crypto go through `pkg/kmsclient` to the core KMS — no local key material.
2. Add a tenant-scoped store (see `services/edge/migrations` RLS pattern in core).
3. Emit audit events to the core audit stream via the KMS API.
4. Move the directory from `seeds/` to `services/` and delete the seed.
