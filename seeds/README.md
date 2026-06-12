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

The edge/IoT device registry is **not** a seed — it is already live as the
first extension service in `services/edge`, ported from keycore.

Promotion checklist for any seed:
1. Rewrite imports against `vecta-kms-extension/pkg/...`; all key operations and
   crypto go through `pkg/kmsclient` to the core KMS — no local key material.
2. Add a tenant-scoped store (see `services/edge/migrations` RLS pattern in core).
3. Emit audit events to the core audit stream via the KMS API.
4. Move the directory from `seeds/` to `services/` and delete the seed.
