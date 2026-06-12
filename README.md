# KMS Extension

Companion product to Vecta KMS. Features that are real but outside the core
key-management mission live here, developed and shipped independently, and
integrate with the KMS over its REST APIs — never in-process.

## Integration contract

- Every extension service talks to the core KMS through
  [`pkg/kmsclient`](pkg/kmsclient/client.go): bearer service token +
  `X-Tenant-ID` header against the keycore API.
- Extension services hold **no key material** and implement **no crypto**;
  key operations are delegated to the KMS, which enforces access policy
  (KeyAccessGrant) and emits the audit trail.
- Multi-tenancy mirrors the core: tenant-scoped stores with RLS (see
  `services/edge/migrations`).

## Services

| Service | Status | Port |
|---|---|---|
| `services/edge` | live skeleton — edge/IoT device registry, ported from keycore | 9410 |

`seeds/` holds the recovered sources of the other features cut from the core
(QKD, QRNG, MPC, DAM, TFE, AI assistant, blockchain audit anchoring) with a
promotion checklist — see [seeds/README.md](seeds/README.md).

## Development

```sh
go build ./...
go vet ./...

# run the edge service against a local KMS
KMS_BASE_URL=https://localhost:8443 \
KMS_SERVICE_TOKEN=... \
KMS_TENANT_ID=tenant-dev \
go run ./services/edge
```
