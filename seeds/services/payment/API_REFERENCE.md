# Payment service API (as it was in KMSBeta)

Copied from KMSBeta `docs/API_REFERENCE.md` when the service moved here (2026-09-29).

## Service 14: Payment (`/svc/payment/`)

Payment crypto: TR-31 key blocks, PIN operations, ISO 20022 message signing.

---

### POST /svc/payment/payment/tr31/translate

Translates a TR-31 key block from one KBPK to another (for inter-system key exchange).

**Request Body**: `keyBlock`, `sourcekbpkId`, `targetKbpkId`, `targetKeyUsage`, `targetModeOfUse`

**Response 200**: `keyBlock` (new TR-31 block under target KBPK)

---

### POST /svc/payment/payment/pin/translate

Translates a PIN block from one format or key to another.

**Request Body**: `pinBlock` (hex), `sourceFormat`, `sourceKeyId`, `targetFormat`, `targetKeyId`, `pan`

**Response 200**: `pinBlock` (hex), `targetFormat`, `targetKeyId`

---

### POST /svc/payment/payment/iso20022/sign

Signs an ISO 20022 XML or JSON message.

**Request Body**: `message` (base64-encoded message), `messageType` (string, e.g. pacs.008), `signingKeyId`, `algorithm`, `includeCertificate` (boolean)

**Response 200**: `signedMessage` (base64), `signature` (base64), `signatureAlgorithm`, `keyId`, `certificateId`

---

### POST /svc/payment/payment/iso20022/verify

Verifies a signed ISO 20022 message.

**Request Body**: `signedMessage` (base64), `messageType`, `signingKeyId`, `signature`

**Response 200**: `valid` (boolean), `signerIdentity`, `keyId`, `verifiedAt`

---


### payment (`/svc/payment/`)

- `POST /svc/payment/payment/ap2/evaluate`
- `GET /svc/payment/payment/ap2/profile`
- `PUT /svc/payment/payment/ap2/profile`
- `POST /svc/payment/payment/crypto`
- `GET /svc/payment/payment/crypto/operations`
- `GET /svc/payment/payment/injection/jobs`
- `POST /svc/payment/payment/injection/jobs`
- `POST /svc/payment/payment/injection/jobs/{id}/ack`
- `GET /svc/payment/payment/injection/terminals`
- `POST /svc/payment/payment/injection/terminals`
- `POST /svc/payment/payment/injection/terminals/{id}/challenge`
- `GET /svc/payment/payment/injection/terminals/{id}/jobs/next`
- `POST /svc/payment/payment/injection/terminals/{id}/verify`
- `POST /svc/payment/payment/iso20022/decrypt`
- `POST /svc/payment/payment/iso20022/encrypt`
- `POST /svc/payment/payment/iso20022/lau/generate`
- `POST /svc/payment/payment/iso20022/lau/verify`
- `POST /svc/payment/payment/iso20022/sign`
- `POST /svc/payment/payment/iso20022/verify`
- `GET /svc/payment/payment/keys`
- `POST /svc/payment/payment/keys`
- `GET /svc/payment/payment/keys/{id}`
- `PUT /svc/payment/payment/keys/{id}`
- `POST /svc/payment/payment/keys/{id}/rotate`
- `POST /svc/payment/payment/mac/cmac`
- `POST /svc/payment/payment/mac/iso9797`
- `POST /svc/payment/payment/mac/retail`
- `POST /svc/payment/payment/mac/verify`
- `POST /svc/payment/payment/pin/cvv/compute`
- `POST /svc/payment/payment/pin/cvv/verify`
- `POST /svc/payment/payment/pin/offset/generate`
- `POST /svc/payment/payment/pin/offset/verify`
- `POST /svc/payment/payment/pin/pvv/generate`
- `POST /svc/payment/payment/pin/pvv/verify`
- `POST /svc/payment/payment/pin/translate`
- `GET /svc/payment/payment/policy`
- `PUT /svc/payment/payment/policy`
- `POST /svc/payment/payment/tr31/create`
- `GET /svc/payment/payment/tr31/key-usages`
- `POST /svc/payment/payment/tr31/parse`
- `POST /svc/payment/payment/tr31/translate`
- `POST /svc/payment/payment/tr31/validate`

