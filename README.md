# ScatterID App — Gateway Proxy & Demonstration Service

[![Cryptography](https://img.shields.io/badge/Crypto-NIST_FIPS_204_(ML--DSA--65)-blue.svg)](https://csrc.nist.gov/pubs/fips/204/final)
[![Ledger](https://img.shields.io/badge/Ledger-Hyperledger_Fabric-purple.svg)](https://www.hyperledger.org/projects/fabric)
[![License: PolyForm Noncommercial](https://img.shields.io/badge/License-PolyForm_Noncommercial_1.0.0-blue.svg)](LICENSE)

Backend application proxy and local cryptographic formatting service for the **ScatterID** post-quantum zero-knowledge identity verification ecosystem.

---

## 1. Architectural Role & Service Scope

**ScatterID App** operates as an application-tier reverse proxy and local commitment generation engine positioned between user clients (wallets, verifier portals) and the core ScatterID Verification Gateway API (`:3000`):

1. **Client-Side Salting & Canonicalization**: Evaluates identity claims through RFC 8785 JSON Canonicalization Scheme (JCS) and prepends 16-byte cryptographically secure pseudorandom number generator (CSPRNG) salts to generate tamper-evident SHA3-256 commitments (`POST /api/hash`).
2. **Gateway API Proxy**: Transparently proxies authenticated credential issuance (`POST /api/issue`) and cryptographic verification requests (`POST /api/verify`) to the core verification gateway without persisting raw claims to disk.
3. **Health & Connectivity Probes**: Validates end-to-end network connectivity to the upstream verification gateway and the Hyperledger Fabric ledger (`GET /api/health`, `GET /healthz`).
4. **Standard Claim Presets**: Exposes verified claim presets across KYC, Healthcare, FinTech, and Higher Education domains (`GET /api/presets`).

> [!NOTE]
> **Headless Architecture & UI Redesign**: The legacy proof-of-concept client portal (`public/*`) was decommissioned to separate client UI presentation from cryptographic proxy operations. The service currently runs in headless API mode while a unified holder workbench is redesigned from scratch.

---

## 2. API Reference

### Health Probes
- **`GET /healthz`**: Basic liveness probe returning HTTP 200 with service uptime.
- **`GET /api/health`**: Upstream readiness probe that queries the verification gateway (`/health`) and checks Fabric ledger connectivity.

### Identity Claim Presets
- **`GET /api/presets`**: Returns standard claim schemas and sample presets for demonstration workflows (`kyc`, `employment`, `healthcare`, `education`).

### Cryptographic Salt & Commitment Generation
- **`POST /api/hash`**
  - **Payload**: `{ "claims": { [key: string]: any }, "salt"?: string }`
  - **Operation**:
    - If `salt` is not supplied, generates a 16-byte hex CSPRNG salt via `crypto.randomBytes(16)`.
    - Canonicalizes each claim key-value pair per RFC 8785.
    - Computes `SHA3-256(salt + canonical_claim)` for each claim to generate leaf commitments.
  - **Response**: `{ "salt": "<32-char hex>", "saltedClaims": { ... }, "claimHashes": { ... } }`

### Credential Issuance Proxy
- **`POST /api/issue`**
  - Proxies issuance requests to `${SCATTERID_GATEWAY_URL}/credentials/issue`.
  - Expects standard credential attributes and holder binding key.

### Credential Verification Proxy
- **`POST /api/verify`**
  - Proxies verification requests to `${SCATTERID_GATEWAY_URL}/credentials/verify`.
  - Verifies post-quantum signature and active ledger revocation status.

---

## 3. Configuration & Environment Variables

| Variable | Default | Description |
| :--- | :--- | :--- |
| `PORT` | `3001` | HTTP port on which the proxy listens |
| `SCATTERID_GATEWAY_URL` | `http://localhost:3000` | Base URL of the core Verification Gateway API |
| `NODE_ENV` | `development` | Runtime environment (`development`, `production`, `test`) |

---

## 4. Automated Testing & Verification

The service includes an automated unit test suite using Node.js's native test runner (`node --test`), verifying route handling, error branches, canonical hashing, and salting behavior without external mock libraries:

```bash
# Run the test suite
npm test
```

### Test Coverage Highlights
- **Health Probes**: Validates `/healthz` structure and status.
- **Claim Presets**: Verifies schema integrity for KYC, healthcare, and education presets.
- **Canonical Hashing**: Confirms deterministic SHA3-256 output across arbitrary key ordering.
- **CSPRNG Salting**: Validates salt uniqueness and 16-byte entropy.
- **Input Validation**: Confirms HTTP 400 rejection for malformed or missing claim payloads.

---

## 5. Development & Local Run

```bash
# Install dependencies
npm install

# Start local proxy server (defaults to port 3001)
npm run dev

# Run automated tests
npm test
```

---

## License

PolyForm Noncommercial License 1.0.0 © ScatterID Security Research.
