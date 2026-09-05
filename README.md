# ScatterID App — Gateway Proxy & Demonstration Service

[![Cryptography](https://img.shields.io/badge/Crypto-NIST_FIPS_204_(ML--DSA--65)-blue.svg)](https://csrc.nist.gov/pubs/fips/204/final)
[![Ledger](https://img.shields.io/badge/Ledger-Hyperledger_Fabric-purple.svg)](https://www.hyperledger.org/projects/fabric)
[![License: PolyForm Noncommercial](https://img.shields.io/badge/License-PolyForm_Noncommercial_1.0.0-blue.svg)](LICENSE)

Backend service and application proxy for **ScatterID** — decentralized, zero-knowledge identity verification infrastructure built for the post-quantum era.

---

## Architecture & Service Scope

**ScatterID App** serves as the application-tier proxy and local cryptographic formatting engine interfacing with the core ScatterID Verification Gateway API (`:3000`):

1. **Client-Side Salting & Canonicalization**: Performs RFC 8785 JSON canonicalization Scheme (JCS) and prepends 16-byte CSPRNG salt to generate tamper-evident SHA3-256 commitments (`POST /api/hash`).
2. **Gateway API Proxy**: Bridges client requests to the backend verification gateway for credential issuance (`POST /api/issue`) and verification (`POST /api/verify`).
3. **Health & Connectivity Probes**: Validates upstream connectivity to the Verification Gateway and Hyperledger Fabric ledger (`GET /api/health`, `GET /healthz`).
4. **Standard Claim Presets**: Exposes production-representative identity presets across KYC, Healthcare, FinTech, and Higher Education (`GET /api/presets`).

> [!NOTE]
> **UI Redesign Notice**: The legacy proof-of-concept client portal (`public/*`) has been decommissioned as part of the ecosystem hardening audit to prepare for a clean, scratch redesign of the web application and holder workbench.

---

## Tech Stack

* **Runtime:** Node.js 24.x / Express 4.x (ES Modules)
* **Security:** Helmet CSP headers + response compression
* **Cryptography:** NIST FIPS 204 ML-DSA-65 + FIPS 202 SHA3-256 + RFC 8785 Canonicalization
* **Test Harness:** Node.js native test runner (`node --test`)

---

## Quickstart (Local Development)

```bash
# 1. Clone the repository
git clone git@github.com:0x4rc4n3/ScatterID-app.git
cd ScatterID-app

# 2. Install dependencies
npm install

# 3. Start local development server
npm run dev
```

---

## Related Repositories

* [ScatterID Core Infrastructure](https://github.com/0x4rc4n3/ScatterID): The core blockchain ledger, HashiCorp Vault KMS, and ML-DSA-65 cryptographic microservice.
