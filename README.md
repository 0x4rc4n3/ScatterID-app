# ScatterID App — Post-Quantum Identity Portal

[![Live Demo](https://img.shields.io/badge/Demo-scatterid.app-00F5A0.svg)](https://scatterid.app)
[![Cryptography](https://img.shields.io/badge/Crypto-NIST_FIPS_204_(ML--DSA--65)-blue.svg)](https://csrc.nist.gov/pubs/fips/204/final)
[![Ledger](https://img.shields.io/badge/Ledger-Hyperledger_Fabric-purple.svg)](https://www.hyperledger.org/projects/fabric)
[![License: PolyForm Noncommercial](https://img.shields.io/badge/License-PolyForm_Noncommercial_1.0.0-blue.svg)](LICENSE)

The official web application and demonstration portal for **ScatterID** — decentralized, zero-knowledge identity verification infrastructure built for the post-quantum era.

---

## Overview

**ScatterID App** delivers an interactive, high-fidelity user experience to demonstrate quantum-safe, privacy-preserving digital credentials. It directly interfaces with the ScatterID Verification Gateway API, HashiCorp Vault KMS, and Hyperledger Fabric blockchain ledger.

Unlike traditional digital identity systems that transmit raw personal data over the wire, ScatterID enforces strict data minimization: **raw attributes never leave the user's device**.

---

## Key Modules & Interactive Story

```
┌────────────────────────────────────────────────────────────────────────┐
│                        SCATTERID.APP EXPERIENCE                        │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  [1] HOLDER STUDIO (Issuance)                                          │
│      • Real-world identity presets (Digital Passport, Driver's License) │
│      • Local client-side canonicalization (RFC 8785 JCS) + CSPRNG salt  │
│      • Transmits ONLY a SHA3-256 commitment to the network             │
│      • Produces a quantum-signed digital credential (ML-DSA-65)        │
│                                                                        │
│  [2] VERIFIER PORTAL (Zero-Knowledge Verification)                     │
│      • Mathematical proof verification without plaintext exposure       │
│      • Selective disclosure (e.g., verify "Age ≥ 21" without DOB)       │
│      • Standalone offline validation capability                         │
│                                                                        │
│  [3] QUANTUM ATTACK & TAMPER SIMULATOR                                 │
│      • Live interactive adversary simulation                           │
│      • Tamper with 1 bit of claim data or signature                     │
│      • Instant cryptographic rejection: demonstrates unforgeability     │
│                                                                        │
│  [4] INFRASTRUCTURE TELEMETRY                                          │
│      • Real-time Hyperledger Fabric ledger height & consensus           │
│      • HashiCorp Vault KMS active key ID & mTLS telemetry               │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Tech Stack

* **Frontend:** Modern Responsive SPA (Semantic HTML5 / Tailwind CSS / Vanilla ES Modules)
* **Backend Bridge:** Node.js / Express proxying to ScatterID Gateway API (`:3000`)
* **Cryptography:** NIST FIPS 204 ML-DSA-65 + SHA3-256 + RFC 8785 Canonicalization
* **Ledger:** Hyperledger Fabric v2.5 with Raft consensus

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
