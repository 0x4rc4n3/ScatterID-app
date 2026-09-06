import express from 'express';
import helmet from 'helmet';
import compression from 'compression';
import path from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
import { createHash, randomBytes } from 'crypto';
import canonicalize from 'canonicalize';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 5000;
const GATEWAY_URL = process.env.GATEWAY_URL || process.env.VERIFICATION_API_URL || 'http://localhost:3000';
const OPS_DASHBOARD_URL = process.env.OPS_DASHBOARD_URL || 'http://localhost:8080';
const VERIFICATION_API_KEY = process.env.VERIFICATION_API_KEY || '';

// Security and compression middleware
app.use(helmet({
  contentSecurityPolicy: false // Allow inline scripts for standalone offline HTML portal
}));
app.use(compression());
app.use(express.json({ limit: '5mb' }));

// Serve static Help Desk Client Portal
app.use(express.static(path.resolve(__dirname, 'public')));

// Health check endpoint for Docker / reverse proxy
app.get('/healthz', (req, res) => {
  res.json({
    status: 'ok',
    service: 'scatterid-app',
    portalPort: PORT,
    timestamp: new Date().toISOString()
  });
});

// Diagnostic probe checking upstream Gateway API & Ops Dashboard status
app.get('/api/health', async (req, res) => {
  let gwStatus = 'unreachable';
  let opsStatus = 'unreachable';

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);
    const gwRes = await fetch(`${GATEWAY_URL}/healthz`, { signal: controller.signal });
    clearTimeout(timeout);
    gwStatus = gwRes.ok ? 'connected' : 'degraded';
  } catch (err) {
    gwStatus = 'unreachable';
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);
    const opsRes = await fetch(`${OPS_DASHBOARD_URL}/healthz`, { signal: controller.signal });
    clearTimeout(timeout);
    opsStatus = opsRes.ok ? 'connected' : 'degraded';
  } catch (err) {
    opsStatus = 'unreachable';
  }

  res.json({
    portal: 'operational',
    gateway: gwStatus,
    gatewayUrl: GATEWAY_URL,
    opsDashboard: opsStatus,
    opsDashboardUrl: OPS_DASHBOARD_URL
  });
});

// Production-representative ScatterID claim presets
const SAMPLE_PRESETS = [
  {
    id: 'identity-record',
    title: 'ScatterID National Civil Registry Record',
    description: 'Enables mathematical identity attestation without revealing full name, exact birthdate, or private civil registry numbers.',
    claim: {
      credentialType: 'CivilIdentityAttestation',
      subject: 'did:scatterid:record:8f92a10c',
      fullName: 'Alice M. Chen',
      identifierNumber: 'REC-9920148-X',
      issuingAuthority: 'Federal Civil Identity Registry',
      effectiveYear: 2026
    }
  },
  {
    id: 'healthcare-clearance',
    title: 'ScatterID Professional Practitioner Clearance',
    description: 'Validates professional surgical privileges and institutional licensing without leaking confidential files.',
    claim: {
      credentialType: 'ProfessionalClearanceRecord',
      subject: 'did:scatterid:record:dr-martinez',
      practitionerName: 'Dr. Sofia Martinez',
      licenseNumber: 'PR-448201',
      specialty: 'Trauma Surgery',
      licenseStatus: 'Active & Unrestricted',
      jurisdiction: 'National Medical Registry'
    }
  },
  {
    id: 'fintech-investor',
    title: 'ScatterID Institutional Status Assertion',
    description: 'Proves qualified institutional entity status with zero sensitive financial asset disclosure.',
    claim: {
      credentialType: 'InstitutionalStatusRecord',
      subject: 'did:scatterid:record:apex-holdings',
      entityName: 'Apex Capital Partners LLC',
      accreditationTier: 'Tier-1 Institutional Authority',
      jurisdiction: 'Financial Regulatory Council',
      regulatoryStatus: 'Compliant'
    }
  },
  {
    id: 'certified-record',
    title: 'ScatterID Verified Achievement & Competency Record',
    description: 'Permanently anchors verified competency and credential records resisting forgery while keeping detailed archives private.',
    claim: {
      credentialType: 'VerifiedCompetencyRecord',
      subject: 'did:scatterid:record:k-okonkwo',
      subjectName: 'Kelechi Okonkwo',
      institution: 'Polytechnic Institute of Technology',
      recordTitle: 'Advanced Systems & Information Security',
      issuanceYear: 2025,
      classification: 'Distinction'
    }
  }
];

app.get('/api/presets', (req, res) => {
  res.json({ presets: SAMPLE_PRESETS });
});

// Deterministic Cryptographic Salting & Hashing Engine
// Computes: SHA3-256( Salt[16 bytes] || Canonicalize_RFC8785(claim) )
app.post('/api/hash', (req, res) => {
  try {
    const { claim, salt: userSalt } = req.body;

    if (!claim || typeof claim !== 'object') {
      return res.status(400).json({ error: 'Valid JSON claim object is required' });
    }

    const saltHex = userSalt || randomBytes(16).toString('hex');
    if (!/^[0-9a-fA-F]{32}$/.test(saltHex)) {
      return res.status(400).json({ error: 'Salt must be a 32-character hexadecimal string (16 bytes)' });
    }

    const canonicalJson = canonicalize(claim);
    if (!canonicalJson) {
      return res.status(400).json({ error: 'Failed to canonicalize claim object' });
    }

    const saltBuffer = Buffer.from(saltHex, 'hex');
    const claimBuffer = Buffer.from(canonicalJson, 'utf-8');
    const payload = Buffer.concat([saltBuffer, claimBuffer]);

    const dataHash = createHash('sha3-256').update(payload).digest('hex');

    res.json({
      salt: saltHex,
      canonicalJson,
      payloadBytesLength: payload.length,
      dataHash
    });
  } catch (err) {
    res.status(500).json({ error: `Hashing failed: ${err.message}` });
  }
});

// Proxy: Direct Verification via Gateway API
app.post('/api/verify', async (req, res) => {
  try {
    const { credentialId, dataHash } = req.body;

    if (!credentialId && !dataHash) {
      return res.status(400).json({ error: 'Either credentialId or dataHash is required' });
    }

    const headers = { 'Content-Type': 'application/json' };
    const authKey = req.headers.authorization || (VERIFICATION_API_KEY ? `Bearer ${VERIFICATION_API_KEY}` : '');
    if (authKey) {
      headers['Authorization'] = authKey.startsWith('Bearer ') ? authKey : `Bearer ${authKey}`;
    }

    const gwRes = await fetch(`${GATEWAY_URL}/verify`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ credentialId, dataHash })
    });

    const gwData = await gwRes.json();
    res.status(gwRes.status).json(gwData);
  } catch (err) {
    res.status(502).json({
      error: `Failed to connect to Verification Gateway: ${err.message}`,
      gatewayUrl: GATEWAY_URL
    });
  }
});

// Proxy: Direct Issuance via Gateway API (Legacy/Direct mode)
app.post('/api/issue', async (req, res) => {
  try {
    const { dataHash, claim, salt, idempotencyKey } = req.body;

    let targetHash = dataHash;

    if (!targetHash && claim && typeof claim === 'object') {
      const saltHex = salt || randomBytes(16).toString('hex');
      const canonicalJson = canonicalize(claim);
      const saltBuffer = Buffer.from(saltHex, 'hex');
      const claimBuffer = Buffer.from(canonicalJson, 'utf-8');
      targetHash = createHash('sha3-256').update(Buffer.concat([saltBuffer, claimBuffer])).digest('hex');
    }

    if (!targetHash || !/^[0-9a-fA-F]{64}$/.test(targetHash)) {
      return res.status(400).json({
        error: 'A 64-character SHA3-256 dataHash is required for issuance'
      });
    }

    const headers = { 'Content-Type': 'application/json' };
    const authKey = req.headers.authorization || (VERIFICATION_API_KEY ? `Bearer ${VERIFICATION_API_KEY}` : '');
    if (authKey) {
      headers['Authorization'] = authKey.startsWith('Bearer ') ? authKey : `Bearer ${authKey}`;
    }

    const gwRes = await fetch(`${GATEWAY_URL}/issue`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        dataHash: targetHash,
        idempotencyKey: idempotencyKey || `app-${Date.now()}`
      })
    });

    const gwData = await gwRes.json();
    res.status(gwRes.status).json(gwData);
  } catch (err) {
    res.status(502).json({
      error: `Failed to connect to Verification Gateway: ${err.message}`,
      gatewayUrl: GATEWAY_URL
    });
  }
});

// ============================================================================
// HELP DESK PORTAL PROXY ROUTES (Forward to Ops Dashboard)
// ============================================================================

// Help Desk Staff Login Proxy
app.post('/api/portal/login', async (req, res) => {
  try {
    const response = await fetch(`${OPS_DASHBOARD_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req.body)
    });
    const data = await response.json();
    res.status(response.status).json(data);
  } catch (err) {
    res.status(502).json({
      error: `Failed to connect to Ops Dashboard: ${err.message}`,
      opsDashboardUrl: OPS_DASHBOARD_URL
    });
  }
});

// Help Desk First-Time Setup Proxy
app.post('/api/portal/first-time-setup', async (req, res) => {
  try {
    const headers = { 'Content-Type': 'application/json' };
    if (req.headers.authorization) headers['Authorization'] = req.headers.authorization;

    const response = await fetch(`${OPS_DASHBOARD_URL}/api/auth/first-time-setup`, {
      method: 'POST',
      headers,
      body: JSON.stringify(req.body)
    });
    const data = await response.json();
    res.status(response.status).json(data);
  } catch (err) {
    res.status(502).json({
      error: `Failed to complete first-time setup: ${err.message}`,
      opsDashboardUrl: OPS_DASHBOARD_URL
    });
  }
});

// Help Desk Issue Intake Proxy
app.post('/api/portal/issue', async (req, res) => {
  try {
    const headers = { 'Content-Type': 'application/json' };
    if (req.headers.authorization) headers['Authorization'] = req.headers.authorization;
    if (req.headers['x-station-id']) headers['x-station-id'] = req.headers['x-station-id'];

    const payload = { ...req.body };
    if (!payload.submission_channel && payload.verification_channel) {
      payload.submission_channel = payload.verification_channel;
    }
    if (payload.inspection_checklist && typeof payload.inspection_checklist === 'object') {
      const chk = payload.inspection_checklist;
      payload.inspection_checklist = {
        substrate_material_integrity: chk.substrate_material_integrity ?? chk.government_id_present ?? true,
        optical_security_features: chk.optical_security_features ?? true,
        biometric_face_match: chk.biometric_face_match ?? chk.physical_biometrics_matched ?? true,
        authority_seal_and_serial: chk.authority_seal_and_serial ?? chk.original_documents_sighted ?? true
      };
      payload.inspection_checklist_verified = 1;
    }

    const response = await fetch(`${OPS_DASHBOARD_URL}/api/requests/issue`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload)
    });
    const data = await response.json();
    res.status(response.status).json(data);
  } catch (err) {
    res.status(502).json({
      error: `Failed to forward issue request: ${err.message}`,
      opsDashboardUrl: OPS_DASHBOARD_URL
    });
  }
});

// Help Desk Revocation Intake Proxy
app.post('/api/portal/revoke', async (req, res) => {
  try {
    const headers = { 'Content-Type': 'application/json' };
    if (req.headers.authorization) headers['Authorization'] = req.headers.authorization;
    if (req.headers['x-station-id']) headers['x-station-id'] = req.headers['x-station-id'];

    const response = await fetch(`${OPS_DASHBOARD_URL}/api/requests/revoke`, {
      method: 'POST',
      headers,
      body: JSON.stringify(req.body)
    });
    const data = await response.json();
    res.status(response.status).json(data);
  } catch (err) {
    res.status(502).json({
      error: `Failed to forward revocation request: ${err.message}`,
      opsDashboardUrl: OPS_DASHBOARD_URL
    });
  }
});

// Help Desk Safe Request Tracking Proxy
app.get('/api/portal/track/:id', async (req, res) => {
  try {
    const headers = {};
    if (req.headers.authorization) headers['Authorization'] = req.headers.authorization;

    const response = await fetch(`${OPS_DASHBOARD_URL}/api/requests/track/${encodeURIComponent(req.params.id)}`, {
      headers
    });
    const data = await response.json();
    res.status(response.status).json(data);
  } catch (err) {
    res.status(502).json({
      error: `Failed to lookup request status: ${err.message}`,
      opsDashboardUrl: OPS_DASHBOARD_URL
    });
  }
});

// Help Desk Password Reset Proxy
app.post('/api/portal/reset-password', async (req, res) => {
  try {
    const headers = { 'Content-Type': 'application/json' };
    if (req.headers.authorization) headers['Authorization'] = req.headers.authorization;

    const response = await fetch(`${OPS_DASHBOARD_URL}/api/auth/reset-password`, {
      method: 'POST',
      headers,
      body: JSON.stringify(req.body)
    });
    const data = await response.json();
    res.status(response.status).json(data);
  } catch (err) {
    res.status(502).json({
      error: `Failed to reset password: ${err.message}`,
      opsDashboardUrl: OPS_DASHBOARD_URL
    });
  }
});

// Help Desk User Profile / Session Verification Proxy
app.get('/api/portal/me', async (req, res) => {
  try {
    const headers = {};
    if (req.headers.authorization) headers['Authorization'] = req.headers.authorization;

    const response = await fetch(`${OPS_DASHBOARD_URL}/api/auth/me`, {
      headers
    });
    const data = await response.json();
    res.status(response.status).json(data);
  } catch (err) {
    res.status(502).json({
      error: `Failed to verify session: ${err.message}`,
      opsDashboardUrl: OPS_DASHBOARD_URL
    });
  }
});

const isDirectRun = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isDirectRun && process.env.NODE_ENV !== 'test') {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`========================================================`);
    console.log(`  ScatterID Client Portal running at http://0.0.0.0:${PORT}`);
    console.log(`  Portal UI available at http://localhost:${PORT}/`);
    console.log(`  Ops Dashboard Target: ${OPS_DASHBOARD_URL}`);
    console.log(`  Verification Gateway: ${GATEWAY_URL}`);
    console.log(`========================================================`);
  });
}

export { app, SAMPLE_PRESETS };
