import express from 'express';
import helmet from 'helmet';
import compression from 'compression';
import path from 'path';
import { fileURLToPath } from 'url';
import { createHash, randomBytes } from 'crypto';
import canonicalize from 'canonicalize';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 8080;
const GATEWAY_URL = process.env.GATEWAY_URL || process.env.VERIFICATION_API_URL || 'http://localhost:3000';
const VERIFICATION_API_KEY = process.env.VERIFICATION_API_KEY || '';

// Security and compression middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      connectSrc: ["'self'"],
      imgSrc: ["'self'", "data:"]
    }
  }
}));
app.use(compression());
app.use(express.json({ limit: '2mb' }));

// Serve static assets from public/
app.use(express.static(path.join(__dirname, 'public')));

// Health check endpoint for Docker / reverse proxy
app.get('/healthz', (req, res) => {
  res.json({
    status: 'ok',
    service: 'scatterid-app',
    timestamp: new Date().toISOString()
  });
});

// Diagnostic probe checking upstream Gateway API status
app.get('/api/health', async (req, res) => {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);
    const gwRes = await fetch(`${GATEWAY_URL}/healthz`, { signal: controller.signal });
    clearTimeout(timeout);
    
    res.json({
      portal: 'operational',
      gateway: gwRes.ok ? 'connected' : 'degraded',
      gatewayUrl: GATEWAY_URL
    });
  } catch (err) {
    res.json({
      portal: 'operational',
      gateway: 'unreachable',
      gatewayUrl: GATEWAY_URL,
      error: err.message
    });
  }
});

// Real-world, production-representative claim presets
const SAMPLE_PRESETS = [
  {
    id: 'kyc-identity',
    title: 'Government National ID & Proof of Age',
    description: 'Enables mathematical age verification (e.g., 21+) without revealing name, exact birthdate, or ID number.',
    claim: {
      credentialType: 'NationalIdentityProof',
      subject: 'did:scatterid:user:8f92a10c',
      fullName: 'Alice M. Chen',
      dateOfBirth: '1996-04-12',
      citizenship: 'CAN',
      issuingAuthority: 'Federal Civil Identity Registry',
      documentNumber: 'ID-9920148-X'
    }
  },
  {
    id: 'healthcare-clearance',
    title: 'Post-Quantum Healthcare Practitioner Credential',
    description: 'Validates hospital surgical privileges and state medical licensing without leaking personal practitioner files.',
    claim: {
      credentialType: 'MedicalLicenseClearance',
      subject: 'did:scatterid:user:dr-martinez',
      practitionerName: 'Dr. Sofia Martinez, MD',
      licenseNumber: 'MED-NY-448201',
      specialty: 'Trauma Surgery',
      licenseStatus: 'Active & Unrestricted',
      jurisdiction: 'US-NY'
    }
  },
  {
    id: 'fintech-investor',
    title: 'Institutional Accredited Investor Proof',
    description: 'Proves qualified institutional buyer (QIB) accreditation status to financial venues with zero net-worth disclosure.',
    claim: {
      credentialType: 'AccreditedInvestorStatus',
      subject: 'did:scatterid:entity:apex-holdings',
      entityName: 'Apex Capital Partners LLC',
      accreditationTier: 'Rule 506(c) Qualified Purchaser',
      jurisdiction: 'US-SEC',
      regulatoryStatus: 'Compliant'
    }
  },
  {
    id: 'academic-degree',
    title: 'Cryptographic University Degree Verification',
    description: 'Permanently anchors university academic honors to resist degree fraud while keeping transcripts private.',
    claim: {
      credentialType: 'UniversityDegreeCredential',
      subject: 'did:scatterid:student:k-okonkwo',
      graduateName: 'Kelechi Okonkwo',
      institution: 'Polytechnic Institute of Technology',
      degree: 'Master of Science in Cybersecurity',
      graduationYear: 2025,
      honors: 'Summa Cum Laude'
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

// Proxy: Issue Credential via Gateway API
app.post('/api/issue', async (req, res) => {
  try {
    const { dataHash, claim, salt, idempotencyKey } = req.body;

    let targetHash = dataHash;

    // If client sent raw claim + salt, calculate canonical hash server-side
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

// Proxy: Verify Credential via Gateway API
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

app.listen(PORT, '0.0.0.0', () => {
  console.log(`========================================================`);
  console.log(`  ScatterID Showcase Portal running at http://0.0.0.0:${PORT}`);
  console.log(`  Gateway API Target: ${GATEWAY_URL}`);
  console.log(`========================================================`);
});
