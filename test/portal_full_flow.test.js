// Exhaustive Full-Flow Integration Test Suite for ScatterID Client Portal
// Document ID: DEV-TEST-PORTAL-01 / ISSUE-103
// Validates all desks: Issue Desk, Verify Desk, Revoke Desk, Tracking Stepper, Clerk Auth & Security

import { describe, test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createHash } from 'node:crypto';
import express from 'express';
import { createPortalApp, SAMPLE_PRESETS } from '../server.js';

describe('ISSUE-103: ScatterID Client Portal Exhaustive Full-Flow Test Suite', () => {
  let portalServer;
  let mockOpsServer;
  let mockGatewayServer;
  let portalUrl;
  let opsUrl;
  let gatewayUrl;

  // Mock State Store
  const mockDb = {
    users: new Map(),
    requests: new Map(),
    credentials: new Map(),
    auditLogs: []
  };

  before(async () => {
    // 1. Setup Mock Ops Dashboard HTTP Server
    const opsApp = express();
    opsApp.use(express.json());

    // Seed test clerk
    mockDb.users.set('clerk_test', {
      id: 'usr_clerk_01',
      username: 'clerk_test',
      role: 'clerk',
      password: 'TempPassword2026!',
      requireFirstTimeSetup: true,
      mfaEnrolled: false
    });

    // Seed test credential
    mockDb.credentials.set('cred_valid_100', {
      credentialId: 'cred_valid_100',
      dataHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      status: 'ACTIVE',
      signatureAlgorithm: 'ML-DSA-87',
      issuedAt: new Date().toISOString()
    });

    mockDb.credentials.set('cred_revoked_200', {
      credentialId: 'cred_revoked_200',
      dataHash: 'a'.repeat(64),
      status: 'REVOKED',
      revocationReason: 'COMPROMISED_KEY',
      revokedAt: new Date().toISOString()
    });

    opsApp.get('/healthz', (req, res) => res.json({ status: 'ok', service: 'mock-ops' }));

    // Login
    opsApp.post('/api/auth/login', (req, res) => {
      const { username, password } = req.body;
      const user = mockDb.users.get(username);
      if (!user || user.password !== password) {
        return res.status(401).json({ error: 'INVALID_CREDENTIALS', message: 'Invalid username or password' });
      }
      if (user.requireFirstTimeSetup) {
        return res.status(200).json({
          status: 'SETUP_REQUIRED',
          requireFirstTimeSetup: true,
          tempToken: `temp_token_${user.id}`,
          message: 'First-time login credential configuration required'
        });
      }
      return res.status(200).json({
        token: `session_token_${user.id}`,
        user: { id: user.id, username: user.username, role: user.role }
      });
    });

    // First Time Setup
    opsApp.post('/api/auth/first-time-setup', (req, res) => {
      const auth = req.headers.authorization;
      if (!auth || !auth.startsWith('Bearer temp_token_')) {
        return res.status(401).json({ error: 'UNAUTHORIZED', message: 'Temporary token required' });
      }
      const { newPassword, confirmPassword } = req.body;
      if (!newPassword || newPassword.length < 10) {
        return res.status(400).json({ error: 'PASSWORD_WEAK', message: 'Password must be at least 10 characters' });
      }
      if (newPassword !== confirmPassword) {
        return res.status(400).json({ error: 'PASSWORD_MISMATCH', message: 'Passwords do not match' });
      }
      const hasUpper = /[A-Z]/.test(newPassword);
      const hasLower = /[a-z]/.test(newPassword);
      const hasDigit = /[0-9]/.test(newPassword);
      const hasSpecial = /[^A-Za-z0-9]/.test(newPassword);
      if (!hasUpper || !hasLower || !hasDigit || !hasSpecial) {
        return res.status(400).json({
          error: 'PASSWORD_COMPLEXITY_FAILED',
          message: 'Password must include uppercase, lowercase, digit, and special character'
        });
      }

      const user = mockDb.users.get('clerk_test');
      user.password = newPassword;
      user.requireFirstTimeSetup = false;
      user.mfaEnrolled = true;

      return res.status(200).json({
        success: true,
        message: 'Onboarding setup completed successfully',
        token: `session_token_${user.id}`,
        user: { id: user.id, username: user.username, role: user.role }
      });
    });

    // Reset Password
    opsApp.post('/api/auth/reset-password', (req, res) => {
      const auth = req.headers.authorization;
      if (!auth || !auth.startsWith('Bearer session_token_')) {
        return res.status(401).json({ error: 'UNAUTHORIZED' });
      }
      const { oldPassword, newPassword, confirmPassword } = req.body;
      const user = mockDb.users.get('clerk_test');
      if (user.password !== oldPassword) {
        return res.status(400).json({ error: 'INCORRECT_OLD_PASSWORD', message: 'Current password does not match' });
      }
      if (newPassword !== confirmPassword) {
        return res.status(400).json({ error: 'PASSWORD_MISMATCH', message: 'New passwords do not match' });
      }
      user.password = newPassword;
      return res.status(200).json({ success: true, message: 'Password updated successfully' });
    });

    // Me
    opsApp.get('/api/auth/me', (req, res) => {
      const auth = req.headers.authorization;
      if (!auth || !auth.startsWith('Bearer session_token_')) {
        return res.status(401).json({ error: 'UNAUTHORIZED', message: 'Invalid or expired session' });
      }
      const user = mockDb.users.get('clerk_test');
      return res.status(200).json({ user: { id: user.id, username: user.username, role: user.role } });
    });

    // Issue Intake
    opsApp.post('/api/requests/issue', (req, res) => {
      const auth = req.headers.authorization;
      if (!auth || !auth.startsWith('Bearer session_token_')) {
        return res.status(401).json({ error: 'UNAUTHORIZED', message: 'Valid clerk session required' });
      }

      const { submission_channel, claimant_data, inspection_checklist, evidence_sha256 } = req.body;

      if (!claimant_data || !claimant_data.fullName) {
        return res.status(400).json({ error: 'MISSING_CLAIMANT', message: 'Claimant fullName is required' });
      }

      if (submission_channel === 'hard') {
        const chk = inspection_checklist || {};
        if (!chk.substrate_material_integrity || !chk.optical_security_features ||
            !chk.biometric_face_match || !chk.authority_seal_and_serial) {
          return res.status(400).json({
            error: 'INCOMPLETE_CHECKLIST',
            message: 'All 4 physical inspection checkpoints are mandatory'
          });
        }
      } else if (submission_channel === 'soft') {
        if (!evidence_sha256 || !/^[0-9a-fA-F]{64}$/.test(evidence_sha256)) {
          return res.status(400).json({
            error: 'INVALID_EVIDENCE_HASH',
            message: 'A 64-character hexadecimal SHA-256 digest is required for soft channel'
          });
        }
      } else {
        return res.status(400).json({ error: 'INVALID_CHANNEL', message: 'submission_channel must be hard or soft' });
      }

      const requestId = `req_issue_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
      const record = {
        id: requestId,
        request_type: 'issuance',
        submission_channel,
        claimant_name: claimant_data.fullName,
        status: submission_channel === 'hard' ? 'EXECUTED' : 'AWAITING_ROOT_ACCEPT',
        created_at: new Date().toISOString()
      };
      mockDb.requests.set(requestId, record);

      return res.status(201).json({
        success: true,
        requestId,
        status: record.status,
        submission_channel,
        message: 'Intake recorded successfully'
      });
    });

    // Revoke Intake
    opsApp.post('/api/requests/revoke', (req, res) => {
      const auth = req.headers.authorization;
      if (!auth || !auth.startsWith('Bearer session_token_')) {
        return res.status(401).json({ error: 'UNAUTHORIZED' });
      }
      const { credential_id, reason, submission_channel, docket_reference } = req.body;
      if (!credential_id) {
        return res.status(400).json({ error: 'MISSING_CREDENTIAL_ID', message: 'credential_id is required' });
      }
      if (!reason) {
        return res.status(400).json({ error: 'MISSING_REASON', message: 'Revocation reason is required' });
      }
      if (!docket_reference) {
        return res.status(400).json({ error: 'MISSING_DOCKET', message: 'Docket reference is mandatory' });
      }

      const requestId = `req_revoke_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
      const record = {
        id: requestId,
        request_type: 'revocation',
        credential_id,
        submission_channel: submission_channel || 'hard',
        reason,
        docket_reference,
        status: 'AWAITING_ROOT_ACCEPT',
        created_at: new Date().toISOString()
      };
      mockDb.requests.set(requestId, record);

      return res.status(201).json({
        success: true,
        requestId,
        status: record.status,
        message: 'Revocation intake recorded; escalated to Root'
      });
    });

    // Safe Tracking Lookup (FR-H6: sanitized response)
    opsApp.get('/api/requests/track/:id', (req, res) => {
      const reqId = req.params.id;
      const record = mockDb.requests.get(reqId);
      if (!record) {
        return res.status(404).json({ error: 'REQUEST_NOT_FOUND', message: `Request ID ${reqId} not found` });
      }

      // Compute 4-step stepper position
      let currentStep = 1;
      let stepLabel = 'Intake Submitted';
      if (record.status === 'PENDING') {
        currentStep = 1;
        stepLabel = 'Intake Received';
      } else if (record.status === 'UNDER_REVIEW') {
        currentStep = 2;
        stepLabel = 'Moderation Review';
      } else if (record.status === 'AWAITING_ROOT_ACCEPT') {
        currentStep = 3;
        stepLabel = 'Root Administrator Authorization';
      } else if (record.status === 'EXECUTED') {
        currentStep = 4;
        stepLabel = 'Ledger Committed & Active';
      } else if (record.status === 'REJECTED') {
        currentStep = -1;
        stepLabel = 'Rejected';
      } else if (record.status === 'FLAGGED') {
        currentStep = 2;
        stepLabel = 'Under Security Review (Flagged)';
      }

      return res.status(200).json({
        requestId: record.id,
        requestType: record.request_type,
        submissionChannel: record.submission_channel,
        status: record.status,
        currentStep,
        stepLabel,
        createdAt: record.created_at
        // Notice: claimant sensitive PII is stripped per FR-H6
      });
    });

    // 2. Setup Mock Gateway Server
    const gwApp = express();
    gwApp.use(express.json());

    gwApp.get('/healthz', (req, res) => res.json({ status: 'ok', service: 'mock-gateway' }));

    gwApp.post('/verify', (req, res) => {
      const { credentialId, dataHash } = req.body;
      if (!credentialId && !dataHash) {
        return res.status(400).json({ error: 'Either credentialId or dataHash is required' });
      }

      const cred = mockDb.credentials.get(credentialId);
      if (!cred) {
        return res.status(404).json({
          valid: false,
          error: 'NOT_FOUND',
          message: 'Credential not registered on ScatterID ledger'
        });
      }

      const isRevoked = cred.status === 'REVOKED';
      return res.status(200).json({
        valid: !isRevoked,
        credentialId: cred.credentialId,
        status: cred.status,
        level1_integrity: true,
        level2_authenticity: !isRevoked,
        algorithm: 'ML-DSA-87 (NIST FIPS 204)',
        revocationDetails: isRevoked ? { reason: cred.revocationReason, revokedAt: cred.revokedAt } : null
      });
    });

    gwApp.post('/issue', (req, res) => {
      const { dataHash, idempotencyKey } = req.body;
      if (!dataHash || dataHash.length !== 64) {
        return res.status(400).json({ error: 'A 64-character SHA3-256 dataHash is required' });
      }
      const credId = `cred_gw_${Date.now()}`;
      mockDb.credentials.set(credId, {
        credentialId: credId,
        dataHash,
        status: 'ACTIVE',
        signatureAlgorithm: 'ML-DSA-87'
      });
      return res.status(201).json({
        success: true,
        credentialId: credId,
        transactionId: `tx_gw_${Date.now()}`
      });
    });

    // Start mock servers on ephemeral ports
    await new Promise((resolve) => {
      mockOpsServer = opsApp.listen(0, '127.0.0.1', () => {
        opsUrl = `http://127.0.0.1:${mockOpsServer.address().port}`;
        resolve();
      });
    });

    await new Promise((resolve) => {
      mockGatewayServer = gwApp.listen(0, '127.0.0.1', () => {
        gatewayUrl = `http://127.0.0.1:${mockGatewayServer.address().port}`;
        resolve();
      });
    });

    // Start Portal App pointing to mock backends
    const portalAppInstance = createPortalApp({
      opsDashboardUrl: opsUrl,
      gatewayUrl: gatewayUrl
    });

    await new Promise((resolve) => {
      portalServer = http.createServer(portalAppInstance);
      portalServer.listen(0, '127.0.0.1', () => {
        portalUrl = `http://127.0.0.1:${portalServer.address().port}`;
        resolve();
      });
    });
  });

  after(async () => {
    if (portalServer) await new Promise((res) => portalServer.close(res));
    if (mockOpsServer) await new Promise((res) => mockOpsServer.close(res));
    if (mockGatewayServer) await new Promise((res) => mockGatewayServer.close(res));
  });

  // =========================================================================
  // SUITE 1: CLERK AUTHENTICATION & FIRST-TIME ONBOARDING FLOW
  // =========================================================================
  describe('1. Clerk Authentication & First-Time Onboarding Flow', () => {
    let tempToken;
    let activeClerkToken;

    test('1.1 Login with wrong password returns 401 Invalid Credentials', async () => {
      const res = await fetch(`${portalUrl}/api/portal/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'clerk_test', password: 'WrongPassword123!' })
      });
      assert.equal(res.status, 401);
      const data = await res.json();
      assert.equal(data.error, 'INVALID_CREDENTIALS');
    });

    test('1.2 First-time login detects requireFirstTimeSetup: true and returns tempToken', async () => {
      const res = await fetch(`${portalUrl}/api/portal/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'clerk_test', password: 'TempPassword2026!' })
      });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.status, 'SETUP_REQUIRED');
      assert.equal(data.requireFirstTimeSetup, true);
      assert.ok(data.tempToken);
      tempToken = data.tempToken;
    });

    test('1.3 First-time setup rejects passwords under 10 chars', async () => {
      const res = await fetch(`${portalUrl}/api/portal/first-time-setup`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${tempToken}`
        },
        body: JSON.stringify({
          newPassword: 'Short1!',
          confirmPassword: 'Short1!'
        })
      });
      assert.equal(res.status, 400);
      const data = await res.json();
      assert.equal(data.error, 'PASSWORD_WEAK');
    });

    test('1.4 First-time setup rejects mismatched confirm password', async () => {
      const res = await fetch(`${portalUrl}/api/portal/first-time-setup`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${tempToken}`
        },
        body: JSON.stringify({
          newPassword: 'ValidPassword2026!#',
          confirmPassword: 'DifferentPassword2026!#'
        })
      });
      assert.equal(res.status, 400);
      const data = await res.json();
      assert.equal(data.error, 'PASSWORD_MISMATCH');
    });

    test('1.5 First-time setup rejects password lacking character complexity', async () => {
      const res = await fetch(`${portalUrl}/api/portal/first-time-setup`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${tempToken}`
        },
        body: JSON.stringify({
          newPassword: 'alllowercasepassword123!',
          confirmPassword: 'alllowercasepassword123!'
        })
      });
      assert.equal(res.status, 400);
      const data = await res.json();
      assert.equal(data.error, 'PASSWORD_COMPLEXITY_FAILED');
    });

    test('1.6 First-time setup succeeds with compliant password and activates session token', async () => {
      const res = await fetch(`${portalUrl}/api/portal/first-time-setup`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${tempToken}`
        },
        body: JSON.stringify({
          newPassword: 'ComplexClerkPass2026!#',
          confirmPassword: 'ComplexClerkPass2026!#'
        })
      });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.success, true);
      assert.ok(data.token);
      activeClerkToken = data.token;
    });

    test('1.7 /api/portal/me verifies the authenticated clerk profile', async () => {
      const res = await fetch(`${portalUrl}/api/portal/me`, {
        headers: { 'Authorization': `Bearer ${activeClerkToken}` }
      });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.user.username, 'clerk_test');
      assert.equal(data.user.role, 'clerk');
    });

    test('1.8 Regular login now succeeds with newly configured password without setup flag', async () => {
      const res = await fetch(`${portalUrl}/api/portal/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'clerk_test', password: 'ComplexClerkPass2026!#' })
      });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.ok(data.token);
      assert.equal(data.user.role, 'clerk');
    });
  });

  // =========================================================================
  // SUITE 2: ISSUE DESK INPUT BOUNDARY, SANITIZATION & CHECKLIST
  // =========================================================================
  describe('2. Issue Desk Input Boundary, Sanitization & Checklist Tests', () => {
    const validClerkToken = 'session_token_usr_clerk_01';

    test('2.1 Issue intake rejects request without claimant fullName', async () => {
      const res = await fetch(`${portalUrl}/api/portal/issue`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${validClerkToken}`
        },
        body: JSON.stringify({
          submission_channel: 'hard',
          claimant_data: { identifierNumber: 'ID-999' },
          inspection_checklist: {
            substrate_material_integrity: true,
            optical_security_features: true,
            biometric_face_match: true,
            authority_seal_and_serial: true
          }
        })
      });
      assert.equal(res.status, 400);
      const data = await res.json();
      assert.equal(data.error, 'MISSING_CLAIMANT');
    });

    test('2.2 Hard Channel rejects when any of 4 physical inspection checkpoints is missing', async () => {
      const res = await fetch(`${portalUrl}/api/portal/issue`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${validClerkToken}`
        },
        body: JSON.stringify({
          submission_channel: 'hard',
          claimant_data: { fullName: 'Elena Rostova' },
          inspection_checklist: {
            substrate_material_integrity: true,
            optical_security_features: true,
            biometric_face_match: false, // Incomplete!
            authority_seal_and_serial: true
          }
        })
      });
      assert.equal(res.status, 400);
      const data = await res.json();
      assert.equal(data.error, 'INCOMPLETE_CHECKLIST');
    });

    test('2.3 Hard Channel succeeds with complete 4-point checklist and returns Request ID', async () => {
      const res = await fetch(`${portalUrl}/api/portal/issue`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${validClerkToken}`,
          'X-Station-Id': 'Counter-05'
        },
        body: JSON.stringify({
          submission_channel: 'hard',
          claimant_data: {
            fullName: 'Elena Rostova',
            dateOfBirth: '1992-04-15',
            credentialType: 'CivilIdentityAttestation',
            identifierNumber: 'SCT-994820',
            issuingAuthority: 'ScatterID Attestation Bureau',
            documentSerial: 'DS-2026-X88'
          },
          inspection_checklist: {
            substrate_material_integrity: true,
            optical_security_features: true,
            biometric_face_match: true,
            authority_seal_and_serial: true
          }
        })
      });
      assert.equal(res.status, 201);
      const data = await res.json();
      assert.equal(data.success, true);
      assert.ok(data.requestId.startsWith('req_issue_'));
      assert.equal(data.submission_channel, 'hard');
    });

    test('2.4 Soft Channel rejects missing or invalid SHA-256 evidence digest', async () => {
      // Missing
      const res1 = await fetch(`${portalUrl}/api/portal/issue`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${validClerkToken}`
        },
        body: JSON.stringify({
          submission_channel: 'soft',
          claimant_data: { fullName: 'Marcus Vance' },
          evidence_sha256: ''
        })
      });
      assert.equal(res1.status, 400);
      const data1 = await res1.json();
      assert.equal(data1.error, 'INVALID_EVIDENCE_HASH');

      // Invalid length / characters
      const res2 = await fetch(`${portalUrl}/api/portal/issue`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${validClerkToken}`
        },
        body: JSON.stringify({
          submission_channel: 'soft',
          claimant_data: { fullName: 'Marcus Vance' },
          evidence_sha256: 'xyz_not_a_valid_hex_hash'
        })
      });
      assert.equal(res2.status, 400);
      const data2 = await res2.json();
      assert.equal(data2.error, 'INVALID_EVIDENCE_HASH');
    });

    test('2.5 Soft Channel computes valid SHA-256 and succeeds with 64-character digest', async () => {
      const scanBuffer = Buffer.from('Mock scanned identity document evidence 2026');
      const evidenceHash = createHash('sha256').update(scanBuffer).digest('hex');
      assert.equal(evidenceHash.length, 64);

      const res = await fetch(`${portalUrl}/api/portal/issue`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${validClerkToken}`
        },
        body: JSON.stringify({
          submission_channel: 'soft',
          claimant_data: {
            fullName: 'Marcus Vance',
            identifierNumber: 'SCT-883190',
            issuingAuthority: 'ScatterID Soft Intake Desk'
          },
          evidence_sha256: evidenceHash
        })
      });
      assert.equal(res.status, 201);
      const data = await res.json();
      assert.equal(data.success, true);
      assert.equal(data.status, 'AWAITING_ROOT_ACCEPT');
    });

    test('2.6 Tamper Detection: Changing scan content yields distinct hash', () => {
      const original = Buffer.from('Original Document Scan Contents');
      const tampered = Buffer.from('Tampered Document Scan Contents');

      const hash1 = createHash('sha256').update(original).digest('hex');
      const hash2 = createHash('sha256').update(tampered).digest('hex');

      assert.notEqual(hash1, hash2);
      assert.equal(hash1.length, 64);
      assert.equal(hash2.length, 64);
    });

    test('2.7 Input boundary test: Max-length string handling & sanitization', async () => {
      const longName = 'A'.repeat(250);
      const res = await fetch(`${portalUrl}/api/portal/issue`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${validClerkToken}`
        },
        body: JSON.stringify({
          submission_channel: 'hard',
          claimant_data: {
            fullName: longName,
            identifierNumber: 'SCT-LONG-01'
          },
          inspection_checklist: {
            substrate_material_integrity: true,
            optical_security_features: true,
            biometric_face_match: true,
            authority_seal_and_serial: true
          }
        })
      });
      assert.equal(res.status, 201);
    });
  });

  // =========================================================================
  // SUITE 3: CRYPTOGRAPHIC HASH ENGINE (RFC 8785 + SHA3-256)
  // =========================================================================
  describe('3. Deterministic Cryptographic Hash Engine (RFC 8785 + SHA3-256)', () => {
    test('3.1 Canonicalizes claim JSON and salts with 16-byte random salt', async () => {
      const claim = {
        fullName: 'Kelechi Okonkwo',
        effectiveYear: 2026,
        jurisdiction: 'ScatterID Registry'
      };

      const res = await fetch(`${portalUrl}/api/hash`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ claim })
      });

      assert.equal(res.status, 200);
      const data = await res.json();
      assert.ok(data.salt);
      assert.equal(data.salt.length, 32); // 16 bytes = 32 hex chars
      assert.equal(data.canonicalJson, '{"effectiveYear":2026,"fullName":"Kelechi Okonkwo","jurisdiction":"ScatterID Registry"}');
      assert.equal(data.dataHash.length, 64);
    });

    test('3.2 Rejects malformed salt (must be 32 hex characters)', async () => {
      const res = await fetch(`${portalUrl}/api/hash`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          claim: { a: 1 },
          salt: 'bad_salt_too_short'
        })
      });
      assert.equal(res.status, 400);
      const data = await res.json();
      assert.ok(data.error.includes('32-character hexadecimal'));
    });

    test('3.3 Key order invariance: different key ordering produces identical canonicalJson and dataHash', async () => {
      const salt = '0123456789abcdef0123456789abcdef';
      const claim1 = { z: 10, a: 20, m: 30 };
      const claim2 = { m: 30, z: 10, a: 20 };

      const res1 = await fetch(`${portalUrl}/api/hash`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ claim: claim1, salt })
      });
      const data1 = await res1.json();

      const res2 = await fetch(`${portalUrl}/api/hash`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ claim: claim2, salt })
      });
      const data2 = await res2.json();

      assert.equal(data1.canonicalJson, data2.canonicalJson);
      assert.equal(data1.dataHash, data2.dataHash);
    });
  });

  // =========================================================================
  // SUITE 4: VERIFY DESK & TWO-LEVEL CRYPTOGRAPHIC VERIFICATION
  // =========================================================================
  describe('4. Verify Desk & Two-Level Cryptographic Verification', () => {
    test('4.1 Verifies active credential with valid Level 1 integrity & Level 2 authenticity', async () => {
      const res = await fetch(`${portalUrl}/api/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ credentialId: 'cred_valid_100' })
      });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.valid, true);
      assert.equal(data.status, 'ACTIVE');
      assert.equal(data.level1_integrity, true);
      assert.equal(data.level2_authenticity, true);
      assert.equal(data.algorithm, 'ML-DSA-87 (NIST FIPS 204)');
    });

    test('4.2 Detects revoked credential and returns revocation details', async () => {
      const res = await fetch(`${portalUrl}/api/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ credentialId: 'cred_revoked_200' })
      });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.valid, false);
      assert.equal(data.status, 'REVOKED');
      assert.equal(data.level2_authenticity, false);
      assert.ok(data.revocationDetails);
      assert.equal(data.revocationDetails.reason, 'COMPROMISED_KEY');
    });

    test('4.3 Non-existent credential returns 404 NOT_FOUND', async () => {
      const res = await fetch(`${portalUrl}/api/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ credentialId: 'cred_non_existent_999' })
      });
      assert.equal(res.status, 404);
      const data = await res.json();
      assert.equal(data.error, 'NOT_FOUND');
    });
  });

  // =========================================================================
  // SUITE 5: REVOKE DESK & MANDATORY DOCKET ENFORCEMENT
  // =========================================================================
  describe('5. Revoke Desk & Mandatory Docket Enforcement', () => {
    const validClerkToken = 'session_token_usr_clerk_01';

    test('5.1 Rejects revocation intake missing credential_id', async () => {
      const res = await fetch(`${portalUrl}/api/portal/revoke`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${validClerkToken}`
        },
        body: JSON.stringify({
          reason: 'Key compromised',
          docket_reference: 'DOC-1234'
        })
      });
      assert.equal(res.status, 400);
      const data = await res.json();
      assert.equal(data.error, 'MISSING_CREDENTIAL_ID');
    });

    test('5.2 Rejects revocation intake missing reason', async () => {
      const res = await fetch(`${portalUrl}/api/portal/revoke`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${validClerkToken}`
        },
        body: JSON.stringify({
          credential_id: 'cred_valid_100',
          docket_reference: 'DOC-1234'
        })
      });
      assert.equal(res.status, 400);
      const data = await res.json();
      assert.equal(data.error, 'MISSING_REASON');
    });

    test('5.3 Rejects revocation intake missing mandatory docket reference', async () => {
      const res = await fetch(`${portalUrl}/api/portal/revoke`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${validClerkToken}`
        },
        body: JSON.stringify({
          credential_id: 'cred_valid_100',
          reason: 'Lost device'
        })
      });
      assert.equal(res.status, 400);
      const data = await res.json();
      assert.equal(data.error, 'MISSING_DOCKET');
    });

    test('5.4 Revocation intake succeeds and escalates to Root Authorization', async () => {
      const res = await fetch(`${portalUrl}/api/portal/revoke`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${validClerkToken}`
        },
        body: JSON.stringify({
          credential_id: 'cred_valid_100',
          reason: 'Physical credential destroyed',
          submission_channel: 'hard',
          docket_reference: 'DOCKET-REV-2026-9901'
        })
      });
      assert.equal(res.status, 201);
      const data = await res.json();
      assert.equal(data.success, true);
      assert.ok(data.requestId.startsWith('req_revoke_'));
      assert.equal(data.status, 'AWAITING_ROOT_ACCEPT');
    });
  });

  // =========================================================================
  // SUITE 6: REQUEST TRACKING & 4-STEP STEPPER RESOLUTION
  // =========================================================================
  describe('6. Request Tracking & 4-Step Stepper Resolution (FR-H6)', () => {
    let testReqId;

    before(async () => {
      // Create request in DB to track
      testReqId = 'req_track_demo_100';
      mockDb.requests.set(testReqId, {
        id: testReqId,
        request_type: 'issuance',
        submission_channel: 'soft',
        claimant_name: 'Sensitive Name Should Not Leak',
        status: 'AWAITING_ROOT_ACCEPT',
        created_at: new Date().toISOString()
      });
    });

    test('6.1 Safe tracking lookup returns currentStep 3 (Root Authorization)', async () => {
      const res = await fetch(`${portalUrl}/api/portal/track/${testReqId}`);
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.requestId, testReqId);
      assert.equal(data.currentStep, 3);
      assert.equal(data.stepLabel, 'Root Administrator Authorization');
      // Verify FR-H6 privacy: claimant_name not present
      assert.equal(data.claimant_name, undefined);
    });

    test('6.2 Safe tracking lookup resolves Step 4 for EXECUTED request', async () => {
      const execReqId = 'req_track_exec_200';
      mockDb.requests.set(execReqId, {
        id: execReqId,
        request_type: 'issuance',
        submission_channel: 'hard',
        status: 'EXECUTED',
        created_at: new Date().toISOString()
      });

      const res = await fetch(`${portalUrl}/api/portal/track/${execReqId}`);
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.currentStep, 4);
      assert.equal(data.stepLabel, 'Ledger Committed & Active');
    });

    test('6.3 Safe tracking lookup returns 404 for unknown request ID', async () => {
      const res = await fetch(`${portalUrl}/api/portal/track/req_unknown_99999`);
      assert.equal(res.status, 404);
      const data = await res.json();
      assert.equal(data.error, 'REQUEST_NOT_FOUND');
    });
  });

  // =========================================================================
  // SUITE 7: HEALTH PROBE & SYSTEM CONNECTIVITY
  // =========================================================================
  describe('7. Health Probe & Upstream Diagnostic Connectivity', () => {
    test('7.1 /api/health probes Gateway and Ops Dashboard status correctly', async () => {
      const res = await fetch(`${portalUrl}/api/health`);
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.portal, 'operational');
      assert.equal(data.gateway, 'connected');
      assert.equal(data.opsDashboard, 'connected');
    });
  });
});
