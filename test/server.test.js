import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { app, SAMPLE_PRESETS } from '../server.js';

let server;
let baseUrl;

test.before(async () => {
  await new Promise((resolve) => {
    server = http.createServer(app);
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      baseUrl = `http://127.0.0.1:${addr.port}`;
      resolve();
    });
  });
});

test.after(async () => {
  await new Promise((resolve) => {
    server.close(resolve);
  });
});

test('GET /healthz returns status ok', async () => {
  const res = await fetch(`${baseUrl}/healthz`);
  assert.equal(res.status, 200);
  const data = await res.json();
  assert.equal(data.status, 'ok');
  assert.equal(data.service, 'scatterid-app');
});

test('GET /api/presets returns standard claim presets', async () => {
  const res = await fetch(`${baseUrl}/api/presets`);
  assert.equal(res.status, 200);
  const data = await res.json();
  assert.ok(Array.isArray(data.presets));
  assert.equal(data.presets.length, 4);
  assert.equal(data.presets[0].id, 'identity-record');
});

test('POST /api/hash computes canonical SHA3-256 hash', async () => {
  const claim = { subject: 'Alice', role: 'Engineer' };
  const salt = '00112233445566778899aabbccddeeff';

  const res = await fetch(`${baseUrl}/api/hash`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ claim, salt })
  });

  assert.equal(res.status, 200);
  const data = await res.json();
  assert.equal(data.salt, salt);
  assert.equal(data.canonicalJson, '{"role":"Engineer","subject":"Alice"}');
  assert.equal(typeof data.dataHash, 'string');
  assert.equal(data.dataHash.length, 64);
});

test('POST /api/hash rejects invalid claim or malformed salt', async () => {
  // Missing claim
  const res1 = await fetch(`${baseUrl}/api/hash`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({})
  });
  assert.equal(res1.status, 400);

  // Malformed salt
  const res2 = await fetch(`${baseUrl}/api/hash`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ claim: { a: 1 }, salt: 'invalid-salt' })
  });
  assert.equal(res2.status, 400);
});

test('POST /api/issue rejects missing or invalid dataHash', async () => {
  const res = await fetch(`${baseUrl}/api/issue`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ dataHash: 'too-short' })
  });
  assert.equal(res.status, 400);
  const data = await res.json();
  assert.ok(data.error.includes('64-character SHA3-256 dataHash'));
});

test('POST /api/verify rejects request with neither credentialId nor dataHash', async () => {
  const res = await fetch(`${baseUrl}/api/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({})
  });
  assert.equal(res.status, 400);
  const data = await res.json();
  assert.ok(data.error.includes('Either credentialId or dataHash is required'));
});
