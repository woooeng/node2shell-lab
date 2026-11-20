'use strict';
/*
 * CVE-2026-111497 lab — web gateway.
 * Serves the dashboard and proxies tests to the two target servers so the
 * browser never deals with CORS, and so we can distinguish a *clean reject*
 * (HTTP 422 from the target) from a *crash* (connection reset / refused, i.e.
 * the target process died mid-decode — the observable symptom of the OOB bug).
 */

const http = require('http');
const zlib = require('zlib');
const fs = require('fs');
const path = require('path');

const PORT = Number(process.env.PORT || 8080);
const TARGETS = {
  vuln: process.env.VULN_URL || 'http://vuln:3000',
  patched: process.env.PATCHED_URL || 'http://patched:3000',
};

// ---- Test payloads --------------------------------------------------------
// Valid round-trip + a set of *benign* hostile/malformed Brotli streams.
// These are fuzz-style inputs (truncated, garbage, structurally invalid). They
// exercise the decoder's hostile-input path. This lab intentionally ships NO
// weaponized OOB-write / RCE payload.
function buildPayloads() {
  const p = [];
  const valid = zlib.brotliCompressSync(Buffer.from('hello from the CVE-2026-111497 lab — this is a valid brotli round-trip\n'.repeat(4)));
  p.push({ id: 'valid', label: 'Valid Brotli (round-trip)', hostile: false, b64: valid.toString('base64') });

  p.push({ id: 'empty', label: 'Empty body', hostile: true, b64: '' });
  p.push({ id: 'truncated', label: 'Truncated valid stream (first 6 bytes)', hostile: true, b64: valid.slice(0, 6).toString('base64') });
  p.push({ id: 'garbage', label: 'Random garbage (256 bytes)', hostile: true, b64: require('crypto').randomBytes(256).toString('base64') });
  p.push({ id: 'allones', label: 'All-0xFF block (128 bytes)', hostile: true, b64: Buffer.alloc(128, 0xff).toString('base64') });
  p.push({ id: 'bitbomb', label: 'Oversized window header + junk', hostile: true,
          b64: Buffer.concat([Buffer.from([0x1b, 0xff, 0xff, 0xff, 0x1f]), require('crypto').randomBytes(64)]).toString('base64') });
  return p;
}
const PAYLOADS = buildPayloads();

function json(res, code, obj) {
  const b = Buffer.from(JSON.stringify(obj));
  res.writeHead(code, { 'content-type': 'application/json' });
  res.end(b);
}

function postToTarget(base, pathname, body) {
  return new Promise((resolve) => {
    const u = new URL(base + pathname);
    const t0 = Date.now();
    const req = http.request(
      { hostname: u.hostname, port: u.port, path: u.pathname, method: body === null ? 'GET' : 'POST',
        headers: body === null ? {} : { 'content-type': 'application/octet-stream', 'content-length': body.length },
        timeout: 8000 },
      (r) => {
        const chunks = [];
        r.on('data', (c) => chunks.push(c));
        r.on('end', () => {
          let parsed = null;
          try { parsed = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { /* ignore */ }
          resolve({ transport: 'ok', status: r.statusCode, body: parsed, elapsedMs: Date.now() - t0 });
        });
      }
    );
    req.on('timeout', () => { req.destroy(new Error('timeout')); });
    req.on('error', (err) => {
      // ECONNRESET / ECONNREFUSED here = the target died or isn't up: the
      // crash/DoS symptom this CVE can produce on an unpatched runtime.
      resolve({ transport: 'failed', error: err.code || err.message, elapsedMs: Date.now() - t0 });
    });
    if (body !== null) req.write(body);
    req.end();
  });
}

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://x');

  if (req.method === 'GET' && (u.pathname === '/' || u.pathname === '/index.html')) {
    const html = fs.readFileSync(path.join(__dirname, 'index.html'));
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    return res.end(html);
  }

  if (req.method === 'GET' && u.pathname === '/api/payloads') {
    return json(res, 200, PAYLOADS.map(({ id, label, hostile, b64 }) => ({ id, label, hostile, bytes: Buffer.from(b64, 'base64').length })));
  }

  if (req.method === 'GET' && u.pathname === '/api/info') {
    const which = u.searchParams.get('target');
    const base = TARGETS[which];
    if (!base) return json(res, 400, { error: 'unknown target' });
    const r = await postToTarget(base, '/info', null);
    return json(res, 200, r);
  }

  if (req.method === 'POST' && u.pathname === '/api/decode') {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', async () => {
      let payload;
      try { payload = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { return json(res, 400, { error: 'bad json' }); }
      const base = TARGETS[payload.target];
      const def = PAYLOADS.find((x) => x.id === payload.payloadId);
      if (!base || !def) return json(res, 400, { error: 'unknown target or payload' });
      const body = Buffer.from(def.b64, 'base64');
      const r = await postToTarget(base, '/decode', body);
      return json(res, 200, { target: payload.target, payloadId: def.id, hostile: def.hostile, inputBytes: body.length, result: r });
    });
    return;
  }

  res.writeHead(404, { 'content-type': 'text/plain' });
  res.end('not found');
});

server.listen(PORT, '0.0.0.0', () => console.log(`gateway on :${PORT} -> ${JSON.stringify(TARGETS)}`));
