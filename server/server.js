'use strict';
/*
 * CVE-2026-111497 test lab — demonstration target server.
 *
 * This server reproduces the *attack surface*: an HTTP endpoint that accepts an
 * untrusted Brotli-compressed request body and decompresses it with the Node.js
 * built-in zlib Brotli decoder (the component that bundles the vulnerable
 * Google Brotli library). This is the same pattern used by Express when a
 * request arrives with `Content-Encoding: br` and a middleware inflates it.
 *
 * It is NOT a weaponized exploit. There is no OOB-write / RCE payload here.
 * The lab is for defenders: confirm version exposure, see the vulnerable code
 * pattern, and observe how a patched vs. unpatched runtime handles hostile /
 * malformed Brotli input.
 */

const http = require('http');
const zlib = require('zlib');
const process = require('process');

const PORT = Number(process.env.PORT || 3000);
const ROLE = process.env.ROLE || 'unknown'; // "vulnerable" | "patched"
const START = Date.now();

// ---- Version / exposure analysis -----------------------------------------
// Fixed Node.js lines for CVE-2026-111497: 22.23.4, 24.22.1, 26.12.1.
// Anything below the fix on an affected major (and EOL majors) is exposed.
function parse(v) {
  return v.replace(/^v/, '').split('.').map(Number);
}
function cmp(a, b) {
  for (let i = 0; i < 3; i++) {
    if ((a[i] || 0) !== (b[i] || 0)) return (a[i] || 0) - (b[i] || 0);
  }
  return 0;
}
function exposure() {
  const v = parse(process.versions.node);
  const major = v[0];
  const fixes = { 22: [22, 23, 4], 24: [24, 22, 1], 26: [26, 12, 1] };
  if (fixes[major]) {
    const patched = cmp(v, fixes[major]) >= 0;
    return {
      vulnerable: !patched,
      reason: patched
        ? `Node ${process.versions.node} is at or above the fixed ${fixes[major].join('.')} for the ${major}.x line.`
        : `Node ${process.versions.node} is below the fixed ${fixes[major].join('.')} for the ${major}.x line.`,
    };
  }
  // Majors with no dedicated fix line (25, 23, 20 and earlier) are EOL / no fix.
  return {
    vulnerable: true,
    reason: `Node ${process.versions.node} (${major}.x) has no patched release — End of Life, no fix.`,
  };
}

function send(res, code, obj) {
  const body = Buffer.from(JSON.stringify(obj));
  res.writeHead(code, {
    'content-type': 'application/json',
    'access-control-allow-origin': '*',
    'access-control-allow-headers': '*',
    'access-control-allow-methods': 'GET,POST,OPTIONS',
  });
  res.end(body);
}

const server = http.createServer((req, res) => {
  if (req.method === 'OPTIONS') return send(res, 204, {});

  // --- metadata / exposure report
  if (req.method === 'GET' && req.url === '/info') {
    const e = exposure();
    return send(res, 200, {
      role: ROLE,
      node: process.versions.node,
      brotli: process.versions.brotli || zlib.constants.BROTLI_VERSION || 'bundled',
      modules: process.versions.modules,
      vulnerable: e.vulnerable,
      reason: e.reason,
      cve: 'CVE-2026-111497',
      pid: process.pid,
      uptimeSec: Math.round((Date.now() - START) / 1000),
    });
  }

  // --- the vulnerable surface: decode an untrusted Brotli body
  if (req.method === 'POST' && req.url === '/decode') {
    const chunks = [];
    let total = 0;
    req.on('data', (c) => {
      total += c.length;
      if (total > 8 * 1024 * 1024) { req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      const input = Buffer.concat(chunks);
      const t0 = process.hrtime.bigint();
      try {
        // >>> This single call is the exploitable sink. On an unpatched
        //     runtime, a crafted stream can trigger the Brotli OOB heap write.
        const out = zlib.brotliDecompressSync(input);
        const ms = Number(process.hrtime.bigint() - t0) / 1e6;
        return send(res, 200, {
          ok: true,
          inputBytes: input.length,
          outputBytes: out.length,
          outputPreview: out.slice(0, 64).toString('utf8'),
          decodeMs: Number(ms.toFixed(3)),
        });
      } catch (err) {
        const ms = Number(process.hrtime.bigint() - t0) / 1e6;
        // A *patched* runtime cleanly rejects hostile input here.
        return send(res, 422, {
          ok: false,
          inputBytes: input.length,
          error: err.code || err.name,
          message: String(err.message).slice(0, 200),
          decodeMs: Number(ms.toFixed(3)),
        });
      }
    });
    req.on('error', () => send(res, 400, { ok: false, error: 'REQUEST_ERROR' }));
    return;
  }

  send(res, 404, { error: 'not found', routes: ['/info', 'POST /decode'] });
});

server.listen(PORT, '0.0.0.0', () => {
  const e = exposure();
  console.log(`[${ROLE}] node ${process.versions.node} brotli ${process.versions.brotli} ` +
              `vulnerable=${e.vulnerable} listening on :${PORT}`);
});
