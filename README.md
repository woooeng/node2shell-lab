# CVE-2026-111497 — Test Lab

An isolated, container-based lab for **CVE-2026-111497**: an out-of-bounds heap
write in the Google **Brotli** decoder bundled by **Node.js** (and Bun). A
crafted `Content-Encoding: br` stream fed to the decoder can crash the process,
leak memory, or lead to remote code execution.

- **Fixed in:** Node.js **22.23.4**, **24.22.1**, **26.12.1**; Bun **1.4.4**.
- **No fix (EOL):** Node.js 25.x, 23.x, 20.x and earlier.
- **Scores:** NVD CVSS v3 **9.8**, OSV CVSS v4 **9.2**, Red Hat v3 8.1 ("Important").
- **CISA KEV:** added **2026-10-27** (in-the-wild exploitation).

## ⚠️ Scope — what this lab is and is not

This is a **defensive / educational** lab for **authorized** testing. It lets you:

1. **Detect exposure** by runtime version (the real-world "am I affected?" check).
2. **See the vulnerable code sink** — the exact `brotliDecompressSync` pattern.
3. **Differentially test** hostile/malformed Brotli against a vulnerable vs. a
   patched runtime and watch how each behaves (clean reject vs. crash/restart).

It ships **benign fuzz inputs only** (truncated, garbage, structurally-invalid
streams). It contains **no weaponized OOB-write / RCE payload** and no shellcode.
Keep it on your own machine; do not point it at systems you do not own.

## Components

| Service   | Image                        | Node     | Status     | Port |
|-----------|------------------------------|----------|------------|------|
| `vuln`    | `node:22.14.0-bookworm-slim` | 22.14.0  | VULNERABLE | 3001 |
| `patched` | `node:22-bookworm-slim`      | 22.23.5  | PATCHED    | 3002 |
| `gateway` | `node:22-bookworm-slim`      | 22.23.5  | dashboard  | 8080 |

```
web/index.html   dashboard UI
web/gateway.js   serves dashboard + proxies tests, detects crash vs. reject
server/server.js target server: /info (exposure) + POST /decode (the sink)
```

## Run

```bash
cd cve-2026-111497-lab
docker compose up -d
```

Then open the dashboard: **http://localhost:8080**

- Each card shows the target's Node/Brotli version and a VULNERABLE/PATCHED verdict.
- "Decoder test harness": pick a payload + target, send it to `/decode`.
  - `REJECTED (422)` = runtime cleanly refused hostile input.
  - `DECODED` = valid round-trip succeeded.
  - `CRASH / RESET` = target died mid-decode (the crash/DoS symptom). The card's
    **PID**/**Uptime** will change on the next refresh when the container restarts.

### CLI equivalents

```bash
curl -s localhost:3001/info | jq        # vulnerable target exposure report
curl -s localhost:3002/info | jq        # patched target
# send a payload through the gateway proxy:
curl -s localhost:8080/api/decode -H 'content-type: application/json' \
  -d '{"target":"vuln","payloadId":"garbage"}' | jq
```

## Note on the Brotli version string

Both runtimes report `process.versions.brotli == 1.1.0`. Node **backports** the
security fix without bumping that string, so **you cannot judge exposure from the
Brotli version** — judge it from the **Node.js version**. The lab's verdict logic
(`server/server.js → exposure()`) does exactly that.

## Teardown

```bash
docker compose down            # stop & remove containers + network
./scripts/teardown.sh          # the above, plus remove pulled images
```

## References

- OpenCVE — https://app.opencve.io/cve/CVE-2026-111497
- Red Hat — https://access.redhat.com/security/cve/cve-2026-111497
- OSV — https://osv.dev/vulnerability/CVE-2026-111497
- Cycode write-up — https://cycode.com/blog/node2shell-cve-2026-111497/
- Aikido write-up — https://www.aikido.dev/blog/node2shell-nodejs-brotli-rce-cve-2026-111497
