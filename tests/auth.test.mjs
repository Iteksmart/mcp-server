import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const PORT = 33217;
const BASE = `http://127.0.0.1:${PORT}`;

async function waitForHealth() {
  const deadline = Date.now() + 10000;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${BASE}/health`);
      if (res.ok) return;
    } catch {}
    await new Promise(r => setTimeout(r, 150));
  }
  throw new Error('server did not become healthy');
}

async function rpc(method, params, key) {
  const headers = { 'content-type': 'application/json' };
  if (key !== undefined) headers['x-itechsmart-mcp-key'] = key;
  const res = await fetch(`${BASE}/messages`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  let body;
  try { body = await res.json(); } catch { body = {}; }
  return { status: res.status, body };
}

const tmp = mkdtempSync(join(tmpdir(), 'itechsmart-mcp-test-'));
writeFileSync(join(tmp, 'ledger.json'), JSON.stringify({ entries: [] }));

const child = spawn(process.execPath, ['dist/index.js'], {
  cwd: process.cwd(),
  env: {
    ...process.env,
    PORT: String(PORT),
    MCP_TRANSPORT: 'http',
    ITECHSMART_MCP_KEYS: 'read-key,admin-key:admin',
    ITECHSMART_MCP_API_KEYS: '',
    CANONICAL_LEDGER_PATH: join(tmp, 'ledger.json'),
    SELF_REPORT_URL: 'http://127.0.0.1:9/noop',
    MCP_RATE_LIMIT_PER_MIN: '1000',
  },
  stdio: ['ignore', 'pipe', 'pipe'],
});

child.stderr.on('data', () => {});
child.stdout.on('data', () => {});
await waitForHealth();

test.after(async () => {
  child.kill('SIGTERM');
  try { await once(child, 'exit'); } catch {}
  rmSync(tmp, { recursive: true, force: true });
});

test('health endpoint is public and identifies UAIO MCP service', async () => {
  const res = await fetch(`${BASE}/health`);
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.status, 'ok');
  assert.equal(body.service, 'itechsmart-uaio-mcp');
});

test('valid x-itechsmart-mcp-key can list tools', async () => {
  const out = await rpc('tools/list', {}, 'read-key');
  assert.equal(out.status, 200);
  assert.ok(Array.isArray(out.body.result.tools));
});

test('invalid key is rejected with 401', async () => {
  const out = await rpc('tools/list', {}, 'bad-key');
  assert.equal(out.status, 401);
});

test('missing key is rejected with 401', async () => {
  const out = await rpc('tools/list', {}, undefined);
  assert.equal(out.status, 401);
});

test('read-only key can call audit scope tool', async () => {
  const out = await rpc('tools/call', { name: 'prooflink.verify_chain', arguments: { limit: 1 } }, 'read-key');
  assert.equal(out.status, 200);
  assert.ok(out.body.result);
});

test('read-only key cannot call mutating tool', async () => {
  const out = await rpc('tools/call', { name: 'approve_sie_finding', arguments: { finding_id: 'test' } }, 'read-key');
  assert.equal(out.status, 403);
  assert.match(out.body.error.message, /admin scope required/i);
});
