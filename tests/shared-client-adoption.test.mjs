// The Soul adapter uses the exact reviewed shared client and its strict
// validation/session cleanup, while retaining the runtime's real loader.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:net';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadContracts } from '../lib/contracts.mjs';
import { connectHq } from '../lib/hq-client.mjs';
import { connectMember } from '../lib/member.mjs';
import { readLines, writeLine } from '../lib/ndjson.mjs';
import { fixture, SOUL, startHQ } from './harness.mjs';

async function endpoint(t, result) {
  const dir = mkdtempSync(join(tmpdir(), 'shared-client-'));
  const sockets = new Set();
  const requests = [];
  let resolveClosed;
  const closed = new Promise((resolve) => { resolveClosed = resolve; });
  const server = createServer((socket) => {
    sockets.add(socket); socket.on('error', () => {});
    socket.on('close', () => { sockets.delete(socket); resolveClosed(); });
    readLines(socket, (line) => {
      const request = JSON.parse(line); requests.push(request);
      writeLine(socket, { id: request.id, ok: true, result });
    });
  });
  const path = join(dir, 'entry.sock');
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(path, resolve); });
  t.after(async () => { for (const socket of sockets) socket.destroy(); await new Promise((resolve) => server.close(resolve)); rmSync(dir, { recursive: true, force: true }); });
  return { path, requests, closed };
}

test('adopted session refuses malformed member hello and closes the entry socket without fetching a runtime', { timeout: 5000 }, async (t) => {
  const valid = { soul_id: SOUL, member_id: 'm_lead', role: 'lead' };
  for (const [name, value] of [
    ['null', null], ['array', []], ['missing fields', {}],
    ['invalid Soul id', { ...valid, soul_id: `${SOUL}\n` }],
    ['invalid member id', { ...valid, member_id: 7 }],
    ['invalid role', { ...valid, role: 'lead\n' }],
  ]) await t.test(name, async (sub) => {
    const entry = await endpoint(sub, value);
    await assert.rejects(connectMember({ AGENT_BOT_SOULS_SOCKET: entry.path, AGENT_BOT_SOULS_MEMBER_TOKEN: 'test-member-token' }), /invalid member identity/);
    await entry.closed;
    assert.deepEqual(entry.requests.map((request) => request.op), ['hello']);
  });
});

test('adopted local client rejects an asynchronous real validator before sending', { timeout: 5000 }, async (t) => {
  const verified = loadContracts();
  const entry = await endpoint(t, {});
  // Validation is genuine, but making it async violates the SDK contract.
  const contracts = { ...verified, async record(schema, value) { return verified.record(schema, value); } };
  const client = await connectHq(entry.path, { contracts });
  t.after(() => client.close());
  await assert.rejects(client.request('Hello', fixture('positive/hello.first-start.json').input), /validation must be synchronous/);
  await client.close(); await entry.closed;
  assert.deepEqual(entry.requests, []);
});

test('adopted local client refuses asynchronous admission validation on the real HQ reply', async (t) => {
  const hq = await startHQ(); t.after(() => hq.done());
  const verified = loadContracts();
  const contracts = { ...verified, async admission(result, hello) { return verified.admission(result, hello); } };
  const client = await connectHq(hq.hq.paths.admission, { contracts });
  t.after(() => client.close());
  await assert.rejects(client.request('Hello', { ...fixture('positive/hello.first-start.json').input, request_id: 'shared_async_validation' }), /validation must be synchronous/);
  assert.equal(client.closed, true, 'reply rejection poisons the connection before reuse');
  await assert.rejects(client.request('status'), (error) => error.transport === true);
});
