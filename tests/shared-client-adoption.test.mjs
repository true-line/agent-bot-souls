// The Soul adapter uses the exact reviewed shared client and its strict
// validation/session cleanup, while retaining the runtime's real loader.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:net';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadContracts } from '../lib/contracts.mjs';
import { attachHq, connectHq } from '../lib/hq-client.mjs';
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

test('launch attach preserves adapter bytes that share the HQ reply read', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'launch-attach-'));
  const path = join(dir, 'admission.sock');
  const launchId = `ln_${'a1'.repeat(12)}`;
  const operations = [];
  const server = createServer((socket) => {
    readLines(socket, (line) => {
      const request = JSON.parse(line);
      operations.push(request.op);
      socket.write(`${JSON.stringify({ id: request.id, ok: true, result: { launch_id: launchId } })}\n${JSON.stringify({ jsonrpc: '2.0', id: 7, result: { ready: true } })}\n`);
    });
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(path, resolve); });
  t.after(async () => { await new Promise((resolve) => server.close(resolve)); rmSync(dir, { recursive: true, force: true }); });

  for (const operation of ['launch.attach', 'stage2a.member.attach']) {
    const stream = await attachHq(path, { launch_id: launchId, attach: 'b2'.repeat(32) },
      { operation });
    const line = new Promise((resolve) => readLines(stream, resolve));
    stream.resume();
    assert.deepEqual(JSON.parse(await line), { jsonrpc: '2.0', id: 7, result: { ready: true } });
    stream.destroy();
  }
  assert.deepEqual(operations, ['launch.attach', 'stage2a.member.attach']);
});

test('launch attach rejects malformed host and shared refusals as contract failures', async () => {
  const contracts = loadContracts();
  const replies = [
    { id: 1, ok: false, host_refusal: { code: 'host.launch_unavailable' } },
    { id: 1, ok: false, refusal: { error: 'lease_expired', explanation: 7 } },
  ];
  for (const reply of replies) {
    const dir = mkdtempSync(join(tmpdir(), 'launch-attach-refusal-'));
    const path = join(dir, 'admission.sock');
    const server = createServer((socket) => readLines(socket, () => writeLine(socket, reply)));
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(path, resolve); });
    try {
      await assert.rejects(
        attachHq(path, { launch_id: `ln_${'a1'.repeat(12)}`, attach: 'b2'.repeat(32) }, { contracts }),
        (error) => error?.name !== 'HqRefusal',
      );
    } finally {
      await new Promise((resolve) => server.close(resolve));
      rmSync(dir, { recursive: true, force: true });
    }
  }
});
