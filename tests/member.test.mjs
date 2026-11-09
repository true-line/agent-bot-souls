// The member's side (lib/member.mjs): binding to HQ's broker with the
// runtime the entry point passes, moving to a new runtime after a newer
// admission, and reconciling a commitment whose reply was lost without
// ever replaying it under a new key (0.4 §7 and §9; T05, T06).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { connectMember, NotCommitted } from '../lib/member.mjs';
import { readLines, writeLine } from '../lib/ndjson.mjs';
import { BIN, hello, SOUL, startHQ } from './harness.mjs';

// An NDJSON server in HQ's framing. `handle(op, payload, socket)` returns
// the result, throws { refusal } or { host_refusal }, or returns DROP to
// cut the connection without answering.
const DROP = Symbol('drop');
async function serve(dir, name, handle) {
  const path = join(dir, name);
  const sockets = new Set();
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => {});
    readLines(socket, async (line) => {
      const req = JSON.parse(line);
      try {
        const result = await handle(req.op, req.payload, socket);
        if (result === DROP) socket.destroy();
        else writeLine(socket, { id: req.id, ok: true, result });
      } catch (e) {
        writeLine(socket, { id: req.id, ok: false, ...e });
      }
    });
  });
  await new Promise((resolve) => { server.listen(path, resolve); });
  return { path, close: () => new Promise((resolve) => { for (const s of sockets) s.destroy(); server.close(resolve); }) };
}

// A stand-in for the entry point's member socket: it answers `runtime`
// with whatever `box.rt` holds.
async function world({ broker }) {
  const dir = mkdtempSync(join(tmpdir(), 'm-'));
  const box = { rt: null, runtimeAsked: 0 };
  const entry = await serve(dir, 'members.sock', (op, payload) => {
    if (op === 'hello') {
      if (payload?.token !== 'tok') throw { host_refusal: { code: 'souls.unknown_member', explanation: 'no' } };
      return { soul_id: SOUL, member_id: 'm_lead', role: 'lead' };
    }
    if (op === 'runtime') { box.runtimeAsked += 1; return { broker, soul_id: SOUL, member_id: 'm_lead', role: 'lead', ...box.rt }; }
    throw { host_refusal: { code: 'souls.unknown_op', explanation: op } };
  });
  const env = { AGENT_BOT_SOULS_SOCKET: entry.path, AGENT_BOT_SOULS_MEMBER_TOKEN: 'tok' };
  return { dir, box, env, done: async () => { await entry.close(); rmSync(dir, { recursive: true, force: true }); } };
}
const RT1 = { runtime_id: 'rt_1', channel_binding: 'cb_1111111111111111', installation_epoch: 1, lease_generation: 1 };
const RT2 = { runtime_id: 'rt_2', channel_binding: 'cb_2222222222222222', installation_epoch: 1, lease_generation: 2 };
const INPUT = { task_id: 'task_17', expected_revision: 2, operation_id: 'complete:task_17', transition: 'completed', result_ref: 'artifact_42' };
const RECEIPT = { contract: 'task/v1', operation_id: 'complete:task_17', task_id: 'task_17', outcome: 'committed', status: 'completed', revision: 3 };

// A scripted broker: `script(kind, message, n)` where n counts commits.
async function stubBroker(dir, script) {
  const seen = { binds: [], commits: [], gets: 0 };
  const broker = await serve(dir, 'broker.sock', (kind, message) => {
    if (kind === 'bind') { seen.binds.push(message.runtime_id); return { runtime_id: message.runtime_id }; }
    if (kind === 'task.commit') { seen.commits.push(message); return script.commit(message, seen.commits.length); }
    if (kind === 'task.get') { seen.gets += 1; return script.get(message); }
    throw { host_refusal: { code: 'host.unknown_kind', explanation: kind } };
  });
  return { ...broker, seen };
}

test('a process the entry point did not start is told so', async () => {
  await assert.rejects(connectMember({}), /not started by agent-bot-souls/);
});

test('a wrong member token is refused by the entry point', async () => {
  const w = await world({ broker: '/nonexistent' });
  try {
    await assert.rejects(connectMember({ ...w.env, AGENT_BOT_SOULS_MEMBER_TOKEN: 'other' }), (e) => e.code === 'souls.unknown_member');
  } finally { await w.done(); }
});

test('against HQ: a member binds with its runtime, commits, and moves to its new runtime after a newer admission', async () => {
  const t = await startHQ();
  const w = await world({ broker: t.hq.paths.broker });
  try {
    const entry = await t.entry();
    const admit = async (over) => {
      const r = (await entry.request('Hello', hello(over))).result;
      const a = r.admitted_runtimes.find((x) => x.role === 'lead');
      return { runtime_id: a.runtime_id, channel_binding: a.channel_binding, installation_epoch: r.installation_epoch, lease_generation: r.lease_generation };
    };
    w.box.rt = await admit();
    const owner = await t.owner();
    const taskId = (await owner.request('tasks.offer', { operation_id: 'offer_1', objective: 'x', done_criteria: 'y', accountable_soul: SOUL })).result.task_id;

    const member = await connectMember(w.env);
    assert.deepEqual([member.member_id, member.role, member.soul_id], ['m_lead', 'lead', SOUL]);
    const runtime = await member.runtime();
    assert.equal(runtime.runtime_id, w.box.rt.runtime_id);
    assert.equal('channel_binding' in runtime, false, 'the binding is not handed back out');
    const [directive] = await member.directives();
    assert.equal(directive.payload.task.task_id, taskId);
    const accepted = await member.commit({ task_id: taskId, expected_revision: 0, operation_id: 'accept:1', transition: 'accepted' });
    assert.deepEqual([accepted.outcome, accepted.status, accepted.revision], ['committed', 'accepted', 1]);

    // A newer admission supersedes the runtime the member is bound as.
    const old = w.box.rt;
    w.box.rt = await admit({ request_id: 'req_0002' });
    const running = await member.commit({ task_id: taskId, expected_revision: 1, operation_id: 'run:1', transition: 'running' });
    assert.deepEqual([running.outcome, running.status], ['committed', 'running']);
    assert.equal((await member.get(taskId)).task.lease_generation, w.box.rt.lease_generation, 'committed under the new lease generation');
    const commits = t.hq.core.receipts.filter((r) => r.kind === 'task.commit').map((r) => r.caller);
    assert.deepEqual(commits, [`runtime:${old.runtime_id}`, `runtime:${w.box.rt.runtime_id}`]);
    // The old runtime's attempt was refused, not committed twice.
    assert.deepEqual(t.hq.core.receipts.filter((r) => r.kind === 'task.commit.refused').map((r) => r.code), ['lease_expired']);
    await member.close();
  } finally { await w.done(); await t.done(); }
});

test('a lost reply on the same runtime: the identical request is sent again and returns the stored receipt', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'b-'));
  const broker = await stubBroker(dir, { commit: (message, n) => (n === 1 ? DROP : RECEIPT), get: () => { throw new Error('no lookup needed'); } });
  const w = await world({ broker: broker.path });
  try {
    w.box.rt = RT1;
    const member = await connectMember(w.env);
    assert.deepEqual(await member.commit(INPUT), RECEIPT);
    assert.equal(broker.seen.commits.length, 2);
    assert.deepEqual(broker.seen.commits[1], broker.seen.commits[0], 'same operation, same request ID, same bytes');
    assert.deepEqual(broker.seen.binds, ['rt_1', 'rt_1']);
    assert.equal(broker.seen.gets, 0);
    await member.close();
  } finally { await w.done(); await broker.close(); rmSync(dir, { recursive: true, force: true }); }
});

test('a lost reply and a new runtime: the record decides, and the operation is never sent again', async () => {
  for (const [name, record, expected] of [
    ['it landed', { task: { task_id: 'task_17', status: 'completed', revision: 3 }, proposals: [] }, { outcome: 'committed', status: 'completed', revision: 3, reconciled: true }],
    ['it did not land', { task: { task_id: 'task_17', status: 'running', revision: 2 }, proposals: [] }, NotCommitted],
    ['another commit landed instead', { task: { task_id: 'task_17', status: 'failed', revision: 3 }, proposals: [] }, NotCommitted],
    ['it was recorded as a proposal', { task: { task_id: 'task_17', status: 'running', revision: 2 }, proposals: [{ proposal_id: 'prop_9', operation_id: 'complete:task_17' }] }, { outcome: 'proposal', proposal_id: 'prop_9', reconciled: true }],
  ]) {
    const dir = mkdtempSync(join(tmpdir(), 'b-'));
    const w = await world({ broker: join(dir, 'broker.sock') });
    const broker = await stubBroker(dir, { commit: () => { w.box.rt = RT2; return DROP; }, get: () => record });
    try {
      w.box.rt = RT1;
      const member = await connectMember(w.env);
      if (expected === NotCommitted) {
        await assert.rejects(member.commit(INPUT), (e) => e instanceof NotCommitted && e.code === 'not_committed' && e.task.revision === record.task.revision, name);
      } else {
        const out = await member.commit(INPUT);
        for (const [k, v] of Object.entries(expected)) assert.equal(out[k], v, `${name}: ${k}`);
        assert.equal(out.operation_id, INPUT.operation_id);
      }
      assert.equal(broker.seen.commits.length, 1, `${name}: no replay`);
      assert.deepEqual(broker.seen.binds, ['rt_1', 'rt_2']);
      await member.close();
    } finally { await w.done(); await broker.close(); rmSync(dir, { recursive: true, force: true }); }
  }
});

test('a refused commit on a superseded runtime is sent once by the new runtime, under the same operation ID', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'b-'));
  const w = await world({ broker: join(dir, 'broker.sock') });
  const broker = await stubBroker(dir, {
    commit: (message, n) => {
      if (n === 1) { w.box.rt = RT2; throw { refusal: { error: 'lease_expired', explanation: 'superseded', correlation_id: 'corr_1' } }; }
      return RECEIPT;
    },
    get: () => { throw new Error('no lookup needed'); },
  });
  try {
    w.box.rt = RT1;
    const member = await connectMember(w.env);
    assert.deepEqual(await member.commit(INPUT), RECEIPT);
    const [first, second] = broker.seen.commits;
    assert.equal(second.operation_id, first.operation_id);
    assert.deepEqual([first.runtime_id, first.lease_generation, second.runtime_id, second.lease_generation], ['rt_1', 1, 'rt_2', 2]);
    await member.close();
  } finally { await w.done(); await broker.close(); rmSync(dir, { recursive: true, force: true }); }
});

test('any other refusal is the answer: nothing is retried', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'b-'));
  const broker = await stubBroker(dir, { commit: () => { throw { refusal: { error: 'revision_conflict', explanation: 'at revision 5', correlation_id: 'corr_2' } }; }, get: () => ({}) });
  const w = await world({ broker: broker.path });
  try {
    w.box.rt = RT1;
    const member = await connectMember(w.env);
    await assert.rejects(member.commit(INPUT), (e) => e.code === 'revision_conflict' && e.transport === false);
    assert.equal(broker.seen.commits.length, 1);
    assert.equal(w.box.runtimeAsked, 1);
    await member.close();
  } finally { await w.done(); await broker.close(); rmSync(dir, { recursive: true, force: true }); }
});

test('agent-bot-souls member <op> gives a harness that only runs commands the same operations', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'b-'));
  const broker = await stubBroker(dir, { commit: () => RECEIPT, get: () => ({ task: { task_id: 'task_17', status: 'running', revision: 2 }, proposals: [] }) });
  const w = await world({ broker: broker.path });
  const cli = (...argv) => new Promise((resolve, reject) => {
    execFile(process.execPath, [BIN, 'member', ...argv], { env: { PATH: process.env.PATH, ...w.env } }, (err, stdout, stderr) => (err ? reject(new Error(stderr)) : resolve(JSON.parse(stdout))));
  });
  try {
    w.box.rt = RT1;
    const runtime = await cli('runtime');
    assert.deepEqual([runtime.runtime_id, runtime.member_id, runtime.lease_generation, 'channel_binding' in runtime], ['rt_1', 'm_lead', 1, false]);
    assert.equal((await cli('get', JSON.stringify({ task_id: 'task_17' }))).task.status, 'running');
    assert.deepEqual(await cli('commit', JSON.stringify(INPUT)), RECEIPT);
    assert.deepEqual([broker.seen.commits[0].operation_id, broker.seen.commits[0].runtime_id, broker.seen.commits[0].contract], ['complete:task_17', 'rt_1', 'task/v1']);
    await assert.rejects(cli('route', JSON.stringify({ role: 'specialist', prompt: 'x' })), /souls\.unknown_op/, 'refusals reach the caller');
  } finally { await w.done(); await broker.close(); rmSync(dir, { recursive: true, force: true }); }
});
