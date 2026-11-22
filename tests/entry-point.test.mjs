// The entry point against the real HQ and agent-comms's broker plugin
// (agent-bot-hq plan §9 row 14). The exit evidence for the row and for
// Stage 1: one task completes with scoped proposals and one final
// commitment. Then the recovery ladder, with real member processes.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { once } from 'node:events';
import { existsSync, mkdirSync, readFileSync, readdirSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { connect as netConnect, Server } from 'node:net';
import { join } from 'node:path';
import { SoulUnavailable, startSoul } from '../lib/entry-point.mjs';
import { connectHq } from '../lib/hq-client.mjs';
import { handoffs, readNotes } from '../lib/notes.mjs';
import { accountHQ, DIGEST, fake, hqProxy, makeSoul, schema, setup, SOUL, startHQ, validate } from './harness.mjs';

const recoveries = (t) => t.soul.events().filter((e) => e.event === 'recovery').map((e) => [e.member_id, e.failure, e.action]);
const finals = (t, taskId) => t.receipts('task.commit').filter((r) => r.task_id === taskId && r.status === 'completed');

test('an adapter needs a session ID before its member reports Ready or prompts', async (suite) => {
  for (const [name, reply] of [['missing', {}], ['empty', { sessionId: '' }], ['wrong type', { sessionId: 7 }]]) {
    await suite.test(name, async () => {
      const isolated = accountHQ();
      const spawn = isolated.options.launch.spawn;
      isolated.options.launch.spawn = (file, args, options) => {
        if (options.env?.AGENT_BOT_SOULS_MEMBER_ID === 'm_lead') {
          const scenario = JSON.stringify({ newSessionReply: reply, once: true });
          options = { ...options, env: { ...options.env, FAKE_ADAPTER_SCENARIO: scenario } };
        }
        return spawn(file, args, options);
      };
      const beforeRetry = [];
      let t;
      try {
        const delay = async () => {
          beforeRetry.push({
            ready: t.receipts('hq.ready').length,
            started: t.soul.events().filter((e) => e.event === 'member-started').length,
          });
        };
        t = await setup({ hq: isolated.options, runtime: { delay } });
        const task = await t.offer();
        await t.soul.prompt('start the member session');
        assert.deepEqual(beforeRetry, [{ ready: 0, started: 0 }]);
        assert.deepEqual(recoveries(t), [['m_lead', 'crash', 'restart']]);
        assert.deepEqual(t.soul.events().filter((e) => e.event === 'member-started').map((e) => e.launch), ['hq', 'hq']);
        assert.equal(t.receipts('hq.ready').length, 2);
        assert.equal(finals(t, task).length, 1);
      } finally {
        if (t) await t.done();
        isolated.layout.remove();
      }
    });
  }
});

test('row 16b: the Soul uses HQ launch, its account member sockets, and HQ stop end to end', { timeout: 30_000 }, async () => {
  const isolated = accountHQ();
  let t;
  let finished = false;
  try {
    t = await setup({ hq: isolated.options });
    const taskId = await t.offer();
    const result = await t.soul.prompt('work through the isolated harness accounts');
    assert.match(result.text, new RegExp(`Completed ${taskId}`));
    assert.deepEqual(t.soul.events().filter((e) => e.event === 'member-started').map((e) => [e.member_id, e.launch]).sort(), [['m_lead', 'hq'], ['m_spec', 'hq']]);
    assert.deepEqual(t.receipts('hq.launch').map((r) => [r.member_id, r.account]).sort(), [['m_lead', 'hqm_a'], ['m_spec', 'hqm_b']]);
    assert.deepEqual(t.receipts('hq.bind').map((r) => r.caller_account).sort(), ['hqm_a', 'hqm_b']);

    const accountDir = join(isolated.layout.homes.hqm_b, '.agent-bot-hq', 'souls', SOUL, 'm_spec');
    assert.ok(readdirSync(accountDir).some((name) => /^artifact_[0-9a-f]{12}\.txt$/.test(name)), 'the adapter wrote in HQ\'s returned account directory');
    assert.equal(existsSync(join(t.contents, 'home', 'm_spec')), false, 'the cooperative home was not created');

    const memberSockets = ['hqm_a', 'hqm_b'].flatMap((account) => readdirSync(join(isolated.layout.dir, account))
      .filter((name) => name.startsWith('member-')).map((name) => join(isolated.layout.dir, account, name)));
    assert.equal(memberSockets.length, 2);
    assert.ok(memberSockets.every((path) => (statSync(path).mode & 0o777) === 0o660));
    const intruder = await connectHq(memberSockets[0]);
    await assert.rejects(intruder.request('hello', { token: 'wrong-member-token' }), (error) => error.code === 'souls.unknown_member');
    await intruder.close();

    await t.done();
    finished = true;
    assert.ok(memberSockets.every((path) => !existsSync(path)), 'member sockets are removed with their launches');
    assert.deepEqual(t.receipts('hq.launch.exited').map((r) => [r.member_id, r.reason, r.contained]).sort(), [['m_lead', 'stopped', true], ['m_spec', 'stopped', true]]);
  } finally {
    if (t && !finished) await t.done();
    isolated.layout.remove();
  }
});

test('a protected request fails before an adapter starts when HQ grants only cooperative', async () => {
  const hq = await startHQ();
  const root = makeSoul();
  const events = [];
  try {
    await assert.rejects(startSoul({ root, hqHome: hq.home, requestedProfile: 'managed-protected', renewEveryMs: 0, log: (event) => events.push(event) }), (error) => error instanceof SoulUnavailable && error.code === 'profile_insufficient' && /managed-cooperative.*managed-protected/.test(error.reason) && /profile_insufficient/.test(error.message));
    assert.deepEqual(events.find((event) => event.event === 'profile-refused'), { event: 'profile-refused', code: 'profile_insufficient', source: 'local', requested_profile: 'managed-protected', granted_profile: 'managed-cooperative' });
    assert.equal(hq.hq.core.receipts.some((receipt) => receipt.kind === 'hq.launch'), false);
    assert.equal(existsSync(join(root, 'Contents/host/members.sock')), false);
  } finally {
    await hq.done();
    rmSync(root, { recursive: true, force: true });
  }
});

test('an initial HQ profile refusal retains the HQ error', async () => {
  const hq = await startHQ();
  const proxy = await hqProxy(hq, ({ op, reply }) => op === 'Hello' && reply.ok
    ? { id: reply.id, ok: false, refusal: { error: 'profile_insufficient', explanation: 'protected profile unavailable', correlation_id: 'corr_profile' } }
    : reply);
  const root = makeSoul();
  const events = [];
  try {
    await assert.rejects(startSoul({ root, hqHome: proxy.home, requestedProfile: 'managed-protected', renewEveryMs: 0, log: (event) => events.push(event) }),
      (error) => error.name === 'HqRefusal' && error.op === 'Hello' && error.code === 'profile_insufficient' && error.transport === false);
    assert.deepEqual(events.find((event) => event.event === 'profile-refused'), { event: 'profile-refused', code: 'profile_insufficient', source: 'hq', requested_profile: 'managed-protected' });
    assert.equal(existsSync(join(root, 'Contents/host/members.sock')), false);
  } finally {
    await proxy.done();
    await hq.done();
    rmSync(root, { recursive: true, force: true });
  }
});

test('a protected grant never falls back to local launch even when the request was cooperative', async () => {
  const hq = await startHQ();
  const proxy = await hqProxy(hq, ({ op, reply }) => op === 'Hello' && reply.ok ? { ...reply, result: { ...reply.result, profile: 'managed-protected', warnings: [] } } : reply);
  const root = makeSoul();
  let soul;
  try {
    soul = await startSoul({ root, hqHome: proxy.home, renewEveryMs: 0 });
    assert.equal(soul.status().profile, 'managed-protected');
    await assert.rejects(soul.prompt('do not cross the protected boundary'), (error) => error.code === 'host.launch_unavailable');
    assert.equal(soul.events().some((event) => ['member-launch-fallback', 'member-started'].includes(event.event)), false);
    assert.equal(existsSync(join(root, 'Contents/home/m_lead')), false, 'no local member home was created');
  } finally {
    await soul?.stop().catch(() => {});
    await proxy.done();
    await hq.done();
    rmSync(root, { recursive: true, force: true });
  }
});

for (const refusal of ['cooperative grant', 'HQ refusal', 'HQ refusal with unconfirmed cleanup']) test(`a protected Soul fences members after ${refusal} on re-admission`, { timeout: 30_000 }, async () => {
  const hqRefused = refusal !== 'cooperative grant';
  const unconfirmed = refusal === 'HQ refusal with unconfirmed cleanup';
  const isolated = accountHQ();
  const hq = await startHQ(isolated.options);
  let releasePromptReply;
  let releaseChunk;
  let markChunkHeld;
  let holdUpdates = false;
  const chunkHeld = new Promise((resolve) => { markChunkHeld = resolve; });
  let markPromptReplyHeld;
  const promptReplyHeld = new Promise((resolve) => { markPromptReplyHeld = resolve; });
  const proxy = await hqProxy(hq, ({ op, reply, count }) => {
    if (op === 'Hello' && reply.ok) {
      if (count > 1 && hqRefused) return { id: reply.id, ok: false, refusal: { error: 'profile_insufficient', explanation: 'protected profile unavailable', correlation_id: 'corr_profile' } };
      return { ...reply, result: { ...reply.result, profile: count === 1 ? 'managed-protected' : 'managed-cooperative', warnings: [] } };
    }
    if (op === 'launch.stop' && reply.ok && unconfirmed) return { ...reply, result: { ...reply.result, state: 'uncontained' } };
    if (holdUpdates && reply.method === 'session/update') return new Promise((resolve) => {
      releaseChunk = () => resolve(reply);
      markChunkHeld();
    });
    if (op === 'session/prompt' && count === 2) return new Promise((resolve) => {
      releasePromptReply = () => resolve(reply);
      markPromptReplyHeld();
    });
    return reply;
  });
  const root = makeSoul();
  let soul;
  try {
    soul = await startSoul({ root, hqHome: proxy.home, requestedProfile: 'managed-protected', renewEveryMs: 0 });
    await soul.prompt('start the protected lead');
    assert.ok(soul.status().members.some((member) => member.running));

    holdUpdates = true;
    const chunks = [];
    const inFlight = assert.rejects(soul.prompt('this reply races the downgrade', (chunk) => chunks.push(chunk)),
      (error) => error instanceof SoulUnavailable && error.code === 'profile_insufficient');
    await Promise.all([promptReplyHeld, chunkHeld]);
    hq.clock.advance(60_001);
    const renewal = soul.renew();
    while (soul.status().state !== 'unavailable') await new Promise((resolve) => setImmediate(resolve));
    const chunksAtFence = [...chunks];
    releaseChunk();
    releasePromptReply();
    await assert.rejects(renewal, (error) => error.code === 'profile_insufficient' && (hqRefused ? error.name === 'HqRefusal' && error.op === 'Hello' : error instanceof SoulUnavailable && /managed-cooperative.*managed-protected/.test(error.reason)));
    await inFlight;
    assert.deepEqual(chunks, chunksAtFence, 'no chunks delivered after the profile fence');
    const status = soul.status();
    assert.deepEqual([status.state, status.profile, status.code], ['unavailable', hqRefused ? undefined : 'managed-cooperative', 'profile_insufficient']);
    const event = soul.events().find((row) => row.event === 'profile-refused');
    assert.equal(event.code, 'profile_insufficient');
    assert.equal(event.source, hqRefused ? 'hq' : 'local');
    assert.ok(status.members.every((member) => !member.running && member.runtime_id === undefined));
    await assert.rejects(soul.prompt('must stay fenced'), (error) => error instanceof SoulUnavailable && error.state === 'unavailable' && error.code === 'profile_insufficient' && /profile_insufficient/.test(error.message));
    assert.throws(() => soul.release(), (error) => error instanceof SoulUnavailable && error.state === 'unavailable' && error.code === 'profile_insufficient');
    assert.equal(soul.events().filter((event) => event.event === 'member-started').length, 1, 'no member restarted after the downgrade');
    if (unconfirmed) {
      assert.match(soul.events().find((row) => row.event === 'member-stop-failed')?.error, /m_lead.*uncontained/);
      await assert.rejects(soul.stop(), /m_lead.*uncontained/);
    } else await soul.stop();
    assert.equal(soul.status().state, 'stopped');
    assert.equal(soul.status().code, undefined);
  } finally {
    await soul?.stop().catch(() => {});
    await proxy.done();
    await hq.done();
    rmSync(root, { recursive: true, force: true });
    isolated.layout.remove();
  }
});

for (const held of ['Hello grant', 'Hello refusal', 'Equip', 'Ready']) test(`shutdown fences a pending ${held} during re-admission`, { timeout: 30_000 }, async () => {
  const isolated = accountHQ();
  const hq = await startHQ(isolated.options);
  let release;
  let signalHeld;
  const responseHeld = new Promise((resolve) => { signalHeld = resolve; });
  const counts = { Hello: 0, Equip: 0, Ready: 0 };
  const proxy = await hqProxy(hq, ({ op, reply }) => {
    if (Object.hasOwn(counts, op)) counts[op] += 1;
    const isHeld = (op === 'Hello' && counts.Hello === 2 && held.startsWith('Hello')) ||
      (op === 'Equip' && counts.Equip === 3 && held === 'Equip') ||
      (op === 'Ready' && counts.Ready === 2 && held === 'Ready');
    if (!isHeld) return reply;
    const output = held === 'Hello refusal' ? { id: reply.id, ok: false, refusal: {
      error: 'profile_insufficient', explanation: 'protected profile unavailable', correlation_id: 'corr_profile',
    } } : reply;
    return new Promise((resolve) => { release = () => resolve(output); signalHeld(); });
  });
  const root = makeSoul();
  let soul;
  try {
    soul = await startSoul({ root, hqHome: proxy.home, renewEveryMs: 0 });
    await soul.prompt('start the lead');
    hq.clock.advance(60_001);
    const renewal = assert.rejects(soul.renew(), (error) => error instanceof SoulUnavailable && error.state === 'stopped');
    await responseHeld;
    const before = { ...counts };
    const admitted = soul.events().filter((event) => event.event === 'admitted').length;
    const stopping = soul.stop();
    assert.equal(soul.status().state, 'stopped');
    release();
    await renewal;
    await stopping;
    assert.deepEqual(counts, before, 'no later admission, Equip, or Ready request');
    assert.equal(soul.events().filter((event) => event.event === 'admitted').length, admitted);
    assert.equal(soul.events().some((event) => event.event === 'profile-refused'), false);
    assert.equal(soul.status().state, 'stopped');
    assert.ok(soul.status().members.every((member) => member.runtime_id === undefined));
  } finally {
    release?.();
    await soul?.stop().catch(() => {});
    await proxy.done(); await hq.done();
    rmSync(root, { recursive: true, force: true });
    isolated.layout.remove();
  }
});

test('a held turn is canceled without delivering updates during shutdown', { timeout: 30_000 }, async () => {
  const isolated = accountHQ();
  const hq = await startHQ(isolated.options);
  let releaseReply;
  let releaseChunk;
  let signalReply;
  let signalChunk;
  let holding = false;
  const replyHeld = new Promise((resolve) => { signalReply = resolve; });
  const chunkHeld = new Promise((resolve) => { signalChunk = resolve; });
  const proxy = await hqProxy(hq, ({ op, reply, count }) => {
    if (holding && reply.method === 'session/update') return new Promise((resolve) => {
      releaseChunk = () => resolve(reply); signalChunk();
    });
    if (op === 'session/prompt' && count === 2) return new Promise((resolve) => {
      releaseReply = () => resolve(reply); signalReply();
    });
    return reply;
  });
  const root = makeSoul();
  let soul;
  try {
    soul = await startSoul({ root, hqHome: proxy.home, renewEveryMs: 0 });
    await soul.prompt('start the lead');
    holding = true;
    const chunks = [];
    const turn = assert.rejects(soul.prompt('a turn during shutdown', (chunk) => chunks.push(chunk)),
      (error) => error instanceof SoulUnavailable && error.state === 'stopped');
    await Promise.all([replyHeld, chunkHeld]);
    const stopping = soul.stop();
    assert.equal(soul.status().state, 'stopped');
    const chunksAtStop = [...chunks];
    releaseChunk();
    releaseReply();
    await turn;
    await stopping;
    assert.deepEqual(chunks, chunksAtStop, 'no updates delivered after shutdown began');
    assert.equal(soul.status().code, undefined);
  } finally {
    releaseChunk?.(); releaseReply?.();
    await soul?.stop().catch(() => {});
    await proxy.done(); await hq.done();
    rmSync(root, { recursive: true, force: true });
    isolated.layout.remove();
  }
});

for (const outcome of ['profile refusal', 'shutdown']) test(`a delayed member restart cannot re-admit after ${outcome}`, { timeout: 30_000 }, async () => {
  const isolated = accountHQ();
  const hq = await startHQ(isolated.options);
  let helloCount = 0;
  const proxy = await hqProxy(hq, ({ op, reply, count }) => {
    if (op === 'Hello' && reply.ok) {
      helloCount += 1;
      return { ...reply, result: { ...reply.result, profile: helloCount === 1 ? 'managed-protected' : 'managed-cooperative', warnings: [] } };
    }
    if (op === 'session/prompt' && count === 2) return { jsonrpc: '2.0', id: reply.id, error: { code: -32603, message: 'adapter disconnected', data: { closed: true } } };
    return reply;
  });
  const root = makeSoul();
  let releaseDelay;
  let signalDelay;
  const delayStarted = new Promise((resolve) => { signalDelay = resolve; });
  const delay = () => new Promise((resolve) => { releaseDelay = resolve; signalDelay(); });
  let soul;
  try {
    soul = await startSoul({ root, hqHome: proxy.home, requestedProfile: 'managed-protected', renewEveryMs: 0, delay });
    await soul.prompt('start the lead');
    const turn = assert.rejects(soul.prompt('wait for a restart'), (error) => error instanceof SoulUnavailable &&
      (outcome === 'shutdown' ? error.state === 'stopped' : error.code === 'profile_insufficient'));
    await delayStarted;
    if (outcome === 'shutdown') await soul.stop();
    else {
      hq.clock.advance(60_001);
      await assert.rejects(soul.renew(), (error) => error.code === 'profile_insufficient');
    }
    const expectedHellos = outcome === 'shutdown' ? 1 : 2;
    assert.equal(helloCount, expectedHellos);
    releaseDelay();
    await turn;
    assert.equal(helloCount, expectedHellos, 'delayed recovery must not issue another Hello');
    assert.equal(soul.status().state, outcome === 'shutdown' ? 'stopped' : 'unavailable');
    assert.ok(soul.status().members.every((member) => !member.running && (outcome === 'shutdown' || member.runtime_id === undefined)));
  } finally {
    releaseDelay?.();
    await soul?.stop().catch(() => {});
    await proxy.done();
    await hq.done();
    rmSync(root, { recursive: true, force: true });
    isolated.layout.remove();
  }
});

test('unauthenticated member connections stay bounded and capacity is released on close', async () => {
  const hq = await startHQ();
  const root = makeSoul();
  let soul;
  const held = [];
  const open = () => new Promise((resolve, reject) => {
    const socket = netConnect(join(root, 'Contents/host/members.sock'));
    socket.once('connect', () => resolve(socket));
    socket.once('error', reject);
  });
  try {
    soul = await startSoul({ root, hqHome: hq.home, renewEveryMs: 0 });
    for (let i = 0; i < 16; i += 1) held.push(await open());
    const overflow = await Promise.all(Array.from({ length: 64 }, async () => {
      const socket = await open();
      await new Promise((resolve) => socket.once('close', resolve));
      return socket;
    }));
    assert.ok(overflow.every((socket) => socket.destroyed));

    const released = held.map((socket) => new Promise((resolve) => socket.once('close', resolve)));
    for (const socket of held) socket.destroy();
    await Promise.all(released);
    const accepted = await open();
    const outcome = await Promise.race([
      new Promise((resolve) => accepted.once('close', () => resolve('closed'))),
      new Promise((resolve) => setTimeout(() => resolve('open'), 50)),
    ]);
    assert.equal(outcome, 'open', 'a released slot accepts another unauthenticated connection');
    accepted.destroy();
  } finally {
    for (const socket of held) socket.destroy();
    await soul?.stop().catch(() => {});
    await hq.done();
    rmSync(root, { recursive: true, force: true });
  }
});

test('an available HQ launch does not fall back locally when adapter environment cannot cross the boundary', async () => {
  const isolated = accountHQ();
  let t;
  try {
    t = await setup({
      hq: isolated.options,
      soul: { adapters: { 'fake-lead': fake(undefined, { env: { EXTRA_UNREVIEWED: 'x' } }), 'fake-specialist': fake() } },
    });
    await assert.rejects(t.soul.prompt('work'), /environment variables that HQ account launch cannot accept/);
    assert.equal(t.soul.events().some((event) => event.event === 'member-launch-fallback' || event.event === 'member-started'), false);
    assert.equal(t.receipts('hq.launch').length, 0, 'the reserved launch never attached or started');
  } finally {
    await t?.done();
    isolated.layout.remove();
  }
});

test('an attach-time account launch failure falls back locally only in the cooperative profile', async () => {
  const isolated = accountHQ();
  const spawn = isolated.options.launch.spawn;
  let refused = false;
  isolated.options.launch.spawn = (file, args, options) => {
    if (!refused && args[1] === '-H') {
      refused = true;
      const error = new Error('injected sudo launch failure');
      error.code = 'ENOENT';
      throw error;
    }
    return spawn(file, args, options);
  };
  let t;
  try {
    t = await setup({ hq: isolated.options });
    const result = await t.soul.prompt('use the authorized cooperative fallback');
    assert.match(result.text, /No waiting directives and no open tasks/);
    assert.deepEqual(t.soul.events().filter((event) => event.event === 'member-launch-fallback').map((event) => event.member_id), ['m_lead']);
    assert.deepEqual(t.soul.events().filter((event) => event.event === 'member-started').map((event) => event.launch), ['local']);
  } finally {
    await t?.done();
    isolated.layout.remove();
  }
});

test('HQ-started mode refuses cooperative local adapter fallback', async () => {
  let t;
  try {
    t = await setup({ runtime: { env: { ...process.env, AGENT_BOT_SOULS_REQUIRE_HQ_LAUNCH: '1' } } });
    await assert.rejects(t.soul.prompt('do not run an adapter in HQ account'),
      (error) => error instanceof SoulUnavailable && error.code === 'host.launch_unavailable'
        && /local fallback is disabled/.test(error.reason));
    assert.equal(t.soul.events().some((event) => ['member-launch-fallback', 'member-started'].includes(event.event)), false);
    assert.deepEqual(t.soul.events().filter((event) => event.event === 'member-launch-fallback-refused').map((event) => event.member_id), ['m_lead']);
    assert.equal(t.receipts('hq.launch').length, 0);
  } finally { await t?.done(); }
});

test('a request-time account launch refusal fails before starting a broken local fallback', async () => {
  const isolated = accountHQ();
  const spawn = isolated.options.launch.spawn;
  isolated.options.launch.spawn = (file, args, options) => {
    if (args[1] !== '-H' && args[2] === 'hqm_a') {
      const error = new Error('injected readiness failure');
      error.code = 'ENOENT';
      throw error;
    }
    return spawn(file, args, options);
  };
  let t;
  try {
    t = await setup({ hq: isolated.options });
    await assert.rejects(
      t.soul.prompt('do not start an account-bound member on the shared broker'),
      (error) => error instanceof SoulUnavailable && /account-bound member m_lead/.test(error.reason),
    );
    assert.equal(t.soul.status().state, 'unavailable');
    assert.deepEqual(t.soul.events().filter((event) => event.event === 'member-launch-fallback-refused').map((event) => event.member_id), ['m_lead']);
    assert.equal(t.soul.events().some((event) => ['member-launch-fallback', 'member-started'].includes(event.event)), false);
    assert.ok(t.receipts('hq.bind.refused').some((receipt) => receipt.runtime_id === t.soul.status().members.find((member) => member.member_id === 'm_lead').runtime_id));
  } finally {
    await t?.done();
    isolated.layout.remove();
  }
});

test('a malformed launch result is stopped before a clean retry', { timeout: 30_000 }, async () => {
  const isolated = accountHQ();
  const hq = await startHQ(isolated.options);
  const proxy = await hqProxy(hq, ({ op, reply, count }) => op === 'launch' && reply.ok && count === 1
    ? { ...reply, result: { ...reply.result, cwd: 'not-absolute' } }
    : reply);
  const root = makeSoul();
  let soul;
  try {
    soul = await startSoul({ root, hqHome: proxy.home, renewEveryMs: 0 });
    await assert.rejects(soul.prompt('first launch is malformed'), /absolute working directory/);
    const result = await soul.prompt('second launch is clean');
    assert.match(result.text, /No waiting directives and no open tasks/);
    assert.deepEqual(soul.events().filter((event) => event.event === 'member-started').map((event) => event.launch), ['hq']);
  } finally {
    await soul?.stop().catch(() => {});
    await proxy.done();
    await hq.done();
    rmSync(root, { recursive: true, force: true });
    isolated.layout.remove();
  }
});

test('an unconfirmed reservation cleanup preserves the setup error and fences another launch', { timeout: 30_000 }, async () => {
  const isolated = accountHQ();
  const hq = await startHQ(isolated.options);
  const proxy = await hqProxy(hq, ({ op, reply }) => {
    if (op === 'launch' && reply.ok) return { ...reply, result: { ...reply.result, cwd: 'not-absolute' } };
    if (op === 'launch.stop' && reply.ok) return { ...reply, result: { ...reply.result, state: 'uncontained' } };
    return reply;
  });
  const root = makeSoul();
  let soul;
  try {
    soul = await startSoul({ root, hqHome: proxy.home, renewEveryMs: 0 });
    await assert.rejects(soul.prompt('exercise malformed setup'), (error) => {
      assert.ok(error instanceof AggregateError);
      assert.match(error.errors[0].message, /absolute working directory/);
      assert.match(error.errors[1].message, /m_lead.*uncontained/);
      return true;
    });
    await assert.rejects(soul.prompt('try starting again'), /connection closed/);
    assert.equal(isolated.launch.calls.some((call) => call.args[1] === '-H'), false);
  } finally {
    await soul?.stop();
    await proxy.done();
    await hq.done();
    rmSync(root, { recursive: true, force: true });
    isolated.layout.remove();
  }
});

test('shutdown fences member startup and cleans up its reservation, attach, or ACP handshake', async (suite) => {
  for (const scenario of ['launch', 'unanswered launch', 'launch.attach', 'initialize']) {
    await suite.test(scenario, { timeout: 15_000 }, async (t) => {
      const reservationLost = scenario === 'unanswered launch';
      const stage = reservationLost ? 'launch' : scenario;
      const isolated = accountHQ();
      const hq = await startHQ(isolated.options);
      let release;
      let launch;
      let reached;
      const held = new Promise((resolve) => { reached = resolve; });
      const stops = [];
      const proxy = await hqProxy(hq, ({ op, reply }) => {
        if (op === 'launch' && reply.ok) launch = reply.result;
        if (op === 'launch.stop' && reply.ok) stops.push(reply.result);
        if (op !== stage) return reply;
        return new Promise((resolve) => {
          release = () => resolve(reply);
          reached();
        });
      });
      const root = makeSoul();
      let soul;
      try {
        soul = await startSoul({ root, hqHome: proxy.home, renewEveryMs: 0 });
        const prompt = assert.rejects(soul.prompt('stop while starting a member'), /the entry point stopped/);
        await held;

        if (reservationLost) t.mock.timers.enable({ apis: ['setTimeout'] });
        const stopping = soul.stop();
        assert.equal(soul.stop(), stopping);
        if (reservationLost) {
          const refused = assert.rejects(stopping, /m_lead is unconfirmed after the shutdown deadline/);
          await new Promise(setImmediate);
          t.mock.timers.tick(30_000);
          t.mock.timers.reset();
          await refused;
          await prompt;
          assert.deepEqual(stops, []);
          assert.equal(isolated.launch.calls.some((call) => call.args[1] === '-H'), false);
          assert.equal(existsSync(launch.member_socket), false);
          assert.equal(existsSync(join(root, 'Contents', 'host', 'members.sock')), false);
          return;
        }
        if (stage === 'launch') {
          // The reservation already exists at HQ, but its ID is still in
          // the withheld reply. Shutdown must wait before confirming it.
          const reachedNextTick = new Promise((resolve) => setImmediate(resolve, 'waiting'));
          assert.equal(await Promise.race([stopping, reachedNextTick]), 'waiting');
          release();
        }
        // For attach and initialize the reply remains withheld until after
        // shutdown. Each transport must still be closed and the launch ended.
        let timeout;
        try {
          const deadline = new Promise((_, reject) => {
            timeout = setTimeout(() => reject(new Error(`shutdown waited for the ${stage} reply`)), 4000);
          });
          await Promise.race([stopping, deadline]);
        } finally { clearTimeout(timeout); }
        await prompt;
        assert.deepEqual(stops, [{ launch_id: launch.launch_id, state: 'exited' }]);
        assert.equal(existsSync(launch.member_socket), false);
        const children = isolated.launch.calls.filter((call) => call.args[1] === '-H').map(({ child }) => child);
        if (stage === 'launch') assert.equal(children.length, 0);
        else {
          assert.equal(children.length, 1);
          await Promise.all(children.map((child) => child.exitCode !== null || child.signalCode !== null ? undefined : once(child, 'exit')));
        }
        assert.equal(soul.events().some((event) => event.event === 'member-started'), false);
      } finally {
        if (reservationLost) t.mock.timers.reset();
        release?.();
        await soul?.stop().catch(() => {});
        await proxy.done();
        await hq.done();
        rmSync(root, { recursive: true, force: true });
        isolated.layout.remove();
      }
    });
  }
});

test('shutdown reports an unanswered stop and closes the other accepted launch', { timeout: 15_000 }, async (t) => {
  const isolated = accountHQ();
  const hq = await startHQ(isolated.options);
  let release;
  let held;
  const waiting = new Promise((resolve) => { held = resolve; });
  const stops = [];
  const proxy = await hqProxy(hq, ({ op, reply }) => {
    if (op !== 'launch.stop') return reply;
    assert.equal(reply.result?.state, 'exited');
    stops.push(reply.result.launch_id);
    if (stops.length !== 1) return reply;
    return new Promise((resolve) => {
      release = () => resolve(reply);
      held();
    });
  });
  const root = makeSoul();
  let soul;
  try {
    soul = await startSoul({ root, hqHome: proxy.home, renewEveryMs: 0 });
    const owner = await hq.owner();
    const offer = await owner.request('tasks.offer', {
      operation_id: 'offer_stop_timeout', objective: 'Exercise shutdown', done_criteria: 'Both members started', accountable_soul: SOUL,
    });
    assert.equal(offer.ok, true);
    assert.match((await soul.prompt('Work the waiting task.')).text, new RegExp(`Completed ${offer.result.task_id}`));
    const launches = isolated.launch.calls.filter((call) => call.args[1] === '-H');
    assert.equal(launches.length, 2);
    assert.ok(launches.every(({ child }) => child.exitCode === null && child.signalCode === null));
    const childExits = Promise.all(launches.map(({ child }) => once(child, 'exit')));
    t.mock.timers.enable({ apis: ['setTimeout'] });
    const stopping = assert.rejects(soul.stop(), /m_lead is unconfirmed: stop reply timed out/);
    await waiting;
    t.mock.timers.tick(45_000);
    t.mock.timers.reset();
    await stopping;
    await childExits;
    assert.equal(stops.length, 2);
    assert.ok(launches.every(({ options }) => !existsSync(options.env.AGENT_BOT_SOULS_SOCKET)));
    assert.equal(existsSync(join(root, 'Contents', 'host', 'members.sock')), false);
  } finally {
    t.mock.timers.reset();
    release?.();
    await soul?.stop().catch(() => {});
    await proxy.done();
    await hq.done();
    rmSync(root, { recursive: true, force: true });
    isolated.layout.remove();
  }
});

test('Stage 1 exit: one task completes with scoped proposals and one final commitment', async () => {
  const t = await setup();
  try {
    // Clock-in: HQ admitted both members under the cooperative profile.
    const status = t.soul.status();
    assert.deepEqual([status.state, status.profile, status.installation_epoch, status.lease_generation], ['ready', 'managed-cooperative', 1, 1]);
    assert.deepEqual(t.receipts('hq.admission').map((r) => [r.soul_id, r.runtimes]), [[SOUL, 2]]);
    assert.equal(t.receipts('hq.equip').length, 2);

    const taskId = await t.offer();
    const chunks = [];
    const result = await t.soul.prompt('Please work the waiting task.', (text) => chunks.push(text));
    assert.equal(result.stop_reason, 'end_turn');
    assert.equal(result.member_id, 'm_lead', 'the owner\'s conversation is the lead\'s');
    assert.match(result.text, new RegExp(`Completed ${taskId} from m_spec's proposal prop_`));
    assert.equal(chunks.join(''), result.text, 'streamed as it arrived');

    // The record in HQ: offered, accepted, running, completed.
    const { task, proposals } = await t.task(taskId);
    assert.deepEqual(validate(schema('task/v1/task-record.schema.json'), task), []);
    assert.deepEqual([task.status, task.revision, task.requester], ['completed', 3, 'owner']);

    // Scoped proposals: the specialist's, for this task, recorded as a
    // proposal while the task stayed running.
    assert.equal(proposals.length, 1);
    const [proposal] = proposals;
    assert.deepEqual([proposal.task_id, proposal.member_id, proposal.role, proposal.transition, proposal.task_status], [taskId, 'm_spec', 'specialist', 'completed', 'running']);
    assert.match(proposal.evidence[0], /^artifact_[0-9a-f]{12}$/);
    assert.ok(existsSync(join(t.contents, 'home/m_spec', `${proposal.evidence[0]}.txt`)), 'the artifact is in the specialist\'s own home');

    // One final commitment, by the lead, citing the proposal.
    const final = finals(t, taskId);
    assert.equal(final.length, 1);
    assert.deepEqual([final[0].by, final[0].outcome, final[0].from], ['m_lead', 'committed', 'running']);
    assert.deepEqual(task.evidence, [proposal.evidence[0], proposal.proposal_id]);
    const commits = t.receipts('task.commit').filter((r) => r.task_id === taskId);
    assert.deepEqual(commits.map((r) => [r.by, r.outcome, r.status]), [
      ['m_lead', 'committed', 'accepted'], ['m_lead', 'committed', 'running'], ['m_spec', 'proposal', 'running'], ['m_lead', 'committed', 'completed'],
    ]);
    // Each member committed as its own bound runtime, over the broker.
    const runtimes = Object.fromEntries(status.members.map((m) => [m.member_id, m.runtime_id]));
    assert.ok(commits.every((r) => r.caller === `runtime:${runtimes[r.by]}`));
    assert.deepEqual([...new Set(t.receipts('hq.bind').map((r) => r.member_id))].sort(), ['m_lead', 'm_spec']);

    // Role routing happened once, lead to specialist.
    assert.deepEqual(t.soul.events().filter((e) => e.event === 'routed').map((e) => [e.from, e.to, e.role, e.task_id]), [['m_lead', 'm_spec', 'specialist', taskId]]);

    // Notes: valid typed-note records; the handoff was superseded by the
    // commitment, so nothing is left to hand off.
    const notes = readNotes(t.contents);
    for (const n of notes) assert.deepEqual(validate(schema('records/v1/typed-note.schema.json'), n), [], JSON.stringify(n));
    assert.deepEqual(notes.map((n) => [n.type, n.task_id, n.member_id, n.runtime_id]), [['handoff', taskId, 'm_lead', runtimes.m_lead], ['commitment', taskId, 'm_lead', runtimes.m_lead]]);
    assert.deepEqual(handoffs(t.contents), []);

    // A second turn finds nothing to do and commits nothing.
    assert.match((await t.soul.prompt('Anything else?')).text, /No waiting directives and no open tasks/);
    assert.equal(t.receipts('task.commit').length, 4);

    // No channel binding reached a receipt, a note or an event.
    const everything = JSON.stringify([t.hq.core.receipts, notes, t.soul.events(), status]);
    assert.equal(/cb_[0-9a-f]{32}/.test(everything), false);
  } finally { await t.done(); }
});

test('the member socket is private, and only a running member\'s token opens it', async () => {
  const t = await setup();
  try {
    const path = join(t.contents, 'host/members.sock');
    assert.equal(statSync(path).mode & 0o777, 0o600);
    assert.equal(statSync(join(t.contents, 'host')).mode & 0o777, 0o700);
    const c = await connectHq(path);
    await assert.rejects(c.request('runtime'), (e) => e.code === 'souls.unknown_member');
    await assert.rejects(c.request('hello', { token: 'guess' }), (e) => e.code === 'souls.unknown_member');
    await assert.rejects(c.request('hello', {}), (e) => e.code === 'souls.unknown_member');
    await assert.rejects(c.request('note', { type: 'handoff', body: 'forged' }), (e) => e.code === 'souls.unknown_member');
    await c.close();
    assert.deepEqual(readNotes(t.contents), []);
  } finally { await t.done(); }
});

test('a failed bind leaves the path reported in use untouched', async (ctx) => {
  const t = await setup();
  try {
    await t.soul.stop();
    const path = join(realpathSync(t.root), 'Contents/host/members.sock');
    const original = Server.prototype.listen;
    const listener = ctx.mock.method(Server.prototype, 'listen', function (...args) {
      if (args[0] !== path) return original.apply(this, args);
      writeFileSync(path, 'occupied', { flag: 'wx' });
      queueMicrotask(() => this.emit('error', Object.assign(new Error('address already in use'), { code: 'EADDRINUSE' })));
      return this;
    });
    try {
      await assert.rejects(startSoul({ root: t.root, hqHome: t.home, renewEveryMs: 0 }), { code: 'EADDRINUSE' });
      assert.equal(readFileSync(path, 'utf8'), 'occupied');
    } finally { listener.mock.restore(); }
  } finally { await t.done(); }
});

test('a Soul runs under one entry point: a second is refused, and a stale socket file is replaced', async () => {
  const t = await setup();
  try {
    await assert.rejects(startSoul({ root: t.root, hqHome: t.home, renewEveryMs: 0 }), /another entry point is running this Soul/);
    // The refused start changed nothing: the first still works a task.
    assert.equal(t.receipts('hq.admission').length, 1);
    const taskId = await t.offer();
    await t.soul.prompt('work');
    assert.equal((await t.task(taskId)).task.status, 'completed');

    await t.soul.stop();
    const path = join(t.contents, 'host/members.sock');
    writeFileSync(path, 'existing file');
    await assert.rejects(startSoul({ root: t.root, hqHome: t.home, renewEveryMs: 0 }), /member socket path is occupied/);
    assert.equal(readFileSync(path, 'utf8'), 'existing file');
    rmSync(path);
    // Exit without closing the listener, as when a previous entry point stopped abruptly.
    execFileSync(process.execPath, ['-e', "require('node:net').createServer().listen(process.argv[1], () => process.exit(0))", path]);
    assert.ok(statSync(path).isSocket());
    const again = await startSoul({ root: t.root, hqHome: t.home, renewEveryMs: 0 });
    try {
      assert.equal(again.status().state, 'ready');
      assert.equal(again.status().lease_generation, 2, 'a restart of the same installation is a new admission');
      assert.equal(again.status().installation_epoch, 1);
    } finally { await again.stop(); }
  } finally { await t.done(); }
});

test('only the lead routes work; a specialist\'s attempts are refused, and its notes are stamped as its own', async () => {
  const t = await setup({ soul: { spec: { probe: true } } });
  try {
    const taskId = await t.offer();
    await t.soul.prompt('work');
    const probe = JSON.parse(readFileSync(join(t.contents, 'home/m_spec/probe.json'), 'utf8'));
    assert.deepEqual([probe.route, probe.route_peer, probe.note], ['souls.not_lead', 'souls.not_lead', 'souls.invalid_request']);
    const finding = readNotes(t.contents).find((n) => n.note_id === probe.note_id);
    assert.deepEqual([finding.type, finding.member_id, finding.task_id, finding.provenance], ['finding', 'm_spec', taskId, ['member']]);
    assert.equal(t.soul.events().filter((e) => e.event === 'routed').length, 1, 'no routing by the specialist');
    assert.equal((await t.task(taskId)).task.status, 'completed');
  } finally { await t.done(); }
});

test('a lead that crashes before the final commitment is restarted after 5 s; the new lead resumes from the handoff note and commits once', async () => {
  const t = await setup({ soul: { lead: { crash: 'before-final', once: true } } });
  try {
    const taskId = await t.offer();
    const before = t.soul.status();
    const result = await t.soul.prompt('work');
    assert.match(result.text, new RegExp(`Completed ${taskId}`));

    assert.deepEqual(recoveries(t), [['m_lead', 'crash', 'restart']]);
    assert.deepEqual(t.delays, [5_000]);
    // The restart was a new admission: a new lease generation and new
    // runtimes, so the crashed lead's runtime can finalize nothing.
    const after = t.soul.status();
    assert.equal(after.lease_generation, before.lease_generation + 1);
    assert.equal(after.installation_epoch, before.installation_epoch, 'the same installation keeps its epoch');
    const leadBefore = before.members.find((m) => m.member_id === 'm_lead').runtime_id;
    const leadAfter = after.members.find((m) => m.member_id === 'm_lead').runtime_id;
    assert.notEqual(leadAfter, leadBefore);

    // Nothing was repeated: one accept, one run, one proposal, one final
    // commitment, and the final one is the new lead's.
    const commits = t.receipts('task.commit').filter((r) => r.task_id === taskId);
    assert.deepEqual(commits.map((r) => [r.by, r.outcome, r.status]), [
      ['m_lead', 'committed', 'accepted'], ['m_lead', 'committed', 'running'], ['m_spec', 'proposal', 'running'], ['m_lead', 'committed', 'completed'],
    ]);
    assert.equal(commits[0].caller, `runtime:${leadBefore}`);
    assert.equal(commits[3].caller, `runtime:${leadAfter}`);
    assert.equal(finals(t, taskId).length, 1);
    assert.equal(t.soul.events().filter((e) => e.event === 'routed').length, 1, 'the specialist was not asked twice');
    const { task, proposals } = await t.task(taskId);
    assert.deepEqual([task.status, task.revision, proposals.length], ['completed', 3, 1]);

    // The handoff note was written by the lead that crashed and read by
    // the one that took over.
    const notes = readNotes(t.contents);
    assert.deepEqual(notes.map((n) => [n.type, n.runtime_id]), [['handoff', leadBefore], ['commitment', leadAfter]]);
    assert.deepEqual(handoffs(t.contents), []);
  } finally { await t.done(); }
});

test('a member that keeps crashing is restarted with backoff, then the fifth crash in an hour quarantines the Soul', async () => {
  const t = await setup({ soul: { lead: { crash: 'on-start' } } });
  try {
    const taskId = await t.offer();
    await assert.rejects(t.soul.prompt('work'), (e) => e instanceof SoulUnavailable && e.state === 'quarantined');
    assert.deepEqual(t.delays, [5_000, 30_000, 120_000, 600_000]);
    assert.deepEqual(recoveries(t).map((r) => r[2]), ['restart', 'restart', 'restart', 'restart', 'quarantine']);
    const status = t.soul.status();
    assert.equal(status.state, 'quarantined');
    assert.ok(status.members.every((m) => !m.running), 'quarantine stops every member');
    // Quarantined means no more attempts, and the task is untouched.
    await assert.rejects(t.soul.prompt('again'), (e) => e.state === 'quarantined');
    assert.equal(t.delays.length, 4);
    assert.deepEqual([(await t.task(taskId)).task.status, t.receipts('task.commit').length], ['offered', 0]);
  } finally { await t.done(); }
});

test('an authentication failure is re-equipped by HQ and the turn continues; a second one is the owner\'s decision', async () => {
  const t = await setup({ soul: { lead: { fail: 'auth', once: true } } });
  try {
    const taskId = await t.offer();
    const equipped = t.receipts('hq.equip').length;
    await t.soul.prompt('work');
    assert.deepEqual(recoveries(t), [['m_lead', 'auth', 're-equip']]);
    assert.equal(t.receipts('hq.equip').length, equipped + 1);
    assert.deepEqual(t.delays, [], 'a healthy process is not restarted');
    assert.equal(t.soul.status().lease_generation, 1, 'and not admitted again');
    assert.equal((await t.task(taskId)).task.status, 'completed');
  } finally { await t.done(); }

  const again = await setup({ soul: { lead: { fail: 'auth' } } });
  try {
    await assert.rejects(again.soul.prompt('work'), (e) => e instanceof SoulUnavailable && e.state === 'needs-owner');
    assert.deepEqual(recoveries(again).map((r) => r[2]), ['re-equip', 'owner-decision']);
    assert.equal(again.soul.status().state, 'needs-owner');
  } finally { await again.done(); }
});

const understudy = (accepts) => ({
  info: {
    soul_id: SOUL,
    members: [
      { member_id: 'm_lead', role: 'lead', adapter_id: 'fake-lead', adapter_version: '0.1.0' },
      { member_id: 'm_spec', role: 'specialist', adapter_id: 'fake-specialist', adapter_version: '0.1.0', fallbacks: [{ adapter_id: 'fake-understudy', adapter_version: '0.2.0' }] },
    ],
  },
  adapters: { 'fake-lead': fake(), 'fake-specialist': fake({ fail: 'provider' }), 'fake-understudy': fake(undefined, { accepts }) },
});

test('a provider outage fails over to the owner\'s next route without a restart delay, and the task completes there', async () => {
  const t = await setup({ soul: understudy(['confidential']) });
  try {
    const taskId = await t.offer({ restrictions: { labels: ['confidential'] } });
    await t.soul.prompt('work');
    assert.deepEqual(recoveries(t), [['m_spec', 'provider', 'fail-over']]);
    assert.deepEqual(t.delays, []);
    const spec = t.soul.status().members.find((m) => m.member_id === 'm_spec');
    assert.equal(spec.adapter_id, 'fake-understudy');
    // HQ admitted the understudy by name, so the route change is on record.
    assert.equal(t.receipts('hq.admission').length, 2);
    const { task, proposals } = await t.task(taskId);
    assert.deepEqual([task.status, proposals.length, finals(t, taskId).length], ['completed', 1, 1]);
  } finally { await t.done(); }
});

test('a fail-over route that may not receive the task\'s data is not used: the work pauses', async () => {
  const t = await setup({ soul: understudy([]) });
  try {
    const taskId = await t.offer({ restrictions: { labels: ['confidential'] } });
    await assert.rejects(t.soul.prompt('work'));
    assert.deepEqual(recoveries(t), [['m_spec', 'provider', 'pause']]);
    const status = t.soul.status();
    assert.equal(status.state, 'unavailable');
    assert.equal(status.members.find((m) => m.member_id === 'm_spec').adapter_id, 'fake-specialist', 'no context went to the understudy');
    assert.equal(t.receipts('hq.admission').length, 1);
    // The task is still running in HQ, with the handoff note for whoever resumes it.
    assert.equal((await t.task(taskId)).task.status, 'running');
    assert.deepEqual(handoffs(t.contents).map((n) => [n.task_id, n.disclosure_restrictions]), [[taskId, ['confidential']]]);
  } finally { await t.done(); }
});

test('a corrupted restricted handoff cannot become permission to send context to a fallback', async () => {
  const t = await setup({ soul: understudy([]) });
  try {
    await t.soul.prompt('No task is waiting yet.');
    const notes = join(t.contents, 'comms', 'notes');
    mkdirSync(notes, { recursive: true });
    writeFileSync(join(notes, 'restricted.json'), JSON.stringify({
      note_id: 'note_restricted', type: 'handoff', member_id: 'm_lead', runtime_id: 'rt_lead',
      timestamp: '2026-11-09T00:00:00Z', body: 'Restricted context', provenance: ['member'],
      disclosure_restrictions: ['confidential'], unexpected: 'corrupted after storage',
    }));
    await t.offer({ restrictions: { labels: ['confidential'] } });
    await assert.rejects(t.soul.prompt('Continue the task.'));
    assert.throws(() => handoffs(t.contents), /handoff restrictions are unavailable/);
    assert.equal(t.soul.status().members.find((m) => m.member_id === 'm_spec').adapter_id, 'fake-specialist');
    assert.equal(t.receipts('hq.admission').length, 1, 'no fallback was admitted');
    assert.deepEqual(recoveries(t), [], 'corrupt notes were not converted into an unrestricted fail-over');
  } finally { await t.done(); }
});

test('an identity-service outage is not a member failure: no restart, no fail-over, the Soul waits', async () => {
  const t = await setup({ soul: { lead: { fail: 'credential' } } });
  try {
    await t.offer();
    await assert.rejects(t.soul.prompt('work'), (e) => e instanceof SoulUnavailable && e.state === 'waiting' && e.reason === 'credential_unavailable');
    assert.deepEqual(recoveries(t), [['m_lead', 'credential_unavailable', 'wait']]);
    assert.deepEqual(t.delays, []);
    assert.equal(t.soul.status().members.find((m) => m.member_id === 'm_lead').running, true);
    assert.equal(t.receipts('hq.admission').length, 1);
  } finally { await t.done(); }
});

test('a lease HQ no longer honours is stale, not stopped: the Soul is admitted again and keeps working', async () => {
  const t = await setup();
  try {
    await t.soul.renew();
    assert.equal(t.soul.status().lease_generation, 1, 'renewed in time: the same lease');
    const first = await t.offer();
    await t.soul.prompt('work');

    t.clock.advance(60_001);
    await t.soul.renew();
    assert.deepEqual(t.soul.events().filter((e) => e.event === 'lease-stale').map((e) => e.code), ['lease_expired']);
    assert.equal(t.soul.status().lease_generation, 2);
    assert.ok(t.soul.status().members.every((m) => m.running), 'no member was stopped');

    const second = await t.offer();
    await t.soul.prompt('work');
    assert.deepEqual([(await t.task(first)).task.status, (await t.task(second)).task.status], ['completed', 'completed']);
    assert.equal((await t.task(second)).task.lease_generation, 2);
  } finally { await t.done(); }
});

test('HQ decides admission: a definition the owner has not accepted does not start', async () => {
  const hq = await startHQ();
  const root = makeSoul({ lock: { definition_digest: `sha256:${'b2'.repeat(32)}` } });
  try {
    await assert.rejects(startSoul({ root, hqHome: hq.home, renewEveryMs: 0 }), (e) => e.code === 'definition_not_accepted');
    assert.equal(existsSync(join(root, 'Contents/host/members.sock')), false, 'nothing is left listening');
    assert.notEqual(`sha256:${'b2'.repeat(32)}`, DIGEST);
  } finally { await hq.done(); rmSync(root, { recursive: true, force: true }); }
});
