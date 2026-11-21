// The real SDK, broker, shells and seatbelt run as the invoking user. The HQ
// harness models account ownership. Native cross-UID admission is tested in HQ.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { existsSync, readFileSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import test from 'node:test';
import { startSoul } from '../lib/entry-point.mjs';
import { connectHq } from '../lib/hq-client.mjs';
import { rpcPeer } from '../lib/jsonrpc.mjs';
import { checkout, PINS } from './pinned.mjs';

test('sandboxed members say hello, bind to their broker and lose their token on stop', {
  skip: process.platform !== 'darwin', timeout: 30_000,
}, async () => {
  const { accountHQ, setup } = await import('./harness.mjs');
  const pin = PINS['agent-bot-machine'];
  const profile = join(checkout('agent-bot-machine'), pin.profile);
  assert.equal(createHash('sha256').update(readFileSync(profile)).digest('hex'), pin.profile_sha256);
  const isolated = accountHQ(undefined, profile);
  const launches = () => isolated.launch.calls.filter(call => call.args[1] === '-H').map(call => call.options.env);
  let world, next;
  try {
    world = await setup({ hq: isolated.options });
    async function completeTask(soul) {
      const id = await world.offer();
      assert.match((await soul.prompt('Work the waiting task.')).text, new RegExp('Completed ' + id));
      assert.equal(world.receipts('task.commit').filter(r => r.task_id === id && r.status === 'completed').length, 1);
      assert.deepEqual(soul.events().filter(e => e.event === 'member-started').map(e => [e.member_id, e.launch]).sort(),
        [['m_lead', 'hq'], ['m_spec', 'hq']]);
    }
    await completeTask(world.soul);
    const old = launches();
    assert.equal(old.length, 2);
    const accounts = { m_lead: 'hqm_a', m_spec: 'hqm_b' };
    for (const env of old) {
      const dir = join(isolated.layout.dir, accounts[env.AGENT_BOT_SOULS_MEMBER_ID]);
      assert.equal(env.AGENT_BOT_SOULS_BROKER, join(dir, 'broker.sock'));
      assert.equal(dirname(env.AGENT_BOT_SOULS_SOCKET), dir);
      assert.notEqual(env.AGENT_BOT_SOULS_SOCKET, env.AGENT_BOT_SOULS_BROKER);
    }
    await world.soul.stop();
    assert.ok(old.every(env => !existsSync(env.AGENT_BOT_SOULS_SOCKET)));
    next = await startSoul({ root: world.root, hqHome: world.home, renewEveryMs: 0 });
    await completeTask(next);
    const fresh = launches().slice(2);
    assert.equal(fresh.length, 2);
    for (const prior of old) {
      const member = fresh.find(env => env.AGENT_BOT_SOULS_MEMBER_ID === prior.AGENT_BOT_SOULS_MEMBER_ID);
      assert.ok(member && member.AGENT_BOT_SOULS_MEMBER_TOKEN !== prior.AGENT_BOT_SOULS_MEMBER_TOKEN);
      assert.notEqual(member.AGENT_BOT_SOULS_SOCKET, prior.AGENT_BOT_SOULS_SOCKET);
      const client = await connectHq(member.AGENT_BOT_SOULS_SOCKET);
      try {
        await assert.rejects(client.request('hello', { token: prior.AGENT_BOT_SOULS_MEMBER_TOKEN }),
          error => error.code === 'souls.unknown_member');
      } finally { await client.close(); }
    }
    assert.deepEqual(world.receipts('hq.bind').map(r => [r.member_id, r.caller_account, r.proof]).sort(), [
      ['m_lead', 'hqm_a', 'hmac-sha256'], ['m_lead', 'hqm_a', 'hmac-sha256'],
      ['m_spec', 'hqm_b', 'hmac-sha256'], ['m_spec', 'hqm_b', 'hmac-sha256'],
    ]);
    await next.stop();
    assert.ok(fresh.every(env => !existsSync(env.AGENT_BOT_SOULS_SOCKET)));
  } finally {
    try { await next?.stop(); } finally {
      try { await world?.done(); } finally { isolated.layout.remove(); }
    }
  }
});

test('Darwin Soul shutdown closes both accepted members and reports incomplete stops', {
  skip: process.platform !== 'darwin', timeout: 45_000,
}, async (t) => {
  const { accountHQ, BIN, hqProxy, makeSoul, SOUL, startHQ } = await import('./harness.mjs');
  const machine = PINS['agent-bot-machine'];
  const profile = join(checkout('agent-bot-machine'), machine.profile);
  assert.equal(createHash('sha256').update(readFileSync(profile)).digest('hex'), machine.profile_sha256);

  for (const scenario of ['normal', 'uncontained', 'refusal', 'disconnect']) await t.test(scenario, async () => {
    const isolated = accountHQ(undefined, profile);
    const hq = await startHQ(isolated.options);
    const root = makeSoul();
    const deliveredStops = [];
    const proxy = await hqProxy(hq, ({ op, reply }) => {
      if (op !== 'launch.stop') return reply;
      assert.equal(reply.result?.state, 'exited');
      deliveredStops.push(reply.result.launch_id);
      if (deliveredStops.length !== 1) return reply;
      if (scenario === 'uncontained') return { ...reply, result: { ...reply.result, state: 'uncontained' } };
      if (scenario === 'refusal') return { id: reply.id, ok: false, host_refusal: { code: 'host.not_running', explanation: 'HQ is stopping' } };
      if (scenario === 'disconnect') return Promise.reject(new Error('fixture drops first stop response'));
      return reply;
    });
    const child = spawn(process.execPath, [BIN, 'run', '--soul', root, '--hq-home', proxy.home], { stdio: ['pipe', 'pipe', 'pipe'] });
    const exited = once(child, 'exit');
    let stderr = '';
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    try {
      const offer = await (await hq.owner()).request('tasks.offer', { operation_id: 'offer_shutdown', objective: 'Exercise shutdown', done_criteria: 'Both members started', accountable_soul: SOUL });
      assert.equal(offer.ok, true);
      let text = '';
      const client = rpcPeer({ input: child.stdout, output: child.stdin, onNotify: (_method, params) => { text += params?.update?.content?.text ?? ''; } });
      await client.request('initialize', { protocolVersion: 1 });
      const { sessionId } = await client.request('session/new', { cwd: root, mcpServers: [] });
      await client.request('session/prompt', { sessionId, prompt: [{ type: 'text', text: 'Work the waiting task.' }] });
      assert.match(text, new RegExp(`Completed ${offer.result.task_id}`));
      const launches = isolated.launch.calls.filter((call) => call.args[1] === '-H');
      assert.deepEqual(launches.map((call) => call.options.env.AGENT_BOT_SOULS_MEMBER_ID), ['m_lead', 'm_spec']);
      assert.ok(launches.every((call) => call.child.exitCode === null && existsSync(call.options.env.AGENT_BOT_SOULS_SOCKET)));
      assert.equal(hq.hq.core.receipts.filter((row) => row.kind === 'hq.bind').length, 2);
      const memberExits = Promise.all(launches.map((call) => once(call.child, 'exit')));

      if (scenario === 'disconnect') child.kill('SIGTERM');
      else child.stdin.end();
      const [code, signal] = await exited;
      assert.equal(signal, null);
      assert.equal(code, scenario === 'normal' ? 0 : 1);
      if (scenario === 'uncontained') assert.match(stderr, /m_lead.*uncontained/);
      if (scenario === 'refusal') assert.match(stderr, /host.not_running.*HQ is stopping/);
      if (scenario === 'disconnect') assert.match(stderr, /launch.stop:.*(?:closed|end)/);
      assert.equal(deliveredStops.length, scenario === 'disconnect' ? 1 : 2);
      await memberExits;
      assert.ok(launches.every((call) => !existsSync(call.options.env.AGENT_BOT_SOULS_SOCKET)));
      assert.equal(existsSync(join(root, 'Contents', 'host', 'members.sock')), false);
    } finally {
      child.kill('SIGKILL');
      await exited;
      await proxy.done();
      await hq.done();
      isolated.layout.remove();
      rmSync(root, { recursive: true, force: true });
    }
  });
});
