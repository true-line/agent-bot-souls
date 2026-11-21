// The real SDK, broker, shells and seatbelt run as the invoking user. The HQ
// harness models account ownership. Native cross-UID admission is tested in HQ.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import test from 'node:test';
import { startSoul } from '../lib/entry-point.mjs';
import { connectHq } from '../lib/hq-client.mjs';
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
