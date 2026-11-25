import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { SoulUnavailable, startSoul } from '../lib/entry-point.mjs';
import { BIN, fake, hqProxy, makeSoul, startHQ } from './harness.mjs';

const quiet = { delay: async () => {}, renewEveryMs: 0, env: {} };

function packageAndHqHome(t, options) {
  const root = makeSoul(options);
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return { root, hqHome: join(root, 'hq') };
}

for (const condition of ['not-installed', 'not-running']) {
  test(`local start with HQ ${condition} requires an explicit per-run switch`, async (t) => {
    const paths = packageAndHqHome(t);
    if (condition === 'not-running') mkdirSync(paths.hqHome);
    await assert.rejects(startSoul({ ...paths, ...quiet }), { name: 'HqUnavailable', status: condition });
    assert.equal(existsSync(join(paths.root, 'Contents/host/installation.json')), false);

    const soul = await startSoul({ ...paths, ...quiet, standalone: true });
    try {
      const status = soul.status();
      assert.equal(status.hq, condition);
      assert.equal(status.profile, 'standalone-unenforced');
      assert.equal(status.installation_epoch, undefined);
      assert.equal(status.lease_generation, undefined);
      await soul.renew();
      assert.match((await soul.prompt('Hello.')).text, /runs unmanaged/);
      assert.equal(soul.events().some((event) => event.event === 'admitted'), false);
    } finally { await soul.stop(); }
  });
}

test('listening HQ takes precedence and its Hello refusal still stops the run', async (t) => {
  const { root } = packageAndHqHome(t);
  const hq = await startHQ();
  t.after(() => hq.done());
  let soul = await startSoul({ root, hqHome: hq.home, ...quiet, standalone: true });
  try {
    assert.equal(soul.status().profile, 'managed-cooperative');
    assert.ok(soul.events().some((event) => event.event === 'standalone-ignored'));
  } finally { await soul.stop(); }

  const proxy = await hqProxy(hq, ({ op, reply }) => op === 'Hello' && reply.ok
    ? { id: reply.id, ok: false, refusal: { error: 'profile_insufficient', explanation: 'requested profile unavailable', correlation_id: 'corr_profile' } }
    : reply);
  try {
    await assert.rejects(startSoul({ root, hqHome: proxy.home, ...quiet, standalone: true }),
      { name: 'HqRefusal', op: 'Hello', code: 'profile_insufficient' });
  } finally { await proxy.done(); }
});

test('standalone cannot replace a required HQ launch, assigned endpoints or an explicit profile', async (t) => {
  const { root, hqHome } = packageAndHqHome(t);
  for (const options of [
    { hqHome, env: { AGENT_BOT_SOULS_REQUIRE_HQ_LAUNCH: '1' } },
    { admissionSocket: join(hqHome, 'admission.sock'), brokerSocket: join(hqHome, 'broker.sock') },
    { hqHome, requestedProfile: 'managed-cooperative' },
    { hqHome, requestedProfile: 'managed-protected' },
    { hqHome, cooperativeStart: {} },
    { hqHome, protectedStart: {} },
  ]) {
    await assert.rejects(startSoul({ root, ...quiet, standalone: true, ...options }),
      { name: 'SoulUnavailable', code: 'profile_insufficient' });
  }
  assert.equal(existsSync(join(root, 'Contents/host/installation.json')), false);
});

test('standalone returns a typed refusal for note writes and broker operations', async (t) => {
  const adapter = `
    import { connectMember } from ${JSON.stringify(new URL('../lib/member.mjs', import.meta.url).href)};
    import { rpcPeer } from ${JSON.stringify(new URL('../lib/jsonrpc.mjs', import.meta.url).href)};
    const peer = rpcPeer({
      input: process.stdin,
      output: process.stdout,
      methods: {
        initialize: () => ({ protocolVersion: 1 }),
        'session/new': () => ({ sessionId: 'test-session' }),
        'session/prompt': async ({ sessionId }) => {
          const member = await connectMember();
          try {
            const refusals = [];
            for (const perform of [
              () => member.note({ type: 'finding', body: 'local test' }),
              () => member.directives(),
            ]) {
              try { await perform(); refusals.push(null); }
              catch (error) { refusals.push(error.code); }
            }
            peer.notify('session/update', { sessionId, update: { sessionUpdate: 'agent_message_chunk',
              content: { type: 'text', text: JSON.stringify(refusals) } } });
            return { stopReason: 'end_turn' };
          } finally { await member.close(); }
        },
      },
    });
  `;
  const paths = packageAndHqHome(t, { adapters: {
    'fake-lead': { command: [process.execPath, '--input-type=module', '-e', adapter] },
    'fake-specialist': fake(),
  } });
  const soul = await startSoul({ ...paths, ...quiet, standalone: true });
  try {
    const result = await soul.prompt('Start the lead.');
    assert.deepEqual(JSON.parse(result.text), ['souls.unmanaged', 'souls.unmanaged']);
  } finally { await soul.stop(); }
});

test('standalone restarts a crashed adapter and sends an auth failure to the owner', async (t) => {
  const crash = packageAndHqHome(t, { lead: { crash: 'on-prompt', once: true } });
  let soul = await startSoul({ ...crash, ...quiet, standalone: true });
  try {
    assert.match((await soul.prompt('Restart the lead.')).text, /runs unmanaged/);
    assert.ok(soul.events().some((event) => event.event === 'recovery' && event.action === 'restart'));
  } finally { await soul.stop(); }

  const auth = packageAndHqHome(t, { lead: { fail: 'auth' } });
  soul = await startSoul({ ...auth, ...quiet, standalone: true });
  try {
    await assert.rejects(soul.prompt('Check auth.'), { name: SoulUnavailable.name, state: 'needs-owner' });
  } finally { await soul.stop(); }
});

test('the CLI requires the flag, reports the standalone profile and refuses conflicting options', (t) => {
  const { root, hqHome } = packageAndHqHome(t);
  const run = (args, input = '') => spawnSync(process.execPath, [BIN, ...args], {
    env: { ...process.env, AGENT_BOT_HQ_HOME: hqHome },
    input, encoding: 'utf8',
  });
  const missing = run(['run', '--soul', root]);
  assert.equal(missing.status, 1);
  assert.match(missing.stderr, /HQ home is missing.*--standalone/);
  const started = run(['chat', '--standalone', '--soul', root], '/status\n/quit\n');
  assert.equal(started.status, 0, started.stderr);
  assert.equal(JSON.parse(started.stdout).profile, 'standalone-unenforced');
  const acp = run(['run', '--soul', root, '--standalone']);
  assert.equal(acp.status, 0, acp.stderr);
  assert.match(acp.stderr, /"event":"standalone"/);
  const conflict = run(['run', '--soul', root, '--standalone', '--protected-start-fd', '3']);
  assert.equal(conflict.status, 1);
  assert.match(conflict.stderr, /--standalone requires the default profile/);
});
