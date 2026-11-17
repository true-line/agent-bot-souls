// Running a Soul without HQ (agent-bot-souls#4, platform PDR-0055). HQ is
// there when its admission socket answers; then the HQ flow is used and
// --standalone is ignored, and said so. Otherwise the entry point stops and
// says which case it found, unless the person running the Soul asked for
// --standalone this run. A standalone run is an unmanaged Soul and reports
// `standalone-unenforced`. The running-HQ case runs the real HQ.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { HqNotFound, SoulUnavailable, STANDALONE_WARNINGS, startSoul } from '../lib/entry-point.mjs';
import { BIN, fake, makeSoul, SOUL, startHQ } from './harness.mjs';

const absent = () => join(tmpdir(), `no-hq-${process.pid}-${Math.random().toString(16).slice(2)}`);
const quiet = { delay: async () => {}, renewEveryMs: 0 };

async function standalone(t, hqHome, soulOptions) {
  const root = makeSoul(soulOptions);
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const soul = await startSoul({ root, hqHome, standalone: true, ...quiet });
  t.after(() => soul.stop());
  return { root, soul };
}

test('with no HQ installed and no --standalone, the entry point stops and says so', async (t) => {
  const root = makeSoul();
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const hqHome = absent();
  await assert.rejects(startSoul({ root, hqHome, ...quiet }), (e) => {
    assert.ok(e instanceof HqNotFound);
    assert.equal(e.found, 'not-installed');
    assert.match(e.message, /HQ is not installed/);
    assert.match(e.message, /--standalone/);
    return true;
  });
  assert.equal(existsSync(join(root, 'Contents', 'host', 'members.sock')), false, 'nothing was started');
});

test('with HQ installed and not running, and no --standalone, the entry point stops and names that case', async (t) => {
  const root = makeSoul();
  const hqHome = mkdtempSync(join(tmpdir(), 'hq-'));
  t.after(() => { rmSync(root, { recursive: true, force: true }); rmSync(hqHome, { recursive: true, force: true }); });
  await assert.rejects(startSoul({ root, hqHome, ...quiet }), (e) => {
    assert.ok(e instanceof HqNotFound);
    assert.equal(e.found, 'not-running');
    assert.match(e.message, /installed at .* but not running/);
    return true;
  });
});

test('--standalone with no HQ runs an unmanaged Soul that reports standalone-unenforced and what it lacks', async (t) => {
  const { soul } = await standalone(t, absent());
  const status = soul.status();
  assert.equal(status.state, 'ready');
  assert.equal(status.soul_id, SOUL);
  assert.equal(status.profile, 'standalone-unenforced');
  assert.equal(status.hq, 'not-installed');
  assert.deepEqual(status.warnings, [...STANDALONE_WARNINGS]);
  assert.equal(status.installation_epoch, undefined, 'no epoch without HQ');
  assert.equal(status.lease_generation, undefined, 'no lease without HQ');
  const [started] = soul.events();
  assert.deepEqual([started.event, started.hq, started.profile], ['standalone', 'not-installed', 'standalone-unenforced']);
  assert.equal(soul.events().filter((e) => e.event === 'admitted').length, 0);

  // The owner's conversation still works. The lead's runtime is refused as
  // unmanaged, so it has no directives or task records to work.
  const result = await soul.prompt('Anything waiting?');
  assert.equal(result.member_id, 'm_lead');
  assert.match(result.text, /runs unmanaged, without HQ; there are no directives or task records/);
});

test('--standalone with HQ installed and not running proceeds, and says it found HQ stopped', async (t) => {
  const hqHome = mkdtempSync(join(tmpdir(), 'hq-'));
  t.after(() => rmSync(hqHome, { recursive: true, force: true }));
  const { soul } = await standalone(t, hqHome);
  assert.deepEqual([soul.status().profile, soul.status().hq], ['standalone-unenforced', 'not-running']);
  assert.match(soul.events()[0].message, /HQ is installed and not running/);
});

test('with HQ running, --standalone is ignored and said so: the HQ flow is used', async (t) => {
  const hq = await startHQ();
  const root = makeSoul();
  t.after(async () => { await hq.done(); rmSync(root, { recursive: true, force: true }); });
  const soul = await startSoul({ root, hqHome: hq.home, standalone: true, ...quiet });
  t.after(() => soul.stop());
  const status = soul.status();
  assert.deepEqual([status.profile, status.hq, status.installation_epoch], ['managed-cooperative', 'running', 1]);
  const ignored = soul.events().find((e) => e.event === 'standalone-ignored');
  assert.match(ignored.message, /--standalone was ignored/);
  assert.equal(soul.events().filter((e) => e.event === 'standalone').length, 0);
  assert.equal(hq.hq.core.receipts.filter((r) => r.kind === 'hq.admission').length, 1);
});

test('without HQ an authentication failure has nothing to re-equip it: it is the owner\'s decision', async (t) => {
  const { soul } = await standalone(t, absent(), { lead: { fail: 'auth' } });
  await assert.rejects(soul.prompt('go'), (e) => e instanceof SoulUnavailable && e.state === 'needs-owner' && /no HQ to re-equip/.test(e.reason));
});

test('without HQ a crashed member is restarted without an admission and the turn continues', async (t) => {
  const { soul } = await standalone(t, absent(), { lead: { crash: 'on-prompt', once: true } });
  const result = await soul.prompt('go');
  assert.match(result.text, /runs unmanaged/);
  assert.deepEqual(soul.events().filter((e) => e.event === 'recovery').map((e) => [e.member_id, e.failure, e.action]), [['m_lead', 'crash', 'restart']]);
  assert.equal(soul.events().filter((e) => e.event === 'admitted').length, 0);
});

test('the executable stops without HQ, and with --standalone a chat reports the unmanaged profile', (t) => {
  const root = makeSoul({ adapters: { 'fake-lead': fake(), 'fake-specialist': fake() } });
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const env = { ...process.env, AGENT_BOT_HQ_HOME: absent() };
  const stopped = spawnSync(process.execPath, [BIN, 'run', '--soul', root], { env, input: '', encoding: 'utf8' });
  assert.equal(stopped.status, 1);
  assert.match(stopped.stderr, /agent-bot-souls: HQ is not installed .*--standalone/);

  const ran = spawnSync(process.execPath, [BIN, 'chat', '--soul', root, '--standalone'], { env, input: '/status\n/quit\n', encoding: 'utf8' });
  assert.equal(ran.status, 0, ran.stderr);
  assert.equal(JSON.parse(ran.stdout).profile, 'standalone-unenforced');
  assert.match(ran.stderr, /"event":"standalone"/);
});
