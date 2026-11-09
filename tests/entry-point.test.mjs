// The entry point against the real HQ and agent-comms's broker plugin
// (agent-bot-hq plan §9 row 14). The exit evidence for the row and for
// Stage 1: one task completes with scoped proposals and one final
// commitment. Then the recovery ladder, with real member processes.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { SoulUnavailable, startSoul } from '../lib/entry-point.mjs';
import { connectHq } from '../lib/hq-client.mjs';
import { handoffs, readNotes } from '../lib/notes.mjs';
import { DIGEST, fake, makeSoul, schema, setup, SOUL, startHQ, validate } from './harness.mjs';

const recoveries = (t) => t.soul.events().filter((e) => e.event === 'recovery').map((e) => [e.member_id, e.failure, e.action]);
const finals = (t, taskId) => t.receipts('task.commit').filter((r) => r.task_id === taskId && r.status === 'completed');

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
    assert.deepEqual(t.receipts('hq.bind').map((r) => r.member_id).sort(), ['m_lead', 'm_spec']);

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
    writeFileSync(join(t.contents, 'host/members.sock'), '');
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
