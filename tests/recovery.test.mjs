// The recovery ladder's decisions (0.4 §9), with a clock and no processes.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { BACKOFF_MS, classify, createLadder } from '../lib/recovery.mjs';

const clockAt = (start = 0) => { let now = start; return { now: () => now, advance: (ms) => { now += ms; } }; };

test('failures are classified before anything is restarted', () => {
  assert.equal(classify({ kind: 'exit' }), 'crash');
  assert.equal(classify({ kind: 'rpc', code: -32000 }), 'auth');
  assert.equal(classify({ kind: 'rpc', code: -32603, data: { failure: 'provider_unavailable' } }), 'provider');
  assert.equal(classify({ kind: 'rpc', code: -32603, data: { failure: 'credential_unavailable' } }), 'credential_unavailable');
  assert.equal(classify({ kind: 'transport' }), 'unknown_outcome');
  // A refused or failed prompt is not a member failure.
  assert.equal(classify({ kind: 'rpc', code: -32602 }), undefined);
  assert.equal(classify(undefined), undefined);
});

test('a crash restarts the same member after 5 s, 30 s, 2 min, then 10 min; the fifth in an hour quarantines the Soul', () => {
  const clock = clockAt();
  const ladder = createLadder({ clock });
  const delays = [];
  for (let i = 0; i < 4; i += 1) {
    const a = ladder.next('crash', { memberId: 'm_lead' });
    assert.equal(a.action, 'restart');
    delays.push(a.delayMs);
    clock.advance(a.delayMs);
  }
  assert.deepEqual(delays, [5_000, 30_000, 120_000, 600_000]);
  assert.deepEqual(delays, [...BACKOFF_MS]);
  assert.deepEqual(ladder.next('crash', { memberId: 'm_lead' }), { action: 'quarantine' });
  assert.equal(ladder.quarantined, true);
  // Quarantined: every later failure, of any member and class, stays there.
  assert.deepEqual(ladder.next('crash', { memberId: 'm_spec' }), { action: 'quarantine' });
  assert.deepEqual(ladder.next('auth', { memberId: 'm_spec' }), { action: 'quarantine' });
  // The owner releases it.
  ladder.release();
  assert.deepEqual(ladder.next('crash', { memberId: 'm_lead' }), { action: 'restart', delayMs: 5_000 });
});

test('crashes count for the Soul across members, and only within the hour', () => {
  const clock = clockAt();
  const ladder = createLadder({ clock });
  for (const m of ['m_lead', 'm_spec', 'm_lead', 'm_spec']) assert.equal(ladder.next('crash', { memberId: m }).action, 'restart');
  assert.equal(ladder.next('crash', { memberId: 'm_lead' }).action, 'quarantine', 'five across two members');

  const spaced = createLadder({ clock });
  for (let i = 0; i < 12; i += 1) {
    assert.equal(spaced.next('crash', { memberId: 'm_lead' }).action, 'restart', `crash ${i + 1}`);
    clock.advance(16 * 60_000); // four an hour never reaches five
  }
});

test('the backoff is per member and starts again after a healthy turn', () => {
  const ladder = createLadder({ clock: clockAt() });
  assert.equal(ladder.next('crash', { memberId: 'm_lead' }).delayMs, 5_000);
  assert.equal(ladder.next('crash', { memberId: 'm_lead' }).delayMs, 30_000);
  assert.equal(ladder.next('crash', { memberId: 'm_spec' }).delayMs, 5_000);
  ladder.healthy('m_lead');
  assert.equal(ladder.next('crash', { memberId: 'm_lead' }).delayMs, 5_000);
});

test('an authentication failure goes to HQ for re-equipment, then to the owner', () => {
  const ladder = createLadder({ clock: clockAt() });
  assert.deepEqual(ladder.next('auth', { memberId: 'm_lead' }), { action: 're-equip' });
  assert.equal(ladder.next('auth', { memberId: 'm_lead' }).action, 'owner-decision');
  ladder.healthy('m_lead');
  assert.deepEqual(ladder.next('auth', { memberId: 'm_lead' }), { action: 're-equip' });
});

test('a provider outage fails over in the owner\'s order, only to a route that may receive the work\'s data', () => {
  const ladder = createLadder({ clock: clockAt() });
  const routes = [{ accepts: ['confidential'] }, { accepts: [] }, { accepts: ['confidential', 'internal'] }];
  assert.deepEqual(ladder.next('provider', { memberId: 'm', routes, route: 0, restrictions: [] }), { action: 'fail-over', route: 1 });
  assert.deepEqual(ladder.next('provider', { memberId: 'm', routes, route: 0, restrictions: ['confidential'] }), { action: 'fail-over', route: 2 }, 'skips the route that may not receive it');
  assert.equal(ladder.next('provider', { memberId: 'm', routes, route: 0, restrictions: ['secret'] }).action, 'pause');
  assert.equal(ladder.next('provider', { memberId: 'm', routes, route: 2, restrictions: [] }).action, 'unavailable');
  assert.equal(ladder.next('provider', { memberId: 'm', routes: [{}], route: 0 }).action, 'unavailable');
  // A provider outage never restarts a healthy process and never counts as a crash.
  for (let i = 0; i < 10; i += 1) ladder.next('provider', { memberId: 'm', routes, route: 0 });
  assert.equal(ladder.quarantined, false);
});

test('an identity-service outage waits; an unknown outcome reconciles; neither restarts or fails over', () => {
  const ladder = createLadder({ clock: clockAt() });
  assert.deepEqual(ladder.next('credential_unavailable', { memberId: 'm' }), { action: 'wait', reason: 'credential_unavailable' });
  assert.deepEqual(ladder.next('unknown_outcome', { memberId: 'm' }), { action: 'reconcile' });
  assert.deepEqual(ladder.next(undefined, { memberId: 'm' }), { action: 'none' });
});
