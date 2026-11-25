import assert from 'node:assert/strict';
import { test } from 'node:test';
import { watchProtectedLease } from '../lib/protected-watchdog.mjs';

test('a stalled HQ renewal cannot extend the last signed lease', async () => {
  const reasons = [];
  const start = Date.now();
  const watcher = watchProtectedLease({ sequence: 1, expiresAtMs: start + 80 }, {
    intervalMs: 10,
    renew: () => new Promise(() => {}),
    stop: (reason) => { reasons.push(reason); },
  });
  assert.deepEqual(await watcher.done, { reason: 'signed lease expired', stopError: null });
  assert.deepEqual(reasons, ['signed lease expired']);
  assert.ok(Date.now() - start < 1_000);
});

test('a duplicate lease causes immediate stop and cannot replace current authority', async () => {
  const reasons = [];
  const watcher = watchProtectedLease({ sequence: 2, expiresAtMs: Date.now() + 2_000 }, {
    intervalMs: 10,
    renew: (current) => ({ ...current, expiresAtMs: Date.now() + 2_000 }),
    stop: (reason) => { reasons.push(reason); },
  });
  assert.deepEqual(await watcher.done, { reason: 'signed lease renewal invalid', stopError: null });
  assert.deepEqual(reasons, ['signed lease renewal invalid']);
  assert.equal(watcher.current().sequence, 2);
});
