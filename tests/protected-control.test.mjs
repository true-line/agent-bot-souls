import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import { setTimeout as delay } from 'node:timers/promises';
import { test } from 'node:test';
import { beginProtectedControl } from '../lib/protected-control.mjs';

test('R renews during delayed HQ admission, verifies the child frame, and keeps ACP off its control pipe', async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  const start = { reservationSha256: `sha256:${'a'.repeat(64)}`,
    startId: 'st_' + '1'.repeat(24), launchId: 'ln_' + '2'.repeat(24) };
  const stopped = [];
  let sequence = 0;
  const control = await beginProtectedControl({ start, activation: {}, input, output,
    renewIntervalMs: 10,
    childVerifier: (frame) => {
      assert.equal(frame.schema, 'agent-bot-souls/protected-child-start/v1');
      return Object.freeze({ sha256: `sha256:${'c'.repeat(64)}` });
    },
    leaseSource: async () => {
      sequence += 1;
      return { reply: { lease_sha256: `sha256:${String(sequence).padStart(64, '0')}` },
        lease: { sequence, expiresAtMs: Date.now() + 2_000 } };
    } });
  await delay(40);
  control.attachSoul({ stop: async () => { stopped.push('stopped'); } });
  let ack = '';
  output.on('data', (bytes) => { ack += bytes.toString('utf8'); });
  await control.acknowledge();
  const parsed = JSON.parse(ack.trim());
  assert.equal(parsed.schema, 'agent-bot-souls/protected-activation-ack/v1');
  assert.ok(parsed.lease_sequence > 1, 'R renewed its A lease while HQ admission was pending');
  assert.equal(parsed.lease_sha256, `sha256:${String(parsed.lease_sequence).padStart(64, '0')}`);
  input.write('{"schema":"agent-bot-souls/protected-child-start/v1"}\n');
  const receipt = await control.waitForChild();
  await control.acknowledgeChild(receipt);
  const lines = ack.trim().split('\n');
  assert.equal(lines.length, 2);
  assert.deepEqual(JSON.parse(lines[1]), { schema: 'agent-bot-souls/protected-child-ready/v1',
    reservation_sha256: start.reservationSha256, start_id: start.startId,
    launch_id: start.launchId, child_start_sha256: receipt.sha256 });
  input.write('{"jsonrpc":"2.0","method":"initialize"}\n');
  assert.deepEqual(await control.done, { reason: 'protected control stopped', stopError: null });
  assert.deepEqual(stopped, ['stopped']);
});

test('a cancelled first Live request cannot start the protected Soul', async () => {
  const abort = new AbortController();
  let release;
  const pending = new Promise((resolve) => { release = resolve; });
  const control = beginProtectedControl({
    start: { reservationSha256: `sha256:${'a'.repeat(64)}` }, activation: {},
    input: new PassThrough(), output: new PassThrough(), signal: abort.signal,
    leaseSource: () => pending,
  });
  abort.abort();
  release({ reply: { lease_sha256: `sha256:${'b'.repeat(64)}` },
    lease: { sequence: 1, expiresAtMs: Date.now() + 2_000 } });
  await assert.rejects(control, /cancelled during first Live request/);
});
