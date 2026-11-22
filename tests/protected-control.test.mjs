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
  let machineChildReady = false;
  const receipt = Object.freeze({ sha256: `sha256:${'c'.repeat(64)}`,
    helloFinalizationSha256: `sha256:${'d'.repeat(64)}`,
    childLauncher: { pid: 301 }, child: { pid: 302 } });
  const control = await beginProtectedControl({ start, activation: {}, input, output,
    renewIntervalMs: 10,
    childVerifier: (frame) => {
      assert.equal(frame.schema, 'agent-bot-souls/protected-child-start/v1');
      return receipt;
    },
    leaseSource: async () => {
      sequence += 1;
      return { reply: { lease_sha256: `sha256:${String(sequence).padStart(64, '0')}` },
        lease: { sequence, expiresAtMs: Date.now() + 2_000,
          childClaim: machineChildReady ? receipt : null } };
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
  machineChildReady = true;
  await delay(40);
  input.write('{"schema":"agent-bot-souls/protected-child-start/v1"}\n');
  const verified = await control.waitForChild();
  await control.acknowledgeChild(verified);
  const lines = ack.trim().split('\n');
  assert.equal(lines.length, 2);
  assert.deepEqual(JSON.parse(lines[1]), { schema: 'agent-bot-souls/protected-child-ready/v1',
    reservation_sha256: start.reservationSha256, start_id: start.startId,
    launch_id: start.launchId, child_start_sha256: verified.sha256 });
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

test('a delayed child frame cannot ack a different provisional A-signed Live child', async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  let written = '';
  output.on('data', (bytes) => { written += bytes.toString('utf8'); });
  let sequence = 0;
  const claim = { sha256: `sha256:${'c'.repeat(64)}`,
    helloFinalizationSha256: `sha256:${'d'.repeat(64)}`,
    childLauncher: { pid: 301 }, child: { pid: 302 } };
  const control = await beginProtectedControl({
    start: { reservationSha256: `sha256:${'a'.repeat(64)}`,
      startId: 'st_' + '1'.repeat(24), launchId: 'ln_' + '2'.repeat(24) },
    activation: {}, input, output, renewIntervalMs: 10,
    childVerifier: () => ({ ...claim, child: { pid: 999 } }),
    leaseSource: async () => {
      sequence += 1;
      return { reply: { lease_sha256: `sha256:${String(sequence).padStart(64, '0')}` },
        lease: { sequence, expiresAtMs: Date.now() + 2_000, childClaim: sequence > 1 ? claim : null } };
    },
  });
  control.attachSoul({ stop: async () => {} });
  await control.acknowledge();
  await delay(40);
  input.write('{"schema":"agent-bot-souls/protected-child-start/v1"}\n');
  await assert.rejects(control.waitForChild(), /provisional Live child differs/);
  assert.equal(written.trim().split('\n').length, 1, 'no second ack may leave R');
  await control.stop();
});

test('late protected admission awaits Soul cleanup after the lease expires', async () => {
  const control = await beginProtectedControl({
    start: { reservationSha256: `sha256:${'a'.repeat(64)}` }, activation: {},
    input: new PassThrough(), output: new PassThrough(),
    leaseSource: async () => ({ reply: { lease_sha256: `sha256:${'b'.repeat(64)}` },
      lease: { sequence: 1, expiresAtMs: Date.now() + 30 } }),
  });
  await control.done;
  let cleaned = false;
  await assert.rejects(control.attachSoul({ stop: async () => {
    await delay(20);
    cleaned = true;
  } }), /signed lease expired during HQ admission/);
  assert.equal(cleaned, true);
});
