import assert from 'node:assert/strict';
import { generateKeyPairSync, createHash, sign } from 'node:crypto';
import { mkdtempSync, lstatSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';
import { test } from 'node:test';
import { canonicalize } from '../lib/contracts.mjs';
import { readProtectedActivation, verifyProtectedActivation } from '../lib/protected-activation.mjs';

const sha = (bytes) => 'sha256:' + createHash('sha256').update(bytes).digest('hex');
const now = 1_800_000_000_000;

async function withSignedFinalization(t, run) {
  const dir = mkdtempSync(join(tmpdir(), 'souls-activation-'));
  const path = join(dir, 'b.sock');
  const server = createServer();
  try {
    await new Promise((resolve) => server.listen(path, resolve));
    const observed = lstatSync(path, { bigint: true });
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const pin = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
    const start = {
      reservationSha256: sha('reservation'), installationId: 'inst_fixture',
      startId: 'st_' + '1'.repeat(24), launchId: 'ln_' + '2'.repeat(24),
      planId: 'plan_fixture', planDigest: '3'.repeat(64), hqEpoch: '4'.repeat(64),
      brokerSocket: path, bridgeUid: Number(observed.uid), runnerGid: Number(observed.gid),
    };
    const payload = {
      schema: 'agent-bot-machine/stage2a-finalization/v1',
      reservation_sha256: start.reservationSha256, installation_id: start.installationId,
      start_id: start.startId, launch_id: start.launchId, plan_id: start.planId,
      plan_digest: start.planDigest, hq_epoch: start.hqEpoch,
      bind_receipt_sha256: sha('bind'), bridge_pid: 1242,
      relay_socket: { path, socket: { uid: Number(observed.uid), gid: Number(observed.gid),
        device: observed.dev.toString(), inode: observed.ino.toString(), mode: Number(observed.mode & 0o7777n) } },
      finalized_at: new Date(now).toISOString(),
    };
    const signPayload = (body) => {
      const purpose = 'agent-bot/stage2a-finalization/v1';
      const payloadBytes = Buffer.from(canonicalize(body));
      const envelope = { schema_version: 1, purpose, issuer_public_key_base64url: pin.toString('base64url'),
        payload_sha256: sha(payloadBytes), payload_base64url: payloadBytes.toString('base64url'),
        signature_base64url: sign(null, Buffer.concat([Buffer.from(purpose + '\0'), payloadBytes]), privateKey).toString('base64url') };
      const envelopeBytes = Buffer.from(canonicalize(envelope));
      return { schema: 'agent-bot-souls/protected-activation/v1',
        reservation_sha256: start.reservationSha256, start_id: start.startId, launch_id: start.launchId,
        runner_wrapper_pid: 1241,
        finalization_sha256: sha(envelopeBytes), finalization_envelope_base64url: envelopeBytes.toString('base64url'),
        bind_receipt_sha256: body.bind_receipt_sha256 };
    };
    await run({ start, pin, payload, signPayload });
  } finally {
    await new Promise((resolve) => server.close(resolve));
    rmSync(dir, { recursive: true, force: true });
  }
}

test('R accepts only a signed B finalization bound to its reservation and live relay node', (t) => withSignedFinalization(t, ({ start, pin, payload, signPayload }) => {
  const frame = signPayload(payload);
  assert.equal(verifyProtectedActivation(frame, start, pin).relaySocket, start.brokerSocket);
  assert.throws(() => verifyProtectedActivation({ ...frame, finalization_sha256: sha('altered') }, start, pin), /envelope digest differs/);
  assert.throws(() => verifyProtectedActivation(frame, start, Buffer.alloc(32)), /installed Machine authority/);
  assert.throws(() => verifyProtectedActivation({ ...frame, live_expires_at_ms: now - 1 }, start, pin), /preface differs/);
  assert.throws(() => verifyProtectedActivation(signPayload({ ...payload, installation_id: 'inst_other' }), start, pin), /differs from the one-use start/);
  assert.throws(() => verifyProtectedActivation(signPayload({ ...payload, relay_socket: { ...payload.relay_socket, socket: { ...payload.relay_socket.socket, inode: '99' } } }), start, pin), /kernel socket differs/);
}));

test('private activation reader refuses ACP bytes before its ack barrier', async () => {
  const input = new PassThrough();
  const waiting = readProtectedActivation(input);
  input.end('{"schema":"frame"}\n{"jsonrpc":"2.0"}\n');
  await assert.rejects(waiting, /trailing or empty preface/);
});
