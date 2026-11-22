import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { test } from 'node:test';
import { canonicalize } from '../lib/contracts.mjs';
import { verifyProtectedLive } from '../lib/protected-live.mjs';

const sha = (bytes) => 'sha256:' + createHash('sha256').update(bytes).digest('hex');
const now = 1_800_000_000_000;

test('R accepts only fresh A-signed, monotonic five-second leases for the same R/B starts', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const pin = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  const challenge = randomBytes(32);
  const start = { reservationSha256: sha('reservation'), installationId: 'inst_fixture',
    startId: 'st_' + '1'.repeat(24), launchId: 'ln_' + '2'.repeat(24),
    planId: 'plan_fixture', planDigest: '3'.repeat(64), hqEpoch: '4'.repeat(64),
    runnerUid: 501, runnerGid: 20, bridgeUid: 502, bridgeGid: 20 };
  const activation = { finalizationSha256: sha('final'), bindReceiptSha256: sha('bind'),
    runnerWrapperPid: 1241, bridgePid: 1242 };
  const runner = { pid: 1241, uid: 501, gid: 20, start_seconds: 1700000000, start_micros: 12345 };
  const bridge = { pid: 1242, uid: 502, gid: 20, start_seconds: 1700000000, start_micros: 23456 };
  const payload = { schema: 'agent-bot-machine/stage2a-live-lease/v1',
    reservation_sha256: start.reservationSha256, installation_id: start.installationId,
    start_id: start.startId, launch_id: start.launchId, plan_id: start.planId,
    plan_digest: start.planDigest, hq_epoch: start.hqEpoch,
    finalization_sha256: activation.finalizationSha256, bind_receipt_sha256: activation.bindReceiptSha256,
    challenge: challenge.toString('base64url'), runner, bridge, sequence: 1,
    issued_at_ms: now - 100, expires_at_ms: now + 4000 };
  const signed = (body) => {
    const purpose = 'agent-bot/stage2a-live-lease/v1';
    const payloadBytes = Buffer.from(canonicalize(body));
    const envelopeBytes = Buffer.from(canonicalize({ schema_version: 1, purpose,
      issuer_public_key_base64url: pin.toString('base64url'), payload_sha256: sha(payloadBytes),
      payload_base64url: payloadBytes.toString('base64url'),
      signature_base64url: sign(null, Buffer.concat([Buffer.from(purpose + '\0'), payloadBytes]), privateKey).toString('base64url') }));
    return { lease_envelope_base64url: envelopeBytes.toString('base64url'),
      lease_sha256: sha(envelopeBytes), lease_sequence: body.sequence,
    };
  };
  const first = verifyProtectedLive(signed(payload), start, activation, challenge, null, pin, now);
  assert.equal(first.sequence, 1);
  assert.throws(() => verifyProtectedLive(signed(payload), start, activation, challenge, first, pin, now), /sequence is stale/);
  assert.throws(() => verifyProtectedLive(signed(payload), start, activation, randomBytes(32), null, pin, now), /challenge/);
  assert.throws(() => verifyProtectedLive(signed({ ...payload, expires_at_ms: now - 1 }), start, activation, challenge, null, pin, now), /expired/);
  assert.throws(() => verifyProtectedLive(signed({ ...payload, finalization_sha256: sha('wrong') }), start, activation, challenge, null, pin, now), /B finalization/);
  assert.throws(() => verifyProtectedLive(signed({ ...payload, bridge: { ...bridge, start_micros: bridge.start_micros + 1 }, sequence: 2 }), start, activation, challenge, first, pin, now), /role start identity changed/);
  const next = verifyProtectedLive(signed({ ...payload, sequence: 2 }), start, activation, challenge, first, pin, now);
  assert.equal(next.sequence, 2);
  const skipped = verifyProtectedLive(signed({ ...payload, sequence: 4 }), start, activation, challenge, next, pin, now);
  assert.equal(skipped.sequence, 4);
  const childLauncher = { ...runner, pid: 1243, start_micros: 34567 };
  const child = { ...runner, pid: 1244, start_micros: 45678 };
  const childReceipt = { sha256: sha('child receipt'), helloFinalizationSha256: sha('hello finalization'),
    childLauncher, child };
  const withChild = { ...payload, sequence: 5,
    hello_finalization_sha256: childReceipt.helloFinalizationSha256,
    child_launcher: childLauncher, child, child_receipt_sha256: childReceipt.sha256 };
  assert.equal(verifyProtectedLive(signed(withChild), start, activation, challenge, skipped, pin, now, childReceipt).sequence, 5);
  assert.throws(() => verifyProtectedLive(signed({ ...withChild, child: { ...child, pid: 9999 } }),
    start, activation, challenge, skipped, pin, now, childReceipt), /child identity differs/);
  assert.throws(() => verifyProtectedLive(signed({ ...withChild, child_receipt_sha256: sha('other receipt') }),
    start, activation, challenge, skipped, pin, now, childReceipt), /child identity differs/);
});
