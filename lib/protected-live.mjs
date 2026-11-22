// A signs a fresh short lease for each R challenge. HQ only transports the
// envelope; it cannot extend the stock child after A revokes the start.
import { createHash, createPublicKey, verify } from 'node:crypto';
import { canonicalize, parseStrict } from './contracts.mjs';
import { readMachinePin } from './protected-start.mjs';

const PURPOSE = 'agent-bot/stage2a-live-lease/v1';
const ENVELOPE = ['schema_version', 'purpose', 'issuer_public_key_base64url', 'payload_sha256', 'payload_base64url', 'signature_base64url'];
const PAYLOAD = ['schema', 'reservation_sha256', 'installation_id', 'start_id', 'launch_id', 'plan_id', 'plan_digest', 'hq_epoch', 'finalization_sha256', 'bind_receipt_sha256', 'challenge', 'runner', 'bridge', 'sequence', 'issued_at_ms', 'expires_at_ms'];
const CHILD_PAYLOAD = [...PAYLOAD, 'hello_finalization_sha256', 'child_launcher', 'child', 'child_receipt_sha256'];
const ROLE = ['pid', 'uid', 'gid', 'start_seconds', 'start_micros'];
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const exact = (value, fields) => value !== null && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === fields.length && fields.every((field) => Object.hasOwn(value, field));
const digest = (bytes) => 'sha256:' + createHash('sha256').update(bytes).digest('hex');
const bad = (reason) => { throw new Error('protected live: ' + reason); };

function decode(value, length) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) bad('noncanonical base64url');
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.toString('base64url') !== value || (length !== undefined && bytes.length !== length)) bad('noncanonical base64url');
  return bytes;
}

function signedJson(bytes) {
  let raw, value;
  try {
    raw = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    value = parseStrict(raw);
  } catch { bad('invalid signed JSON'); }
  if (canonicalize(value) !== raw) bad('signed JSON is not canonical');
  return value;
}

const validRole = (role, uid, gid) => exact(role, ROLE)
  && Number.isSafeInteger(role.pid) && role.pid > 1
  && role.uid === uid && role.gid === gid
  && Number.isSafeInteger(role.start_seconds) && role.start_seconds > 0
  && Number.isSafeInteger(role.start_micros) && role.start_micros >= 0 && role.start_micros < 1_000_000;

export function verifyProtectedLive(reply, start, activation, challenge, previous, pin, now = Date.now(), childReceipt = null) {
  if (!exact(reply, ['lease_envelope_base64url', 'lease_sha256', 'lease_sequence'])
    || !SHA256.test(reply.lease_sha256) || !Number.isSafeInteger(reply.lease_sequence)
    || !Buffer.isBuffer(pin) || pin.length !== 32 || !Buffer.isBuffer(challenge) || challenge.length !== 32) {
    bad('invalid lease reply or challenge');
  }
  const bytes = decode(reply.lease_envelope_base64url);
  if (bytes.length > 8 * 1024 || digest(bytes) !== reply.lease_sha256) bad('lease envelope digest differs');
  const envelope = signedJson(bytes);
  if (!exact(envelope, ENVELOPE) || envelope.schema_version !== 1 || envelope.purpose !== PURPOSE
    || !SHA256.test(envelope.payload_sha256) || !decode(envelope.issuer_public_key_base64url, 32).equals(pin)) {
    bad('lease signer differs from installed Machine authority');
  }
  const payloadBytes = decode(envelope.payload_base64url);
  if (digest(payloadBytes) !== envelope.payload_sha256) bad('lease payload digest differs');
  const key = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), pin]), format: 'der', type: 'spki' });
  if (!verify(null, Buffer.concat([Buffer.from(PURPOSE + '\0'), payloadBytes]), key,
    decode(envelope.signature_base64url, 64))) bad('invalid lease signature');
  const payload = signedJson(payloadBytes);
  if (!exact(payload, childReceipt ? CHILD_PAYLOAD : PAYLOAD) || payload.schema !== 'agent-bot-machine/stage2a-live-lease/v1'
    || payload.reservation_sha256 !== start.reservationSha256
    || payload.installation_id !== start.installationId || payload.start_id !== start.startId
    || payload.launch_id !== start.launchId || payload.plan_id !== start.planId
    || payload.plan_digest !== start.planDigest || payload.hq_epoch !== start.hqEpoch
    || payload.finalization_sha256 !== activation.finalizationSha256
    || payload.bind_receipt_sha256 !== activation.bindReceiptSha256
    || payload.challenge !== challenge.toString('base64url')) {
    bad('lease differs from signed start, B finalization or fresh challenge');
  }
  if (!validRole(payload.runner, start.runnerUid, start.runnerGid)
    || !validRole(payload.bridge, start.bridgeUid, start.bridgeGid)
    || payload.runner.pid !== activation.runnerWrapperPid
    || payload.bridge.pid !== activation.bridgePid) bad('lease role identity differs from live start');
  if (childReceipt && (payload.child_receipt_sha256 !== childReceipt.sha256
    || payload.hello_finalization_sha256 !== childReceipt.helloFinalizationSha256
    || !validRole(payload.child_launcher, start.runnerUid, start.runnerGid)
    || !validRole(payload.child, start.runnerUid, start.runnerGid)
    || canonicalize(payload.child_launcher) !== canonicalize(childReceipt.childLauncher)
    || canonicalize(payload.child) !== canonicalize(childReceipt.child))) {
    bad('lease child identity differs from signed child start');
  }
  if (!Number.isSafeInteger(payload.sequence) || payload.sequence < 1
    || payload.sequence !== reply.lease_sequence
    || (previous && payload.sequence <= previous.sequence)) bad('lease sequence is stale');
  if (previous && (canonicalize(payload.runner) !== canonicalize(previous.runner)
    || canonicalize(payload.bridge) !== canonicalize(previous.bridge))) bad('lease role start identity changed');
  if (!Number.isSafeInteger(payload.issued_at_ms) || !Number.isSafeInteger(payload.expires_at_ms)
    || payload.issued_at_ms > now || payload.expires_at_ms <= now
    || payload.expires_at_ms <= payload.issued_at_ms || payload.expires_at_ms - payload.issued_at_ms > 5_000) {
    bad('lease is expired, future-dated or exceeds five seconds');
  }
  return Object.freeze({ sequence: payload.sequence, runner: Object.freeze(payload.runner),
    bridge: Object.freeze(payload.bridge), expiresAtMs: payload.expires_at_ms });
}

export function checkProtectedLive(reply, start, activation, challenge, previous, childReceipt = null) {
  return verifyProtectedLive(reply, start, activation, challenge, previous, readMachinePin(), Date.now(), childReceipt);
}
