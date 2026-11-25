// HQ sends this private preface only after Machine has finalized B and
// confirmed the live R/B start. It is consumed before owner ACP stdio.
import { createHash, createPublicKey, verify } from 'node:crypto';
import { lstatSync } from 'node:fs';
import { canonicalize, parseStrict } from './contracts.mjs';
import { readMachinePin } from './protected-start.mjs';

const PURPOSE = 'agent-bot/stage2a-finalization/v1';
const FIELDS = ['schema', 'reservation_sha256', 'start_id', 'launch_id', 'runner_wrapper_pid', 'finalization_sha256', 'finalization_envelope_base64url', 'bind_receipt_sha256'];
const ENVELOPE = ['schema_version', 'purpose', 'issuer_public_key_base64url', 'payload_sha256', 'payload_base64url', 'signature_base64url'];
const PAYLOAD = ['schema', 'reservation_sha256', 'installation_id', 'start_id', 'launch_id', 'plan_id', 'plan_digest', 'hq_epoch', 'bind_receipt_sha256', 'relay_socket', 'bridge_pid', 'finalized_at'];
const NODE = ['uid', 'gid', 'device', 'inode', 'mode'];
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const MAX_LINE = 32 * 1024;
const exact = (value, fields) => value !== null && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === fields.length && fields.every((field) => Object.hasOwn(value, field));
const digest = (bytes) => 'sha256:' + createHash('sha256').update(bytes).digest('hex');
const bad = (reason) => { throw new Error('protected activation: ' + reason); };

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

export function verifyProtectedActivation(value, start, pin, stat = lstatSync) {
  if (!exact(value, FIELDS) || value.schema !== 'agent-bot-souls/protected-activation/v1'
    || !SHA256.test(value.reservation_sha256) || !SHA256.test(value.finalization_sha256)
    || !SHA256.test(value.bind_receipt_sha256) || value.reservation_sha256 !== start.reservationSha256
    || value.start_id !== start.startId || value.launch_id !== start.launchId
    || !Number.isSafeInteger(value.runner_wrapper_pid) || value.runner_wrapper_pid <= 1) {
    bad('preface differs from the signed start');
  }
  if (!Buffer.isBuffer(pin) || pin.length !== 32) bad('Machine pin is unavailable');
  const envelopeBytes = decode(value.finalization_envelope_base64url);
  if (envelopeBytes.length > 8 * 1024 || digest(envelopeBytes) !== value.finalization_sha256) bad('finalization envelope digest differs');
  const envelope = signedJson(envelopeBytes);
  if (!exact(envelope, ENVELOPE) || envelope.schema_version !== 1 || envelope.purpose !== PURPOSE
    || !SHA256.test(envelope.payload_sha256) || !decode(envelope.issuer_public_key_base64url, 32).equals(pin)) {
    bad('finalization envelope differs from installed Machine authority');
  }
  const payloadBytes = decode(envelope.payload_base64url);
  if (digest(payloadBytes) !== envelope.payload_sha256) bad('finalization payload digest differs');
  const signature = decode(envelope.signature_base64url, 64);
  const key = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), pin]), format: 'der', type: 'spki' });
  if (!verify(null, Buffer.concat([Buffer.from(PURPOSE + '\0'), payloadBytes]), key, signature)) bad('invalid finalization signature');
  const payload = signedJson(payloadBytes);
  if (!exact(payload, PAYLOAD) || payload.schema !== 'agent-bot-machine/stage2a-finalization/v1'
    || payload.reservation_sha256 !== start.reservationSha256
    || payload.installation_id !== start.installationId || payload.start_id !== start.startId
    || payload.launch_id !== start.launchId || payload.plan_id !== start.planId
    || payload.plan_digest !== start.planDigest || payload.hq_epoch !== start.hqEpoch
    || payload.bind_receipt_sha256 !== value.bind_receipt_sha256
    || !Number.isSafeInteger(payload.bridge_pid) || payload.bridge_pid <= 1
    || !exact(payload.relay_socket, ['path', 'socket'])
    || payload.relay_socket.path !== start.brokerSocket || !exact(payload.relay_socket.socket, NODE)) {
    bad('signed B finalization differs from the one-use start');
  }
  const claim = payload.relay_socket.socket;
  let observed;
  try { observed = stat(start.brokerSocket, { bigint: true }); }
  catch { bad('cannot inspect B relay socket'); }
  if (!observed.isSocket() || observed.uid !== BigInt(claim.uid)
    || observed.gid !== BigInt(claim.gid) || observed.dev.toString() !== claim.device
    || observed.ino.toString() !== claim.inode || Number(observed.mode & 0o7777n) !== claim.mode
    || claim.uid !== start.bridgeUid || claim.gid !== start.runnerGid) {
    bad('B relay kernel socket differs from signed finalization');
  }
  return Object.freeze({ relaySocket: start.brokerSocket, bridgePid: payload.bridge_pid,
    runnerWrapperPid: value.runner_wrapper_pid,
    bindReceiptSha256: value.bind_receipt_sha256, finalizationSha256: value.finalization_sha256 });
}

export function checkProtectedActivation(value, start) {
  return verifyProtectedActivation(value, start, readMachinePin());
}

export function readProtectedActivation(input, { timeoutMs = 10_000 } = {}) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let bytes = 0;
    const finish = (error, value) => {
      clearTimeout(timer);
      input.off('data', onData); input.off('end', onEnd); input.off('error', onError);
      input.pause();
      if (error) reject(error); else resolve(value);
    };
    const onEnd = () => finish(new Error('protected activation: EOF before preface'));
    const onError = () => finish(new Error('protected activation: pipe error'));
    const onData = (chunk) => {
      bytes += chunk.length;
      if (bytes > MAX_LINE) return finish(new Error('protected activation: preface exceeds 32 KiB'));
      chunks.push(chunk);
      const raw = Buffer.concat(chunks);
      const newline = raw.indexOf(0x0a);
      if (newline < 0) return;
      if (newline !== raw.length - 1 || newline === 0) return finish(new Error('protected activation: trailing or empty preface'));
      let value;
      try { value = parseStrict(new TextDecoder('utf-8', { fatal: true }).decode(raw.subarray(0, -1))); }
      catch { return finish(new Error('protected activation: invalid UTF-8 JSON preface')); }
      finish(null, value);
    };
    const timer = setTimeout(() => finish(new Error('protected activation: preface timed out')), timeoutMs);
    input.on('data', onData); input.once('end', onEnd); input.once('error', onError);
    input.resume();
  });
}
