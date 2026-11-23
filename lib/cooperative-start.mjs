// Machine passes a purpose-separated, one-use cooperative reservation on fd 3.
// This module authenticates the handoff before any writable Soul state is used.
import { createHash, createPublicKey, verify } from 'node:crypto';
import { closeSync, fstatSync, readSync } from 'node:fs';
import { dirname, isAbsolute, join, parse, resolve } from 'node:path';
import { canonicalize, parseStrict } from './contracts.mjs';
import { MACHINE_PIN, readMachinePin } from './protected-start.mjs';

const PURPOSE = 'agent-bot/soul-cooperative-reservation/v3';
const LAUNCH_PURPOSE = 'agent-bot/stage2a-cooperative-launch-inputs/v3\0';
const FD_FIELDS = ['schema', 'reservation_envelope_base64url', 'reservation_sha256', 'machine_pin_path', 'launch_input_records', 'state_root', 'admission_challenge_base64url'];
const ENVELOPE_FIELDS = ['schema_version', 'purpose', 'issuer_public_key_base64url', 'payload_sha256', 'payload_base64url', 'signature_base64url'];
const PAYLOAD_FIELDS = ['contract', 'kind', 'schema_version', 'host_id', 'issued_at', 'expires_at', 'installed_plan_receipt_sha256', 'assignment', 'endpoints', 'measurement_binding', 'admission_challenge_sha256'];
const SHA = /^sha256:[0-9a-f]{64}$/;
const HEX = /^[0-9a-f]{64}$/;
const START = /^st_[0-9a-f]{24}$/;
const LAUNCH = /^ln_[0-9a-f]{24}$/;
const MAX_BYTES = 2 * 1024 * 1024;
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const exact = (value, fields) => object(value) && Object.keys(value).length === fields.length
  && fields.every((field) => Object.hasOwn(value, field));
const sha = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const absolute = (value) => typeof value === 'string' && !value.includes('\0')
  && isAbsolute(value) && resolve(value) === value && value !== parse(value).root;
const bad = (reason) => { throw new Error(`cooperative start: ${reason}`); };

function base64url(value, length) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) bad('noncanonical base64url');
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.toString('base64url') !== value || (length !== undefined && bytes.length !== length)) bad('noncanonical base64url');
  return bytes;
}

function jcs(bytes) {
  let text, value;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    value = parseStrict(text);
  } catch (error) { bad(`invalid UTF-8 JSON: ${error.message}`); }
  if (canonicalize(value) !== text) bad('JSON is not canonical');
  return value;
}

function endpoint(value, hqUid, runnerUid) {
  return object(value) && absolute(value.directory) && absolute(value.socket_path)
    && dirname(value.socket_path) === value.directory
    && value.owner_uid === hqUid && value.expected_peer_uid === runnerUid
    && value.dir_mode === 0o2750 && value.socket_mode === 0o660
    && Number.isSafeInteger(value.group_gid) && value.group_gid > 0;
}

// The optional identity makes the signed Contracts vector testable without
// assuming that a developer workstation has Machine's synthetic runner UID.
export function verifyCooperativeStart(value, root, pin, now = Date.now(), identity = {
  uid: process.getuid(), euid: process.geteuid(), gid: process.getgid(), egid: process.getegid(),
}) {
  if (!exact(value, FD_FIELDS) || value.schema !== 'agent-bot-souls/cooperative-start/v1'
    || value.machine_pin_path !== MACHINE_PIN || !SHA.test(value.reservation_sha256)
    || !object(value.launch_input_records) || !absolute(root) || !absolute(value.state_root)) bad('invalid fd 3 input fields');
  if (!Buffer.isBuffer(pin) || pin.length !== 32) bad('installed Machine pin is unavailable');
  const envelopeBytes = base64url(value.reservation_envelope_base64url);
  if (sha(envelopeBytes) !== value.reservation_sha256) bad('reservation envelope digest differs');
  const envelope = jcs(envelopeBytes);
  if (!exact(envelope, ENVELOPE_FIELDS) || envelope.schema_version !== 3
    || envelope.purpose !== PURPOSE || !SHA.test(envelope.payload_sha256)) bad('unsupported reservation envelope');
  if (!base64url(envelope.issuer_public_key_base64url, 32).equals(pin)) bad('reservation signer differs from installed pin');
  const payloadBytes = base64url(envelope.payload_base64url);
  if (sha(payloadBytes) !== envelope.payload_sha256) bad('reservation payload digest differs');
  const payload = jcs(payloadBytes);
  const key = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), pin]), format: 'der', type: 'spki' });
  if (!verify(null, Buffer.concat([Buffer.from(PURPOSE + '\0'), payloadBytes]), key,
    base64url(envelope.signature_base64url, 64))) bad('invalid reservation signature');
  const challenge = base64url(value.admission_challenge_base64url, 32);

  const a = payload.assignment;
  const b = payload.measurement_binding;
  const snaps = b?.snapshots;
  const issued = Date.parse(payload.issued_at);
  const expires = Date.parse(payload.expires_at);
  if (!(exact(payload, PAYLOAD_FIELDS) || exact(payload, [...PAYLOAD_FIELDS, 'qualification_provider']))
    || payload.contract !== 'machine/v3'
    || payload.kind !== 'soul-cooperative-reservation' || payload.schema_version !== 3
    || !object(a) || !object(b) || !object(snaps)
    || b.contract !== 'machine/v3' || b.kind !== 'stage2a-measurement-binding'
    || b.schema_version !== 3 || b.profile_in_force !== 'managed-cooperative'
    || !SHA.test(payload.installed_plan_receipt_sha256) || !SHA.test(payload.admission_challenge_sha256)
    || sha(challenge) !== payload.admission_challenge_sha256
    || !Number.isFinite(issued) || !Number.isFinite(expires) || issued > now || expires <= now
    || expires <= issued || expires - issued > 30_000 || a.expires_at !== payload.expires_at
    || !START.test(a.start_id ?? '') || !LAUNCH.test(a.launch_id ?? '')
    || !HEX.test(a.hq_epoch ?? '') || !HEX.test(a.plan_digest ?? '')
    || !HEX.test(a.package_sha256 ?? '') || !HEX.test(a.soul_artifact_sha256 ?? '')
    || !SHA.test(b.definition_measurement ?? '') || !SHA.test(b.launch_input_measurement ?? '')
    || !SHA.test(b.claimed_definition_digest ?? '')
    || a.installation_id !== b.installation_id || a.soul_id !== b.soul_id
    || a.start_id !== b.start_id || a.launch_id !== b.launch_id
    || a.plan_id !== b.plan_id || a.plan_digest !== b.installed_plan_digest
    || a.hq_epoch !== b.hq_epoch || payload.host_id !== b.host_id
    || a.package_sha256 !== b.package_sha256 || a.soul_artifact_sha256 !== b.soul_artifact_sha256
    || a.package_root !== root || snaps.definition?.root_path !== root
    || a.launch_inputs_root !== snaps.launch_inputs?.root_path
    || a.runtime_root !== b.r_inventory?.snapshot?.path
    || a.node_path !== join(a.runtime_root, 'bin', 'node')
    || a.entry_path !== join(a.runtime_root, 'bin', 'agent-bot-souls.mjs')
    || !absolute(a.runtime_root) || !absolute(a.launch_inputs_root)
    || a.runtime_root === root || a.runtime_root === a.launch_inputs_root
    || a.launch_inputs_root === root
    || a.state_root !== value.state_root || a.state_root_mode !== '0700'
    || a.state_root !== join('/private/var', `agent-bot-soul-runner-${a.runner_account}`, 'state')
    || !Number.isSafeInteger(a.machine_uid) || a.machine_uid <= 399
    || a.machine_uid === a.runner_uid || !Number.isSafeInteger(a.runner_uid) || a.runner_uid < 1
    || !Number.isSafeInteger(a.runner_gid) || a.runner_gid < 1
    || a.runner_uid !== identity.uid || a.runner_uid !== identity.euid
    || a.runner_gid !== identity.gid || a.runner_gid !== identity.egid
    || snaps.definition?.owner_uid !== a.machine_uid || snaps.definition?.owner_gid !== a.runner_gid
    || snaps.launch_inputs?.owner_uid !== a.machine_uid || snaps.launch_inputs?.owner_gid !== a.runner_gid
    || b.r_inventory?.reader_uid !== a.runner_uid || b.r_inventory?.reader_gid !== a.runner_gid
    || b.r_inventory?.machine_uid !== a.machine_uid
    || !Array.isArray(b.r_components) || !b.r_components.some((row) =>
      row?.component_id === 'souls' && row.source_repository === 'true-line/agent-bot-souls')
    || !object(payload.endpoints) || !endpoint(payload.endpoints.admission, a.hq_uid, a.runner_uid)
    || !endpoint(payload.endpoints.broker, a.hq_uid, a.runner_uid)
    || payload.endpoints.admission.socket_path === payload.endpoints.broker.socket_path) {
    bad('reservation does not bind this runner, host, frozen inputs and cooperative start');
  }
  const records = value.launch_input_records;
  if (sha(Buffer.concat([Buffer.from(LAUNCH_PURPOSE), Buffer.from(canonicalize(records))]))
    !== b.launch_input_measurement) bad('launch input records differ from signed reservation');
  const expectedArgv = [a.node_path, a.entry_path, 'run', '--soul', root,
    '--admission-socket', payload.endpoints.admission.socket_path,
    '--broker-socket', payload.endpoints.broker.socket_path,
    '--profile', 'managed-cooperative', '--cooperative-start-fd', '3'];
  if (canonicalize(records.argv) !== canonicalize(expectedArgv) || records.selected_command !== a.node_path) {
    bad('fixed cooperative argv differs from signed reservation');
  }
  return Object.freeze({
    definitionRoot: root, stateRoot: value.state_root, stateCustody: 'runner-home-canonical',
    entryLaunch: true, snapshotCustody: 'machine-admin', snapshotOwnerUid: a.machine_uid,
    snapshotGroupGid: a.runner_gid, definitionSnapshot: snaps.definition,
    launchInputSnapshot: snaps.launch_inputs, launchInputRoot: a.launch_inputs_root,
    runtimeRoot: a.runtime_root, rInventory: b.r_inventory, rComponents: b.r_components,
    definitionMeasurement: b.definition_measurement, launchInputMeasurement: b.launch_input_measurement,
    launchInputRecords: records, installationId: a.installation_id, runnerUid: a.runner_uid,
    runnerGid: a.runner_gid, soulId: a.soul_id, claimedDefinitionDigest: b.claimed_definition_digest,
    startId: a.start_id, launchId: a.launch_id, hqEpoch: a.hq_epoch,
    expiresAt: payload.expires_at,
    planId: a.plan_id, planDigest: a.plan_digest, hostId: payload.host_id,
    reservationSha256: value.reservation_sha256,
    admissionSocket: payload.endpoints.admission.socket_path,
    admissionEndpoint: payload.endpoints.admission,
    brokerSocket: payload.endpoints.broker.socket_path,
    brokerEndpoint: payload.endpoints.broker,
    admissionChallengeSha256: payload.admission_challenge_sha256,
    admissionChallengeBase64url: value.admission_challenge_base64url,
  });
}

export function checkCooperativeStart(value, root) {
  return verifyCooperativeStart(value, root, readMachinePin());
}

// Machine may publish the signed start immediately before H binds C. Retry
// only a failed Unix connect, never an attach whose one-use outcome is unknown.
export async function connectCooperativeAdmission(start, connect, {
  signal, now = Date.now, delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  maxWaitMs = 5_000,
} = {}) {
  const expiry = Date.parse(start?.expiresAt);
  if (!absolute(start?.admissionSocket) || !Number.isFinite(expiry)
    || !Number.isSafeInteger(maxWaitMs) || maxWaitMs < 1 || maxWaitMs > 5_000
    || typeof connect !== 'function') bad('signed C endpoint and expiry are required');
  const deadline = Math.min(expiry, now() + maxWaitMs);
  for (;;) {
    signal?.throwIfAborted();
    const remaining = deadline - now();
    if (remaining <= 0) bad('signed C endpoint did not become available before the deadline');
    const controller = new AbortController();
    const abort = () => controller.abort(signal.reason);
    signal?.addEventListener('abort', abort, { once: true });
    const timer = setTimeout(() => controller.abort(new Error('cooperative C connect deadline')), remaining);
    try {
      const hq = await connect(start.admissionSocket, controller.signal);
      if (now() >= expiry || controller.signal.aborted) {
        hq?.destroy?.();
        bad('signed cooperative reservation expired before C attach');
      }
      return hq;
    } catch (error) {
      if (signal?.aborted) throw signal.reason;
      if (controller.signal.aborted) bad('signed C endpoint did not become available before the deadline');
      if (error?.op !== 'connect' || error.transport !== true
        || !/\b(?:ENOENT|ECONNREFUSED)\b/.test(error.message)) throw error;
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
    }
    const wait = Math.min(50, deadline - now());
    if (wait <= 0) bad('signed C endpoint did not become available before the deadline');
    await delay(wait);
  }
}

// The first frame on the signed H admission socket consumes the Machine
// reservation. The same HQ connection must carry the subsequent hq/v1 Hello.
export async function attachCooperative(hq, value, start) {
  if (!hq || typeof hq.request !== 'function' || !start
    || typeof start.admissionChallengeBase64url !== 'string'
    || value?.admission_challenge_base64url !== start.admissionChallengeBase64url
    || !SHA.test(start.reservationSha256)) bad('verified admission handoff is unavailable');
  const result = await hq.request('cooperative.attach.v3', {
    reservation_envelope_base64url: value.reservation_envelope_base64url,
    admission_challenge_base64url: start.admissionChallengeBase64url,
  });
  if (!exact(result, ['schema', 'reservation_sha256', 'start_id', 'launch_id', 'broker_socket_path', 'acp_ticket_base64url'])
    || result.schema !== 'hq/cooperative-attach/v3'
    || result.reservation_sha256 !== start.reservationSha256
    || result.start_id !== start.startId || result.launch_id !== start.launchId
    || result.broker_socket_path !== start.brokerSocket) {
    bad('HQ attach reply differs from the signed Machine reservation');
  }
  base64url(result.acp_ticket_base64url, 32);
  return result;
}

export function readCooperativeStart(fd) {
  if (fd !== 3) bad('requires inherited fd 3');
  let stat;
  try { stat = fstatSync(fd); } catch { bad('fd 3 is unavailable'); }
  if (!stat.isFIFO()) bad('fd 3 must be a pipe');
  const chunks = [];
  let size = 0;
  try {
    for (;;) {
      const chunk = Buffer.allocUnsafe(Math.min(65_536, MAX_BYTES + 1 - size));
      const count = readSync(fd, chunk, 0, chunk.length);
      if (count === 0) break;
      size += count;
      if (size > MAX_BYTES) bad('fd 3 exceeds 2 MiB');
      chunks.push(chunk.subarray(0, count));
    }
  } catch (error) {
    if (error?.message?.startsWith('cooperative start:')) throw error;
    bad(`fd 3 read failed: ${error.code ?? error.message}`);
  } finally { closeSync(fd); }
  if (size === 0) bad('fd 3 is empty');
  return jcs(Buffer.concat(chunks));
}
