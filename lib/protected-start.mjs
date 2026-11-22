// Machine's fixed R launcher passes a signed, one-use reservation on fd 3.
// HQ independently verifies the live start and finalizes admission.
import { createHash, createPublicKey, verify } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync, readSync } from 'node:fs';
import { dirname, isAbsolute, join, parse, resolve } from 'node:path';
import { canonicalize, parseStrict } from './contracts.mjs';

export const MACHINE_PIN = '/Library/Application Support/ai.true-line.agent-bot-hq/soul-authority.pub';
const FD_FIELDS = ['schema', 'reservation_envelope_base64url', 'reservation_sha256', 'machine_pin_path', 'launch_input_records', 'state_root'];
const ENVELOPE_FIELDS = ['schema_version', 'purpose', 'issuer_public_key_base64url', 'payload_sha256', 'payload_base64url', 'signature_base64url'];
const PURPOSE = 'agent-bot/stage2a-reservation/v2';
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const BARE_SHA256 = /^[0-9a-f]{64}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const START_ID = /^st_[0-9a-f]{24}$/;
const LAUNCH_ID = /^ln_[0-9a-f]{24}$/;
const MAX_BYTES = 64 * 1024;
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const exact = (value, fields) => object(value) && Object.keys(value).length === fields.length
  && fields.every((field) => Object.hasOwn(value, field));
const digest = (bytes) => 'sha256:' + createHash('sha256').update(bytes).digest('hex');
const absolute = (value) => typeof value === 'string' && !value.includes('\0')
  && isAbsolute(value) && resolve(value) === value && value !== parse(value).root;
const bad = (message) => { throw new Error('protected start: ' + message); };

function base64url(value, length) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) bad('noncanonical base64url');
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.toString('base64url') !== value || (length !== undefined && bytes.length !== length)) bad('noncanonical base64url');
  return bytes;
}

function canonicalJson(bytes) {
  let value, text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    value = parseStrict(text);
  } catch (error) { bad('invalid UTF-8 JSON: ' + error.message); }
  if (canonicalize(value) !== text) bad('signed JSON is not canonical');
  return value;
}

function checkedAcl(path) {
  if (process.platform !== 'darwin') return;
  const result = spawnSync('/bin/ls', ['-lde', path], { encoding: 'utf8', maxBuffer: 16384 });
  if (result.error || result.status !== 0) bad('cannot inspect pin ACL at ' + path);
  const lines = result.stdout.trimEnd().split('\n');
  if (!/^[-bcdlps][rwxStTs-]{9}[+@ ]/.test(lines[0] ?? '')) bad('cannot parse pin ACL at ' + path);
  if (lines.length === 1 && lines[0][10] !== '+') return;
  if (lines.length < 2 || lines.slice(1).some((line) => !/^\s*\d+:\s+.+\sdeny\s+/.test(line))) {
    bad('pin ACL may grant another account access at ' + path);
  }
}

export function readMachinePin() {
  if (constants.O_NOFOLLOW === undefined) bad('no-follow pin access is unavailable');
  const ancestors = [];
  for (let path = dirname(MACHINE_PIN); ; path = dirname(path)) {
    ancestors.push(path);
    if (path === parse(path).root) break;
  }
  for (const path of ancestors.reverse()) {
    const stat = lstatSync(path);
    if (!stat.isDirectory() || stat.uid !== 0 || (stat.mode & 0o022)) bad('unsafe Machine pin ancestor ' + path);
    checkedAcl(path);
  }
  const stat = lstatSync(MACHINE_PIN);
  if (!stat.isFile() || stat.uid !== 0 || stat.gid !== 0 || (stat.mode & 0o7777) !== 0o444
    || stat.nlink !== 1 || stat.size !== 32) bad('Machine pin is not root:wheel 0444 raw Ed25519 key');
  checkedAcl(MACHINE_PIN);
  let fd;
  try {
    fd = openSync(MACHINE_PIN, constants.O_RDONLY | constants.O_NOFOLLOW);
    const opened = fstatSync(fd);
    if (!opened.isFile() || opened.dev !== stat.dev || opened.ino !== stat.ino || opened.uid !== 0
      || opened.gid !== 0 || (opened.mode & 0o7777) !== 0o444 || opened.nlink !== 1 || opened.size !== 32) {
      bad('Machine pin changed while opening');
    }
    const bytes = readFileSync(fd);
    if (bytes.length !== 32) bad('Machine pin changed while reading');
    return bytes;
  } finally { if (fd !== undefined) closeSync(fd); }
}

// Supplying a pin is useful for signed fixture tests. The runtime entry always
// calls checkProtectedStart, which reads the fixed installed pin itself.
export function verifyProtectedStart(value, root, pin, now = Date.now()) {
  if (!exact(value, FD_FIELDS) || value.schema !== 'agent-bot-souls/protected-start/v1'
    || value.machine_pin_path !== MACHINE_PIN || !SHA256.test(value.reservation_sha256)
    || !object(value.launch_input_records) || !absolute(root) || !absolute(value.state_root)) {
    bad('invalid fd 3 input fields');
  }
  if (!Buffer.isBuffer(pin) || pin.length !== 32) bad('installed Machine pin is unavailable');
  const envelopeBytes = base64url(value.reservation_envelope_base64url);
  if (digest(envelopeBytes) !== value.reservation_sha256) bad('reservation envelope digest differs');
  const envelope = canonicalJson(envelopeBytes);
  if (!exact(envelope, ENVELOPE_FIELDS) || envelope.schema_version !== 2 || envelope.purpose !== PURPOSE
    || !SHA256.test(envelope.payload_sha256)) bad('unsupported reservation envelope');
  if (!base64url(envelope.issuer_public_key_base64url, 32).equals(pin)) bad('reservation signer differs from installed pin');
  const payloadBytes = base64url(envelope.payload_base64url);
  if (digest(payloadBytes) !== envelope.payload_sha256) bad('reservation payload digest differs');
  const payload = canonicalJson(payloadBytes);
  const signature = base64url(envelope.signature_base64url, 64);
  const key = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), pin]), format: 'der', type: 'spki' });
  if (!verify(null, Buffer.concat([Buffer.from(PURPOSE + '\0'), payloadBytes]), key, signature)) bad('invalid reservation signature');

  const assignment = payload?.assignment;
  const binding = payload?.measurement_binding;
  const snapshots = binding?.snapshots;
  const issued = Date.parse(payload?.issued_at);
  const expires = Date.parse(payload?.expires_at);
  if (payload?.contract !== 'machine/v2' || payload?.kind !== 'stage2a-reservation' || payload?.schema_version !== 2
    || !object(assignment) || assignment.schema !== 'agent-bot-machine/soul-start-assignment/v2'
    || !object(binding) || binding.contract !== 'machine/v2' || binding.kind !== 'stage2a-measurement-binding'
    || binding.schema_version !== 2 || binding.profile_in_force !== 'managed-protected'
    || !object(snapshots) || !object(snapshots.definition) || !object(snapshots.launch_inputs)
    || !absolute(snapshots.definition.root_path) || !absolute(snapshots.launch_inputs.root_path)
    || snapshots.definition.root_path !== root || !absolute(assignment.package_root)
    || !ID.test(binding.installation_id ?? '') || assignment.installation_id !== binding.installation_id
    || assignment.soul_id !== binding.soul_id || !START_ID.test(binding.start_id ?? '')
    || assignment.start_id !== binding.start_id || !LAUNCH_ID.test(binding.launch_id ?? '')
    || assignment.launch_id !== binding.launch_id || !/^[0-9a-f]{64}$/.test(binding.hq_epoch ?? '')
    || assignment.hq_epoch !== binding.hq_epoch || payload.host_id !== binding.host_id
    || assignment.plan_id !== binding.plan_id
    || binding.installed_plan_digest !== assignment.plan_digest
    || assignment.package_sha256 !== binding.package_sha256
    || assignment.soul_artifact_sha256 !== binding.soul_artifact_sha256
    || !SHA256.test(binding.definition_measurement ?? '') || !SHA256.test(binding.launch_input_measurement ?? '')
    || !SHA256.test(binding.claimed_definition_digest ?? '')
    || !BARE_SHA256.test(binding.soul_artifact_sha256 ?? '')
    || !Number.isSafeInteger(assignment.machine_uid) || assignment.machine_uid <= 399
    || assignment.machine_uid === assignment.runner_uid
    || !Number.isSafeInteger(assignment.runner_gid) || assignment.runner_gid < 1
    || assignment.runner_gid !== process.getgid() || assignment.runner_gid !== process.getegid()
    || snapshots.definition.owner_uid !== assignment.machine_uid
    || snapshots.launch_inputs.owner_uid !== assignment.machine_uid
    || snapshots.definition.owner_gid !== assignment.runner_gid
    || snapshots.launch_inputs.owner_gid !== assignment.runner_gid
    || !Number.isSafeInteger(assignment.runner_uid) || assignment.runner_uid !== process.getuid()
    || process.geteuid() !== assignment.runner_uid
    || !Number.isFinite(issued) || !Number.isFinite(expires) || issued > now || expires <= now
    || expires <= issued || expires - issued > 30_000 || assignment.expires_at !== payload.expires_at
    || !absolute(assignment.admission?.socket_path) || !absolute(assignment.relay?.socket_path)
    || assignment.admission.socket_path === assignment.relay.socket_path
    || payload.member_endpoint?.member_socket !== assignment.member?.socket_path
    || !object(payload.member_endpoint?.member_endpoint)
    || payload.member_endpoint.member_endpoint.directory !== assignment.member?.directory
    || payload.member_endpoint.member_endpoint.owner_uid !== assignment.member?.owner_uid
    || payload.member_endpoint.member_endpoint.group_gid !== assignment.member?.group_gid
    || payload.member_endpoint.member_endpoint.dir_mode !== assignment.member?.dir_mode
    || payload.member_endpoint.member_endpoint.socket_mode !== assignment.member?.socket_mode
    || !Array.isArray(payload.member_endpoint.member_endpoint.peer_uids)
    || !Array.isArray(assignment.member?.peer_uids)
    || canonicalize(payload.member_endpoint.member_endpoint.peer_uids) !== canonicalize(assignment.member?.peer_uids)
    || assignment.runner_account !== '_abm-sr-' + createHash('sha256').update(binding.installation_id).digest('hex').slice(0, 20)
    || value.state_root !== join('/var', 'agent-bot-soul-runner-' + assignment.runner_account, 'state')) {
    bad('reservation does not bind this live runner, definition and protected start');
  }
  const launchMeasurement = digest(Buffer.concat([
    Buffer.from('agent-bot/stage2a-launch-inputs/v1\0'),
    Buffer.from(canonicalize(value.launch_input_records)),
  ]));
  if (launchMeasurement !== binding.launch_input_measurement) bad('launch input records differ from signed reservation');
  return Object.freeze({
    definitionRoot: root, stateRoot: value.state_root, stateCustody: 'runner-home', entryLaunch: true,
    snapshotCustody: 'machine-admin', snapshotOwnerUid: assignment.machine_uid,
    snapshotGroupGid: assignment.runner_gid,
    definitionSnapshot: snapshots.definition, launchInputSnapshot: snapshots.launch_inputs,
    launchInputRoot: snapshots.launch_inputs.root_path,
    definitionMeasurement: binding.definition_measurement,
    launchInputMeasurement: binding.launch_input_measurement,
    launchInputRecords: value.launch_input_records,
    installationId: binding.installation_id, runnerUid: assignment.runner_uid,
    soulId: binding.soul_id, claimedDefinitionDigest: binding.claimed_definition_digest,
    startId: binding.start_id, launchId: binding.launch_id, hqEpoch: binding.hq_epoch,
    planId: assignment.plan_id, planDigest: assignment.plan_digest,
    bridgeUid: assignment.bridge_uid, bridgeGid: assignment.bridge_gid, runnerGid: assignment.runner_gid,
    reservationSha256: value.reservation_sha256,
    admissionSocket: assignment.admission.socket_path, admissionEndpoint: assignment.admission,
    brokerSocket: assignment.relay.socket_path,
    memberEndpoint: payload.member_endpoint,
  });
}

export function checkProtectedStart(value, root) {
  if (!exact(value, FD_FIELDS) || value.schema !== 'agent-bot-souls/protected-start/v1'
    || value.machine_pin_path !== MACHINE_PIN || !absolute(root)) bad('invalid fd 3 input fields');
  return verifyProtectedStart(value, root, readMachinePin());
}

export function readProtectedStart(fd, root) {
  if (fd !== 3) bad('requires inherited fd 3');
  let stat;
  try { stat = fstatSync(fd); } catch { bad('fd 3 is unavailable'); }
  if (!stat.isFIFO()) bad('fd 3 must be a pipe');
  const chunks = [];
  let size = 0;
  try {
    for (;;) {
      const chunk = Buffer.allocUnsafe(Math.min(65536, MAX_BYTES + 1 - size));
      const count = readSync(fd, chunk, 0, chunk.length);
      if (count === 0) break;
      size += count;
      if (size > MAX_BYTES) bad('fd 3 exceeds 64 KiB');
      chunks.push(chunk.subarray(0, count));
    }
  } finally { closeSync(fd); }
  if (size === 0) bad('fd 3 is empty');
  let value;
  try { value = parseStrict(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks))); }
  catch (error) { bad('fd 3 is invalid UTF-8 JSON: ' + error.message); }
  return value;
}
