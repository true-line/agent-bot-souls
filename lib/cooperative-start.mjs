// Machine passes a purpose-separated, one-use cooperative reservation on fd 3.
// This module authenticates the handoff before any writable Soul state is used.
import { createHash, createPublicKey, verify } from 'node:crypto';
import { closeSync, fstatSync, lstatSync, readSync, realpathSync } from 'node:fs';
import { dirname, isAbsolute, join, parse, resolve } from 'node:path';
import { canonicalize, parseStrict } from './contracts.mjs';
import { MACHINE_PIN, readMachinePin } from './protected-start.mjs';

const PURPOSE = 'agent-bot/soul-cooperative-reservation/v3';
const PUBLISH_OUTCOME_PURPOSE = 'agent-bot/soul-cooperative-publish-outcome/v3';
const LAUNCH_PURPOSE = 'agent-bot/stage2a-cooperative-launch-inputs/v3\0';
const FD_FIELDS = ['schema', 'reservation_envelope_base64url', 'reservation_sha256', 'machine_pin_path', 'launch_input_records', 'state_root', 'admission_challenge_base64url'];
const B_FD_FIELDS = [...FD_FIELDS, 'member_socket_path', 'relay_socket_path',
  'publish_outcome_envelope_base64url', 'request_identity'];
const ENVELOPE_FIELDS = ['schema_version', 'purpose', 'issuer_public_key_base64url', 'payload_sha256', 'payload_base64url', 'signature_base64url'];
const PAYLOAD_FIELDS = ['contract', 'kind', 'schema_version', 'host_id', 'issued_at', 'expires_at', 'installed_plan_receipt_sha256', 'assignment', 'adapter_transport', 'endpoints', 'measurement_binding', 'admission_challenge_sha256'];
const ENDPOINT_FIELDS = ['directory', 'socket_path', 'owner_uid', 'group_gid', 'dir_mode', 'socket_mode', 'expected_peer_uid'];
const PARENT_FIELDS = ['parent_device', 'parent_inode', 'parent_birthtime_ns'];
const RELAY_IDENTITY_FIELDS = ['path', 'uid', 'gid', 'mode', 'device', 'inode', 'birthtime_ns'];
const PUBLISH_OUTCOME_FIELDS = ['contract', 'kind', 'schema_version', 'reservation_sha256',
  'bridge_assignment_sha256', 'order_sha256', 'request_sha256', 'request_device',
  'request_inode', 'request_birthtime_ns', 'installation_id', 'start_id',
  'launch_id', 'published_at', 'expires_at', 'publication_mode'];
const REQUEST_IDENTITY_FIELDS = ['device', 'inode', 'birthtime_ns', 'owner_uid', 'group_gid', 'mode'];
const SHA = /^sha256:[0-9a-f]{64}$/;
const HEX = /^[0-9a-f]{64}$/;
const START = /^st_[0-9a-f]{24}$/;
const LAUNCH = /^ln_[0-9a-f]{24}$/;
const POSITIVE_DECIMAL = /^[1-9][0-9]{0,19}$/;
const HQ_IPC_BASE = '/Library/Application Support/ai.true-line.agent-bot-hq';
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

function endpoint(value, ownerUid, peerUid, { parent = false, groupGid } = {}) {
  return exact(value, parent ? [...ENDPOINT_FIELDS, ...PARENT_FIELDS] : ENDPOINT_FIELDS)
    && absolute(value.directory) && absolute(value.socket_path)
    && Buffer.byteLength(value.socket_path) <= 103
    && dirname(value.socket_path) === value.directory
    && value.owner_uid === ownerUid && value.expected_peer_uid === peerUid
    && value.dir_mode === 0o2750 && value.socket_mode === 0o660
    && Number.isSafeInteger(value.group_gid) && value.group_gid > 0
    && (groupGid === undefined || value.group_gid === groupGid)
    && (!parent || PARENT_FIELDS.every((field) => POSITIVE_DECIMAL.test(value[field] ?? '')));
}

function assignedBPaths(endpoints, installationId, startId) {
  const slot = (domain, ...values) => sha(Buffer.from([domain, ...values].join('\0'))).slice(7, 27);
  const install = slot('agent-bot-soul-endpoint-installation/v1', installationId);
  const leaf = `${slot('agent-bot-soul-endpoint-start/v1', installationId, startId)}.sock`;
  return endpoints.admission?.directory === join(HQ_IPC_BASE, 'r', install)
    && endpoints.admission?.socket_path === join(HQ_IPC_BASE, 'r', install, leaf)
    && endpoints.member?.directory === join(HQ_IPC_BASE, 'm', install)
    && endpoints.member?.socket_path === join(HQ_IPC_BASE, 'm', install, leaf)
    && endpoints.relay?.directory === join(HQ_IPC_BASE, 's', install)
    && endpoints.relay?.socket_path === join(HQ_IPC_BASE, 's', install, leaf);
}

function assignedEndpoints(payload, assignment, value, brokeredB) {
  const e = payload.endpoints;
  if (!object(e) || !endpoint(e.admission, assignment.hq_uid, assignment.runner_uid,
    { groupGid: assignment.runner_gid })) return false;
  if (!brokeredB) {
    return Object.keys(e).sort().join(',') === 'admission,broker'
      && endpoint(e.broker, assignment.hq_uid, assignment.runner_uid,
        { groupGid: assignment.runner_gid })
      && e.admission.socket_path !== e.broker.socket_path;
  }
  const bridgeUid = e.member?.expected_peer_uid;
  return Object.keys(e).sort().join(',') === 'admission,member,relay'
    && SHA.test(payload.bridge_launch_sha256 ?? '')
    && Number.isSafeInteger(bridgeUid) && bridgeUid >= 300 && bridgeUid <= 399
    && ![assignment.runner_uid, assignment.hq_uid, assignment.machine_uid].includes(bridgeUid)
    && endpoint(e.member, assignment.runner_uid, bridgeUid,
      { parent: true, groupGid: bridgeUid })
    && endpoint(e.relay, bridgeUid, assignment.runner_uid,
      { parent: true, groupGid: assignment.runner_gid })
    && assignedBPaths(e, assignment.installation_id, assignment.start_id)
    && value.member_socket_path === e.member.socket_path
    && value.relay_socket_path === e.relay.socket_path;
}

// The optional identity makes the signed Contracts vector testable without
// assuming that a developer workstation has Machine's synthetic runner UID.
export function verifyCooperativeStart(value, root, pin, now = Date.now(), identity = {
  uid: process.getuid(), euid: process.geteuid(), gid: process.getgid(), egid: process.getegid(),
}) {
  const brokeredB = value?.schema === 'agent-bot-souls/cooperative-start/v2';
  if (!(brokeredB ? exact(value, B_FD_FIELDS) : exact(value, FD_FIELDS))
    || (!brokeredB && value.schema !== 'agent-bot-souls/cooperative-start/v1')
    || value.machine_pin_path !== MACHINE_PIN || !SHA.test(value.reservation_sha256)
    || !object(value.launch_input_records) || !absolute(root) || !absolute(value.state_root)
    || (brokeredB && (!exact(value.request_identity, REQUEST_IDENTITY_FIELDS)
      || !['device', 'inode', 'birthtime_ns'].every((field) =>
        POSITIVE_DECIMAL.test(value.request_identity[field] ?? ''))
      || value.request_identity.mode !== 0o640))) bad('invalid fd 3 input fields');
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
  const payloadFields = brokeredB ? [...PAYLOAD_FIELDS, 'bridge_launch_sha256'] : PAYLOAD_FIELDS;
  if (!(exact(payload, payloadFields) || exact(payload, [...payloadFields, 'qualification_provider']))
    || payload.contract !== 'machine/v3'
    || payload.kind !== 'soul-cooperative-reservation' || payload.schema_version !== 3
    || payload.adapter_transport !== (brokeredB ? 'brokered-b' : 'direct-comms')
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
    || (brokeredB && (value.request_identity.owner_uid !== a.machine_uid
      || value.request_identity.group_gid !== a.runner_gid))
    || snaps.definition?.owner_uid !== a.machine_uid || snaps.definition?.owner_gid !== a.runner_gid
    || snaps.launch_inputs?.owner_uid !== a.machine_uid || snaps.launch_inputs?.owner_gid !== a.runner_gid
    || b.r_inventory?.reader_uid !== a.runner_uid || b.r_inventory?.reader_gid !== a.runner_gid
    || b.r_inventory?.machine_uid !== a.machine_uid
    || !Array.isArray(b.r_components) || !b.r_components.some((row) =>
      row?.component_id === 'souls' && row.source_repository === 'true-line/agent-bot-souls')
    || !assignedEndpoints(payload, a, value, brokeredB)) {
    bad('reservation does not bind this runner, host, frozen inputs and cooperative start');
  }
  const records = value.launch_input_records;
  if (records.adapter_transport !== payload.adapter_transport
    || (brokeredB ? records.bridge_launch_sha256 !== payload.bridge_launch_sha256
      : Object.hasOwn(records, 'bridge_launch_sha256'))) {
    bad('adapter transport differs from the signed reservation');
  }
  if (sha(Buffer.concat([Buffer.from(LAUNCH_PURPOSE), Buffer.from(canonicalize(records))]))
    !== b.launch_input_measurement) bad('launch input records differ from signed reservation');
  const expectedArgv = [a.node_path, a.entry_path, 'run', '--soul', root,
    '--admission-socket', payload.endpoints.admission.socket_path,
    ...(brokeredB ? ['--member-socket', payload.endpoints.member.socket_path,
      '--relay-socket', payload.endpoints.relay.socket_path]
      : ['--broker-socket', payload.endpoints.broker.socket_path]),
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
    adapterTransport: payload.adapter_transport,
    ...(brokeredB ? { memberSocket: payload.endpoints.member.socket_path,
      memberEndpoint: payload.endpoints.member, relaySocket: payload.endpoints.relay.socket_path,
      relayEndpoint: payload.endpoints.relay, bridgeLaunchSha256: payload.bridge_launch_sha256 }
      : { brokerSocket: payload.endpoints.broker.socket_path,
        brokerEndpoint: payload.endpoints.broker }),
    admissionChallengeSha256: payload.admission_challenge_sha256,
    admissionChallengeBase64url: value.admission_challenge_base64url,
  });
}

export function checkCooperativeStart(value, root) {
  return verifyCooperativeStart(value, root, readMachinePin());
}

// A's signed parent identities are checked again in R before writable state
// or a member socket is opened. B's live relay inode is a later H observation.
export function verifyCooperativeBParents(start) {
  if (start?.adapterTransport !== 'brokered-b') return;
  for (const endpoint of [start.memberEndpoint, start.relayEndpoint]) {
    let stat;
    try { stat = lstatSync(endpoint.directory, { bigint: true }); }
    catch { bad('assigned B endpoint parent is unavailable'); }
    if (!stat.isDirectory() || realpathSync(endpoint.directory) !== endpoint.directory
      || stat.uid !== BigInt(endpoint.owner_uid) || stat.gid !== BigInt(endpoint.group_gid)
      || (stat.mode & 0o7777n) !== 0o2750n
      || stat.dev.toString() !== endpoint.parent_device
      || stat.ino.toString() !== endpoint.parent_inode
      || stat.birthtimeNs.toString() !== endpoint.parent_birthtime_ns) {
      bad('assigned B endpoint parent differs from Machine measurement');
    }
  }
}

// A per-start B member path is never a stale local Soul socket. R may bind
// only the signed vacant leaf; it must not unlink a node left by another
// process or a failed prior attempt in A's assigned parent.
export function verifyCooperativeBMemberPath(start, stat = lstatSync) {
  if (start?.adapterTransport !== 'brokered-b'
    || start.memberSocket !== start.memberEndpoint?.socket_path
    || !absolute(start.memberSocket)) bad('signed B member socket is unavailable');
  let existing;
  try { existing = stat(start.memberSocket, { throwIfNoEntry: false }); }
  catch { bad('signed B member socket cannot be inspected'); }
  if (existing) bad('signed B member socket path is occupied');
  return start.memberSocket;
}

// The live socket identity must first come from an authenticated H/A B
// finalization. R then compares it with the signed endpoint and the kernel
// pathname immediately before using the relay. This check alone cannot
// authenticate H's reply or prove that B owns the listening descriptor.
export function verifyCooperativeBRelaySocket(start, identity) {
  if (start?.adapterTransport !== 'brokered-b' || !exact(identity, RELAY_IDENTITY_FIELDS)) {
    bad('authenticated B relay identity is unavailable');
  }
  const endpoint = start.relayEndpoint;
  if (identity.path !== start.relaySocket || identity.path !== endpoint?.socket_path
    || identity.uid !== endpoint.owner_uid || identity.gid !== endpoint.group_gid
    || identity.mode !== endpoint.socket_mode
    || ![identity.device, identity.inode, identity.birthtime_ns].every((value) => POSITIVE_DECIMAL.test(value ?? ''))) {
    bad('B relay identity differs from the signed endpoint');
  }
  verifyCooperativeBParents(start);
  let observed;
  try { observed = lstatSync(identity.path, { bigint: true }); }
  catch { bad('B relay socket is unavailable'); }
  if (!observed.isSocket() || observed.uid !== BigInt(identity.uid)
    || observed.gid !== BigInt(identity.gid)
    || (observed.mode & 0o7777n) !== BigInt(identity.mode)
    || observed.dev.toString() !== identity.device
    || observed.ino.toString() !== identity.inode
    || observed.birthtimeNs.toString() !== identity.birthtime_ns) {
    bad('B relay socket differs from authenticated identity');
  }
  return identity.path;
}

// Machine's dispatcher observes the already-open watched request inode and
// waits on that FD for A's separate post-publication outcome. The caller must
// supply that observed identity and the exact canonical request bytes; a path
// lookup here could silently switch to a replacement inode. This verifies the
// outcome before any B attach, but does not grant B admission by itself.
export function verifyCooperativeBPublishOutcome(value, start, pin, now = Date.now()) {
  const requestIdentity = value?.request_identity;
  if (start?.adapterTransport !== 'brokered-b'
    || !exact(value, B_FD_FIELDS) || value.schema !== 'agent-bot-souls/cooperative-start/v2'
    || !exact(requestIdentity, REQUEST_IDENTITY_FIELDS)
    || !['device', 'inode', 'birthtime_ns'].every((field) => POSITIVE_DECIMAL.test(requestIdentity[field] ?? ''))
    || requestIdentity.owner_uid !== start.snapshotOwnerUid
    || requestIdentity.group_gid !== start.runnerGid || requestIdentity.mode !== 0o640
    || !Buffer.isBuffer(pin) || pin.length !== 32) {
    bad('observed B publication handoff is unavailable');
  }
  const request = Object.fromEntries(FD_FIELDS.map((field) => [field,
    field === 'schema' ? 'agent-bot-souls/cooperative-start/v1' : value[field]]));
  const requestBytes = Buffer.from(canonicalize(request));
  const envelopeBytes = base64url(value.publish_outcome_envelope_base64url);
  if (envelopeBytes.length > 8192) bad('B publish outcome exceeds 8192 bytes');
  const envelope = jcs(envelopeBytes);
  if (!exact(envelope, ENVELOPE_FIELDS) || envelope.schema_version !== 3
    || envelope.purpose !== PUBLISH_OUTCOME_PURPOSE
    || !SHA.test(envelope.payload_sha256)) bad('unsupported B publish outcome envelope');
  if (!base64url(envelope.issuer_public_key_base64url, 32).equals(pin)) {
    bad('B publish outcome signer differs from installed pin');
  }
  const payloadBytes = base64url(envelope.payload_base64url);
  if (sha(payloadBytes) !== envelope.payload_sha256) bad('B publish outcome payload digest differs');
  const payload = jcs(payloadBytes);
  const key = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), pin]), format: 'der', type: 'spki' });
  if (!verify(null, Buffer.concat([Buffer.from(PUBLISH_OUTCOME_PURPOSE + '\0'), payloadBytes]), key,
    base64url(envelope.signature_base64url, 64))) bad('invalid B publish outcome signature');
  const published = Date.parse(payload.published_at);
  const expires = Date.parse(payload.expires_at);
  const reservationExpires = Date.parse(start.expiresAt);
  if (!exact(payload, PUBLISH_OUTCOME_FIELDS)
    || payload.contract !== 'machine/v3'
    || payload.kind !== 'soul-cooperative-publish-outcome'
    || payload.schema_version !== 3
    || !SHA.test(payload.bridge_assignment_sha256 ?? '')
    || !SHA.test(payload.order_sha256 ?? '')
    || payload.reservation_sha256 !== start.reservationSha256
    || payload.request_sha256 !== sha(requestBytes)
    || payload.request_device !== requestIdentity.device
    || payload.request_inode !== requestIdentity.inode
    || payload.request_birthtime_ns !== requestIdentity.birthtime_ns
    || payload.installation_id !== start.installationId
    || payload.start_id !== start.startId || payload.launch_id !== start.launchId
    || payload.publication_mode !== 'direct'
    || !Number.isFinite(published) || !Number.isFinite(expires)
    || !Number.isFinite(reservationExpires) || published > now
    || expires <= now || published >= expires || expires > reservationExpires) {
    bad('B publish outcome differs from the observed request and signed start');
  }
  return Object.freeze(payload);
}

export function checkCooperativeBPublishOutcome(value, start) {
  return verifyCooperativeBPublishOutcome(value, start, readMachinePin());
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
  if (start?.adapterTransport === 'brokered-b') {
    bad('B attach and live bridge bind are not available');
  }
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
