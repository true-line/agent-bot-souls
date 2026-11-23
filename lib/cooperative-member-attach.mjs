// R independently checks the A-signed cooperative Ready, the A-observed B
// socket, and the exact B-to-H arm objects before accepting an H attach.
import { createHash, createPublicKey, verify } from 'node:crypto';
import { dirname, isAbsolute, parse, resolve } from 'node:path';
import { canonicalize, parseStrict } from './contracts.mjs';
import { verifyCooperativeBRelaySocket } from './cooperative-start.mjs';

const FIELDS = ['version', 'installation_id', 'start_id', 'member_id', 'member_selector',
  'runtime_id', 'launch_id', 'attach', 'expires_at', 'cwd', 'member_socket',
  'member_endpoint', 'member_bridge_token', 'bridge_ready_nonce', 'runner_endpoint',
  'child_observation_envelope_base64url', 'child_observation_envelope_sha256',
  'member_b_authority_envelope_base64url', 'member_b_authority_envelope_sha256',
  'ready_envelope_base64url', 'ready_envelope_sha256',
  'bridge_observed_envelope_base64url', 'bridge_arm_rows_base64url'];
const ENVELOPE = ['schema_version', 'purpose', 'issuer_public_key_base64url',
  'payload_sha256', 'payload_base64url', 'signature_base64url'];
const IDENTITY = ['profile_in_force', 'host_id', 'installation_id', 'soul_id',
  'start_id', 'hq_epoch'];
const CHILD = ['contract', 'kind', 'schema_version', ...IDENTITY, 'reservation_sha256',
  'assignment_envelope_sha256', 'provisional_hq_mapping_sha256',
  'provisional_hq_mapping', 'members', 'observed_at', 'issued_at', 'expires_at'];
const POLICY = ['contract', 'kind', 'schema_version', ...IDENTITY, 'plan_id',
  'plan_digest', 'reservation_sha256', 'member_set_assignment_envelope_sha256',
  'owner_plan_member_set_sha256', 'b_authority', 'hq_uid', 'runner_uid', 'bridge',
  'members', 'issued_at', 'expires_at'];
const READY = ['contract', 'kind', 'schema_version', 'profile_in_force', 'host_id',
  'installation_id', 'start_id', 'hq_epoch', 'reservation_sha256',
  'assignment_envelope_sha256', 'child_observation_envelope_sha256',
  'provisional_hq_mapping_sha256', 'member_b_authority_envelope_sha256',
  'bridge_observed_sha256', 'members', 'issued_at', 'expires_at'];
const OBSERVED_B = ['contract', 'kind', 'schema_version', 'reservation_sha256',
  'bridge_assignment_sha256', 'bind_receipt_sha256', 'installation_id', 'start_id',
  'launch_id', 'plan_id', 'plan_digest', 'hq_epoch', 'grant_nonce', 'launcher',
  'bridge', 'relay_socket', 'relay_socket_birthtime_ns', 'observed_at', 'expires_at'];
const MAP = ['contract', 'kind', 'schema_version', ...IDENTITY,
  'assignment_envelope_sha256', 'runtime_state', 'acp_authority', 'members',
  'issued_at', 'expires_at'];
const CHILD_MEMBER = ['member_id', 'launch_id', 'member_selector', 'runtime_id',
  'grant_sha256', 'launcher_process', 'child_process'];
const POLICY_MEMBER = ['member_id', 'launch_id', 'member_selector', 'adjacent_cli_path',
  'adjacent_cli_sha256', 'qualification'];
const READY_MEMBER = ['member_id', 'member_launch_id', 'member_selector',
  'grant_sha256', 'launcher_process', 'child_process', 'h_observation_sha256',
  'b_arm_receipt_sha256'];
const PROCESS = ['pid', 'uid', 'gid', 'start_seconds', 'start_micros'];
const CHILD_PROCESS = ['pid', 'uid', 'gid', 'parent_pid', 'process_group_id',
  'start_seconds', 'start_micros', 'executable_sha256'];
const ARM = ['member_id', 'member_selector', 'runtime_id',
  'child_observation_envelope_sha256', 'bridge_uid', 'adapter_pid', 'adapter_uid',
  'adapter_gid', 'adapter_start_seconds', 'adapter_start_micros', 'relay_peer_rule',
  'relay_peer_state', 'provider_ingress', 'state', 'armed_at'];
const QUALIFICATION = ['model', 'request_sha256', 'headers_sha256',
  'client_key_sha256', 'http_host', 'messages_query', 'response_text'];
const SHA = /^sha256:[0-9a-f]{64}$/;
const HEX = /^[0-9a-f]{64}$/;
const POSITIVE = /^[1-9][0-9]*$/;
const bad = (reason) => { throw new Error(`cooperative member attach: ${reason}`); };
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const exact = (value, fields) => object(value) && Object.keys(value).length === fields.length
  && fields.every((field) => Object.hasOwn(value, field));
const sha = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const same = (a, b) => canonicalize(a) === canonicalize(b);
const absolute = (value) => typeof value === 'string' && !value.includes('\0')
  && isAbsolute(value) && resolve(value) === value && value !== parse(value).root;

function decode(value, length) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) bad('noncanonical base64url');
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.toString('base64url') !== value || (length !== undefined && bytes.length !== length)) {
    bad('noncanonical base64url');
  }
  return bytes;
}

function jcs(bytes) {
  let text, value;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); value = parseStrict(text); }
  catch { return bad('invalid canonical JSON'); }
  if (canonicalize(value) !== text) bad('signed or forwarded JSON is not canonical');
  return value;
}

function signed(encoded, digest, purpose, schemaVersion, pin, maxBytes = 32768) {
  if (!SHA.test(digest ?? '')) bad('signed envelope digest is invalid');
  const bytes = decode(encoded);
  if (bytes.length < 1 || bytes.length > maxBytes || sha(bytes) !== digest) {
    bad('signed envelope digest differs');
  }
  const envelope = jcs(bytes);
  if (!exact(envelope, ENVELOPE) || envelope.schema_version !== schemaVersion
    || envelope.purpose !== purpose || !SHA.test(envelope.payload_sha256 ?? '')
    || !decode(envelope.issuer_public_key_base64url, 32).equals(pin)) {
    bad('signed envelope purpose or Machine pin differs');
  }
  const payloadBytes = decode(envelope.payload_base64url);
  if (sha(payloadBytes) !== envelope.payload_sha256) bad('signed payload digest differs');
  const key = createPublicKey({ key: Buffer.concat([
    Buffer.from('302a300506032b6570032100', 'hex'), pin]), format: 'der', type: 'spki' });
  if (!verify(null, Buffer.concat([Buffer.from(purpose + '\0'), payloadBytes]), key,
    decode(envelope.signature_base64url, 64))) bad('Machine signature is invalid');
  return jcs(payloadBytes);
}

function live(value, now, maxExpiry, issuedField = 'issued_at') {
  const issued = Date.parse(value?.[issuedField]);
  const expires = Date.parse(value?.expires_at);
  if (!Number.isFinite(issued) || !Number.isFinite(expires) || issued > now
    || expires <= now || expires <= issued || expires - issued > 30000
    || expires > maxExpiry) bad('signed evidence is expired or stale');
}

function process(value, uid, gid) {
  return exact(value, PROCESS) && value.uid === uid && value.gid === gid
    && Number.isSafeInteger(value.pid) && value.pid > 1
    && Number.isSafeInteger(value.start_seconds) && value.start_seconds > 0
    && Number.isSafeInteger(value.start_micros) && value.start_micros >= 0
    && value.start_micros <= 999999;
}

// relayCheck is injected only by synthetic tests; the entry point uses the
// live lstat/Fstatat-compatible comparison in verifyCooperativeBRelaySocket.
export function verifyCooperativeMemberSetAttach(result, start, assignment, admission,
  pin = start?.machinePin, now = Date.now(), relayCheck = verifyCooperativeBRelaySocket) {
  const a = assignment?.payload;
  if (!Buffer.isBuffer(pin) || pin.length !== 32 || a?.profile_in_force !== 'managed-cooperative'
    || start?.adapterTransport !== 'brokered-b' || !exact(result, FIELDS)
    || result.version !== 'stage2a-member-attach/v1'
    || Buffer.byteLength(canonicalize(result)) > 32768
    || !HEX.test(result.attach ?? '') || !HEX.test(result.bridge_ready_nonce ?? '')
    || !/^[0-9a-f]{48}$/.test(result.member_bridge_token ?? '')
    || !absolute(result.cwd) || !absolute(result.member_socket)
    || result.installation_id !== start.installationId || result.start_id !== start.startId
    || !Array.isArray(admission?.admitted_runtimes)) bad('invalid cooperative H attach result');
  const assigned = a.members.find((m) => m.member_id === result.member_id);
  const admitted = admission.admitted_runtimes.find((m) => m.member_id === result.member_id);
  if (!assigned || !admitted || result.runtime_id !== admitted.runtime_id
    || result.launch_id !== assigned.launch_id || result.member_selector !== assigned.member_selector
    || result.member_socket !== start.memberSocket || !same(result.member_endpoint, start.memberEndpoint)
    || !exact(result.runner_endpoint, ['socketPath', 'peerUid', 'directory'])
    || result.runner_endpoint.socketPath !== start.admissionSocket
    || result.runner_endpoint.peerUid !== a.runner_uid
    || result.runner_endpoint.directory !== dirname(start.admissionSocket)
    || !Number.isFinite(Date.parse(result.expires_at)) || Date.parse(result.expires_at) <= now) {
    bad('H attach differs from signed member or endpoint');
  }
  const child = signed(result.child_observation_envelope_base64url,
    result.child_observation_envelope_sha256,
    'agent-bot/stage2a-member-set-child-observation/v1', 1, pin);
  const policy = signed(result.member_b_authority_envelope_base64url,
    result.member_b_authority_envelope_sha256,
    'agent-bot/stage2a-b-member-authority/v1', 1, pin);
  const ready = signed(result.ready_envelope_base64url, result.ready_envelope_sha256,
    'agent-bot/soul-cooperative-member-ready/v3', 3, pin, 16384);
  const observedB = signed(result.bridge_observed_envelope_base64url,
    ready.bridge_observed_sha256, 'agent-bot/soul-cooperative-b-observed/v3', 3, pin, 8192);
  const maxExpiry = Date.parse(a.expires_at);
  if (!exact(child, CHILD) || !exact(policy, POLICY) || !exact(ready, READY)
    || !exact(observedB, OBSERVED_B) || !exact(child.provisional_hq_mapping, MAP)) {
    bad('signed cooperative evidence shape differs');
  }
  for (const [value, kind] of [[child, 'stage2a-member-set-child-observation'],
    [policy, 'stage2a-b-member-authority']]) {
    if (value.contract !== 'machine/v3' || value.kind !== kind || value.schema_version !== 1
      || IDENTITY.some((field) => value[field] !== a[field])
      || value.reservation_sha256 !== start.reservationSha256) {
      bad('A-signed evidence differs from the reviewed start');
    }
    live(value, now, maxExpiry);
  }
  if (ready.contract !== 'machine/v3' || ready.kind !== 'soul-cooperative-member-ready'
    || ready.schema_version !== 3 || ready.profile_in_force !== a.profile_in_force
    || ['host_id', 'installation_id', 'start_id', 'hq_epoch']
      .some((field) => ready[field] !== a[field])
    || ready.reservation_sha256 !== start.reservationSha256
    || ready.assignment_envelope_sha256 !== assignment.envelopeSha256
    || ready.child_observation_envelope_sha256 !== result.child_observation_envelope_sha256
    || ready.member_b_authority_envelope_sha256 !== result.member_b_authority_envelope_sha256
    || ready.provisional_hq_mapping_sha256 !== child.provisional_hq_mapping_sha256
    || observedB.contract !== 'machine/v3' || observedB.kind !== 'soul-cooperative-b-observed'
    || observedB.schema_version !== 3 || observedB.reservation_sha256 !== start.reservationSha256
    || observedB.bridge_assignment_sha256 !== a.b_authority.envelope_sha256
    || observedB.installation_id !== a.installation_id || observedB.start_id !== a.start_id
    || observedB.launch_id !== start.launchId || observedB.plan_id !== a.plan_id
    || observedB.plan_digest !== a.plan_digest || observedB.hq_epoch !== a.hq_epoch
    || !SHA.test(observedB.bind_receipt_sha256 ?? '')
    || decode(observedB.grant_nonce, 32).length !== 32) {
    bad('cooperative Ready or B observation differs from signed start');
  }
  live(ready, now, maxExpiry);
  live(observedB, now, maxExpiry, 'observed_at');
  if (Date.parse(result.expires_at) > Date.parse(ready.expires_at)
    || Date.parse(ready.expires_at) > Date.parse(observedB.expires_at)) {
    bad('H attach exceeds signed Ready or B observation');
  }
  const map = child.provisional_hq_mapping;
  if (child.assignment_envelope_sha256 !== assignment.envelopeSha256
    || child.provisional_hq_mapping_sha256 !== sha(Buffer.from(canonicalize(map)))
    || policy.member_set_assignment_envelope_sha256 !== assignment.envelopeSha256
    || policy.owner_plan_member_set_sha256 !== a.owner_plan_member_set_sha256
    || policy.plan_id !== a.plan_id || policy.plan_digest !== a.plan_digest
    || policy.hq_uid !== start.hqUid || policy.runner_uid !== a.runner_uid
    || !same(policy.b_authority, a.b_authority) || !same(policy.bridge, a.bridge)
    || map.contract !== 'hq/v1' || map.kind !== 'stage2a-provisional-member-map'
    || map.schema_version !== 1 || IDENTITY.some((field) => map[field] !== a[field])
    || map.assignment_envelope_sha256 !== assignment.envelopeSha256
    || map.runtime_state !== 'provisional' || map.acp_authority !== 'withheld') {
    bad('A-signed child, B policy or H map differs from signed assignment');
  }
  live(map, now, maxExpiry);
  if (![child.members, policy.members, ready.members, map.members,
    result.bridge_arm_rows_base64url].every((rows) => Array.isArray(rows) && rows.length === 2)) {
    bad('signed cooperative member rows are incomplete');
  }
  const armRows = result.bridge_arm_rows_base64url.map((encoded) => jcs(decode(encoded)));
  for (let i = 0; i < 2; i++) {
    const m = a.members[i];
    const c = child.members[i];
    const p = policy.members[i];
    const r = ready.members[i];
    const h = map.members[i];
    const arm = armRows[i];
    const admittedRuntime = admission.admitted_runtimes.find((row) => row.member_id === m.member_id);
    if (!exact(c, CHILD_MEMBER) || !exact(p, POLICY_MEMBER) || !exact(r, READY_MEMBER)
      || !exact(h, ['member_id', 'member_selector', 'runtime_id', 'channel_binding'])
      || !exact(arm, ARM) || !admittedRuntime
      || [c, p, r, h, arm].some((row) => row.member_id !== m.member_id
        || row.member_selector !== m.member_selector)
      || c.launch_id !== m.launch_id || p.launch_id !== m.launch_id
      || r.member_launch_id !== m.launch_id || c.runtime_id !== h.runtime_id
      || arm.runtime_id !== h.runtime_id || h.runtime_id !== admittedRuntime.runtime_id
      || h.channel_binding !== admittedRuntime.channel_binding
      || !same(c.launcher_process, r.launcher_process)
      || !same(c.child_process, r.child_process) || c.grant_sha256 !== r.grant_sha256
      || !SHA.test(r.h_observation_sha256 ?? '') || !SHA.test(c.grant_sha256 ?? '')
      || !SHA.test(r.b_arm_receipt_sha256 ?? '') || r.b_arm_receipt_sha256 !== sha(Buffer.from(canonicalize(arm)))
      || p.adjacent_cli_path !== m.adjacent_cli_path
      || p.adjacent_cli_sha256 !== m.adjacent_cli_sha256
      || !exact(p.qualification, QUALIFICATION)
      || !['request_sha256', 'headers_sha256', 'client_key_sha256']
        .every((field) => SHA.test(p.qualification[field] ?? ''))
      || !process(c.launcher_process, a.runner_uid, a.runner_gid)
      || !exact(c.child_process, CHILD_PROCESS)
      || c.child_process.parent_pid !== c.launcher_process.pid
      || c.child_process.uid !== a.runner_uid || c.child_process.gid !== a.runner_gid
      || !Number.isSafeInteger(c.child_process.pid) || c.child_process.pid <= 1
      || !Number.isSafeInteger(c.child_process.process_group_id)
      || c.child_process.process_group_id <= 1
      || !Number.isSafeInteger(c.child_process.start_seconds) || c.child_process.start_seconds <= 0
      || !Number.isSafeInteger(c.child_process.start_micros) || c.child_process.start_micros < 0
      || c.child_process.start_micros > 999999
      || c.child_process.executable_sha256 !== m.command_sha256
      || arm.child_observation_envelope_sha256 !== result.child_observation_envelope_sha256
      || arm.bridge_uid !== a.bridge.uid
      || arm.adapter_pid !== c.child_process.pid || arm.adapter_uid !== c.child_process.uid
      || arm.adapter_gid !== c.child_process.gid
      || arm.adapter_start_seconds !== c.child_process.start_seconds
      || arm.adapter_start_micros !== c.child_process.start_micros
      || arm.relay_peer_rule !== 'a-attested-live-direct-child-of-adapter-v1'
      || arm.relay_peer_state !== 'unobserved'
      || arm.provider_ingress !== 'withheld-pending-per-peer-attestation'
      || arm.state !== 'armed' || !Number.isFinite(Date.parse(arm.armed_at))
      || Date.parse(arm.armed_at) > now) {
      bad('member child, B arm or H runtime differs from signed assignment');
    }
  }
  if (child.members[0].launcher_process.pid === child.members[1].launcher_process.pid
    || child.members[0].child_process.pid === child.members[1].child_process.pid
    || !process(observedB.launcher, a.bridge.uid, a.bridge.gid)
    || !process(observedB.bridge, a.bridge.uid, a.bridge.gid)
    || observedB.bridge.pid === observedB.launcher.pid
    || !exact(observedB.relay_socket, ['path', 'socket'])
    || !exact(observedB.relay_socket.socket, ['uid', 'gid', 'device', 'inode', 'mode'])
    || observedB.relay_socket.path !== start.relaySocket
    || observedB.relay_socket.socket.uid !== start.relayEndpoint?.owner_uid
    || observedB.relay_socket.socket.gid !== start.relayEndpoint?.group_gid
    || observedB.relay_socket.socket.mode !== start.relayEndpoint?.socket_mode
    || ![observedB.relay_socket.socket.device, observedB.relay_socket.socket.inode,
      observedB.relay_socket_birthtime_ns].every((value) => POSITIVE.test(value ?? ''))) {
    bad('A-observed B process or relay socket differs from signed start');
  }
  relayCheck(start, { path: observedB.relay_socket.path,
    uid: observedB.relay_socket.socket.uid, gid: observedB.relay_socket.socket.gid,
    mode: observedB.relay_socket.socket.mode,
    device: observedB.relay_socket.socket.device,
    inode: observedB.relay_socket.socket.inode,
    birthtime_ns: observedB.relay_socket_birthtime_ns });
  return Object.freeze({ child: Object.freeze(child), policy: Object.freeze(policy),
    ready: Object.freeze(ready), observedB: Object.freeze(observedB),
    readyEnvelopeSha256: result.ready_envelope_sha256 });
}
