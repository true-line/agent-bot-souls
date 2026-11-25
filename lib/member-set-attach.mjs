// R consumes H's post-Hello handoff only after independently checking the
// three exact A-signed records. H's attach and bridge tokens are transport
// capabilities; they cannot replace A's observed children or B policy.
import { createHash, createPublicKey, verify } from 'node:crypto';
import { dirname, isAbsolute, parse, resolve } from 'node:path';
import { canonicalize, parseStrict } from './contracts.mjs';
import { verifyCooperativeMemberSetAttach } from './cooperative-member-attach.mjs';

const FIELDS = ['version', 'installation_id', 'start_id', 'member_id', 'member_selector',
  'runtime_id', 'launch_id', 'attach', 'expires_at', 'cwd', 'member_socket',
  'member_endpoint', 'member_bridge_token', 'bridge_ready_nonce', 'runner_endpoint',
  'child_observation_envelope_base64url', 'child_observation_envelope_sha256',
  'member_b_authority_envelope_base64url', 'member_b_authority_envelope_sha256',
  'ready_envelope_base64url', 'ready_envelope_sha256'];
const ENVELOPE = ['schema_version', 'purpose', 'issuer_public_key_base64url',
  'payload_sha256', 'payload_base64url', 'signature_base64url'];
const COMMON = ['contract', 'kind', 'schema_version', 'profile_in_force', 'host_id',
  'installation_id', 'soul_id', 'start_id', 'hq_epoch'];
const CHILD = [...COMMON, 'reservation_sha256', 'assignment_envelope_sha256',
  'provisional_hq_mapping_sha256', 'provisional_hq_mapping', 'members',
  'observed_at', 'issued_at', 'expires_at'];
const B_POLICY = [...COMMON, 'plan_id', 'plan_digest', 'reservation_sha256',
  'member_set_assignment_envelope_sha256', 'owner_plan_member_set_sha256',
  'b_authority', 'hq_uid', 'runner_uid', 'bridge', 'members', 'issued_at', 'expires_at'];
const LOCAL_TEST_B_POLICY = [...B_POLICY, 'outer_launch_id', 'local_test'];
const READY = [...COMMON, 'reservation_sha256', 'assignment_envelope_sha256',
  'child_observation_envelope_sha256', 'b_authority_sha256',
  'member_b_authority_envelope_sha256', 'provisional_hq_mapping_sha256',
  'bridge_process', 'members', 'observed_at', 'issued_at', 'expires_at'];
const MAP = [...COMMON, 'assignment_envelope_sha256', 'runtime_state',
  'acp_authority', 'members', 'issued_at', 'expires_at'];
const CHILD_MEMBER = ['member_id', 'launch_id', 'member_selector', 'runtime_id',
  'grant_sha256', 'launcher_process', 'child_process'];
const B_MEMBER = ['member_id', 'launch_id', 'member_selector', 'adjacent_cli_path',
  'adjacent_cli_sha256', 'qualification'];
const READY_MEMBER = ['member_id', 'launch_id', 'member_selector', 'runtime_id',
  'bridge_arm', 'bridge_arm_receipt_sha256'];
const ARM = ['member_id', 'member_selector', 'runtime_id',
  'child_observation_envelope_sha256', 'bridge_uid', 'adapter_pid', 'adapter_uid',
  'adapter_gid', 'adapter_start_seconds', 'adapter_start_micros', 'relay_peer_rule',
  'relay_peer_state', 'provider_ingress', 'state', 'armed_at'];
const CHILD_PROCESS = ['pid', 'uid', 'gid', 'parent_pid', 'process_group_id',
  'start_seconds', 'start_micros', 'executable_sha256'];
const LAUNCHER_PROCESS = ['pid', 'uid', 'gid', 'start_seconds', 'start_micros'];
const BRIDGE_PROCESS = ['pid', 'uid', 'gid', 'start_seconds', 'start_micros',
  'executable_sha256'];
const QUALIFICATION = ['model', 'request_sha256', 'headers_sha256',
  'client_key_sha256', 'http_host', 'messages_query', 'response_text'];
const LOCAL_TEST_QUALIFICATION = ['mode', 'model', 'body_profile',
  'static_projection_sha256', 'owner_prompt_sha256', 'r_first_brief_sha256',
  'header_shape_sha256', 'client_key_sha256', 'http_host', 'messages_query',
  'response_text_sha256'];
const LOCAL_TEST_FIELDS = ['selected_member_id', 'selected_launch_id',
  'selected_member_selector', 'runner_account', 'expected_child_cwd_lexical',
  'expected_child_cwd_emitted', 'expected_child_home_lexical',
  'expected_memory_path_lexical', 'body_profile', 'static_projection_sha256',
  'owner_prompt_sha256', 'r_first_brief_sha256', 'header_shape',
  'header_shape_sha256', 'client_key_sha256', 'model', 'http_host',
  'messages_query', 'fixture_config_sha256', 'ancillary_profile',
  'ancillary_profile_sha256'];
const SHA = /^sha256:[0-9a-f]{64}$/;
const HEX = /^[0-9a-f]{64}$/;
const bad = (reason) => { throw new Error(`member-set attach: ${reason}`); };
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const exact = (value, fields) => object(value) && Object.keys(value).length === fields.length
  && fields.every((field) => Object.hasOwn(value, field));
const sha = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const same = (left, right) => canonicalize(left) === canonicalize(right);
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
  catch { return bad('invalid signed JSON'); }
  if (canonicalize(value) !== text) bad('signed JSON is not canonical');
  return value;
}

function signed(value, digest, purpose, pin) {
  if (!SHA.test(digest ?? '')) bad('signed envelope digest is invalid');
  const bytes = decode(value);
  if (bytes.length < 1 || bytes.length > 32768 || sha(bytes) !== digest) bad('signed envelope digest differs');
  const envelope = jcs(bytes);
  if (!exact(envelope, ENVELOPE) || envelope.schema_version !== 1 || envelope.purpose !== purpose
    || !SHA.test(envelope.payload_sha256 ?? '')
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

function lifetime(value, now, latest) {
  const issued = Date.parse(value?.issued_at);
  const expires = Date.parse(value?.expires_at);
  if (!Number.isFinite(issued) || !Number.isFinite(expires) || issued > now
    || expires <= now || expires <= issued || expires - issued > 30000
    || (latest !== undefined && expires > latest)) bad('signed evidence is expired or stale');
}

function common(value, assignment, kind, localTest = false) {
  const a = assignment.payload;
  if (value.contract !== (localTest ? 'machine/local-test-v1' : 'machine/v3')
    || value.kind !== kind || value.schema_version !== 1
    || ['profile_in_force', 'host_id', 'installation_id', 'soul_id', 'start_id', 'hq_epoch']
      .some((field) => value[field] !== a[field])) bad(`${kind} differs from the signed assignment`);
}

function memberRows(rows, fields, assignment) {
  const assigned = assignment.payload.members;
  if (!Array.isArray(rows) || rows.length !== 2 || !rows.every((row) => exact(row, fields))) {
    bad('signed member rows are incomplete');
  }
  for (let i = 0; i < 2; i++) {
    for (const field of ['member_id', 'launch_id', 'member_selector']) {
      if (rows[i][field] !== assigned[i][field]) bad('signed member row differs from assignment');
    }
  }
}

export function verifyMemberSetAttach(result, start, assignment, admission,
  pin = start?.machinePin, now = Date.now()) {
  const localTest = start?.localTestMode === true;
  const cooperative = assignment?.payload?.profile_in_force === 'managed-cooperative';
  if (localTest && cooperative) bad('local-test start cannot use cooperative member evidence');
  if (cooperative) return verifyCooperativeMemberSetAttach(result, start, assignment,
    admission, pin, now);
  if (!Buffer.isBuffer(pin) || pin.length !== 32 || !assignment?.payload
    || (localTest && assignment.payload.contract !== 'machine/local-test-v1')
    || (!localTest && assignment.payload.contract !== 'machine/v3')
    || !['managed-protected', 'managed-cooperative'].includes(assignment.payload.profile_in_force)
    || (cooperative && start?.adapterTransport !== 'brokered-b')
    || !exact(result, FIELDS)
    || result.version !== (localTest ? 'stage2a-member-attach-local-test/v1' : 'stage2a-member-attach/v1')
    || Buffer.byteLength(canonicalize(result)) > 131072
    || !HEX.test(result.attach ?? '') || !HEX.test(result.bridge_ready_nonce ?? '')
    || !/^[0-9a-f]{48}$/.test(result.member_bridge_token ?? '')
    || !absolute(result.cwd) || !absolute(result.member_socket)
    || result.installation_id !== start?.installationId || result.start_id !== start?.startId
    || !Array.isArray(admission?.admitted_runtimes)) bad('invalid two-member H attach result');
  const assigned = assignment.payload.members.find((member) => member.member_id === result.member_id);
  const admitted = admission.admitted_runtimes.find((runtime) => runtime.member_id === result.member_id);
  const endpoint = start.memberEndpoint?.member_endpoint ?? start.memberEndpoint;
  const memberSocket = start.memberEndpoint?.member_socket ?? start.memberSocket;
  if (!assigned || !admitted || result.runtime_id !== admitted.runtime_id
    || result.launch_id !== assigned.launch_id || result.member_selector !== assigned.member_selector
    || result.member_socket !== memberSocket || !same(result.member_endpoint, endpoint)
    || !exact(result.runner_endpoint, ['socketPath', 'peerUid', 'directory'])
    || result.runner_endpoint.socketPath !== start.admissionSocket
    || result.runner_endpoint?.peerUid !== start.runnerUid
    || result.runner_endpoint?.directory !== dirname(start.admissionSocket)
    || !Number.isFinite(Date.parse(result.expires_at)) || Date.parse(result.expires_at) <= now) {
    bad('H attach differs from the signed member or endpoint');
  }
  const child = signed(result.child_observation_envelope_base64url,
    result.child_observation_envelope_sha256,
    localTest ? 'agent-bot/stage2a-member-set-child-observation-local-test/v1'
      : 'agent-bot/stage2a-member-set-child-observation/v1', pin);
  const policy = signed(result.member_b_authority_envelope_base64url,
    result.member_b_authority_envelope_sha256,
    localTest ? 'agent-bot/stage2a-b-member-authority-local-test/v1'
      : 'agent-bot/stage2a-b-member-authority/v1', pin);
  const ready = signed(result.ready_envelope_base64url, result.ready_envelope_sha256,
    localTest ? 'agent-bot/stage2a-member-set-ready-local-test/v1'
      : 'agent-bot/stage2a-member-set-ready/v1', pin);
  const a = assignment.payload;
  const latest = Date.parse(a.expires_at);
  if (!exact(child, CHILD) || !exact(policy, localTest ? LOCAL_TEST_B_POLICY : B_POLICY)
    || !exact(ready, READY)
    || !exact(child.provisional_hq_mapping, MAP)) bad('signed two-member evidence shape differs');
  for (const [value, kind] of [[child, 'stage2a-member-set-child-observation'],
    [policy, 'stage2a-b-member-authority'], [ready, 'stage2a-member-set-ready']]) {
    common(value, assignment, kind, localTest);
    lifetime(value, now, latest);
    if (value.reservation_sha256 !== start.reservationSha256) bad('evidence reservation differs');
  }
  if (child.assignment_envelope_sha256 !== assignment.envelopeSha256
    || policy.member_set_assignment_envelope_sha256 !== assignment.envelopeSha256
    || ready.assignment_envelope_sha256 !== assignment.envelopeSha256
    || child.provisional_hq_mapping_sha256 !== sha(Buffer.from(canonicalize(child.provisional_hq_mapping)))
    || ready.provisional_hq_mapping_sha256 !== child.provisional_hq_mapping_sha256
    || ready.child_observation_envelope_sha256 !== result.child_observation_envelope_sha256
    || ready.member_b_authority_envelope_sha256 !== result.member_b_authority_envelope_sha256
    || ready.b_authority_sha256 !== a.b_authority.envelope_sha256
    || policy.owner_plan_member_set_sha256 !== a.owner_plan_member_set_sha256
    || !same(policy.b_authority, a.b_authority) || !same(policy.bridge, a.bridge)
    || policy.plan_id !== a.plan_id || policy.plan_digest !== a.plan_digest
    || policy.runner_uid !== a.runner_uid || policy.hq_uid !== start.hqUid
    || (localTest && policy.outer_launch_id !== start.launchId)) {
    bad('A-signed evidence chain differs from the reviewed start');
  }
  if (localTest) {
    const lt = policy.local_test;
    const selected = a.members.find((member) => member.member_id === lt?.selected_member_id);
    const selectedPolicy = policy.members?.find?.((member) => member.member_id === lt?.selected_member_id);
    const childSlot = createHash('sha256')
      .update('agent-bot-soul-endpoint-start/v1\0')
      .update(a.installation_id).update('\0').update(a.start_id)
      .digest('hex').slice(0, 20);
    const childRoot = `/var/agent-bot-soul-runner-${lt?.runner_account}/state/child-${childSlot}`;
    if (!exact(lt, LOCAL_TEST_FIELDS) || !selected || selected.role !== 'lead'
      || lt.selected_launch_id !== selected.launch_id
      || lt.selected_launch_id === start.launchId
      || lt.selected_member_selector !== selected.member_selector
      || lt.runner_account !== '_abm-sr-' + createHash('sha256')
        .update(a.installation_id).digest('hex').slice(0, 20)
      || lt.expected_child_cwd_lexical !== `${childRoot}/work`
      || lt.expected_child_cwd_emitted !== '/private' + lt.expected_child_cwd_lexical
      || lt.expected_child_home_lexical !== `${childRoot}/home`
      || lt.expected_memory_path_lexical !== lt.expected_child_home_lexical
        + '/.claude/projects/'
        + lt.expected_child_cwd_emitted.replace(/[^A-Za-z0-9]/g, '-') + '/memory/'
      || (result.member_id === selected.member_id && result.cwd !== lt.expected_child_cwd_lexical)
      || lt.body_profile !== 'stage2a-stock-observed-local-test/v1'
      || !['static_projection_sha256', 'owner_prompt_sha256', 'r_first_brief_sha256',
        'header_shape_sha256', 'client_key_sha256', 'fixture_config_sha256',
        'ancillary_profile_sha256'].every((field) => SHA.test(lt[field] ?? ''))
      || !exact(lt.header_shape, ['schema', 'host', 'required_fixed',
        'required_volatile', 'forbidden', 'allow_extra'])
      || lt.header_shape.schema !== 'stage2a-observed-body-header-shape/v1'
      || lt.header_shape.host !== lt.http_host
      || lt.header_shape.allow_extra !== false
      || !exact(lt.ancillary_profile, ['schema', 'body_profile',
        'normalized_body_sha256', 'first_header_shape', 'first_headers_sha256',
        'second_header_shape', 'second_headers_sha256', 'order', 'target_after',
        'max_ancillary', 'ancillary_http_status'])
      || lt.ancillary_profile.schema !== 'stage2a-stock-ancillary-local-test-profile/v1'
      || lt.ancillary_profile.body_profile !== 'stage2a-stock-ancillary-one-block/v1'
      || !SHA.test(lt.ancillary_profile.normalized_body_sha256 ?? '')
      || !SHA.test(lt.ancillary_profile.first_headers_sha256 ?? '')
      || !SHA.test(lt.ancillary_profile.second_headers_sha256 ?? '')
      || canonicalize(lt.ancillary_profile.order) !== canonicalize(['first', 'second'])
      || canonicalize(lt.ancillary_profile.target_after) !== canonicalize(['first'])
      || lt.ancillary_profile.max_ancillary !== 2
      || lt.ancillary_profile.ancillary_http_status !== 422
      || sha(Buffer.from(canonicalize(lt.header_shape))) !== lt.header_shape_sha256
      || sha(Buffer.from(canonicalize(lt.ancillary_profile))) !== lt.ancillary_profile_sha256
      || !selectedPolicy || !exact(selectedPolicy.qualification, LOCAL_TEST_QUALIFICATION)
      || ['model', 'body_profile', 'static_projection_sha256', 'owner_prompt_sha256',
        'r_first_brief_sha256', 'header_shape_sha256', 'client_key_sha256',
        'http_host', 'messages_query'].some((field) => selectedPolicy.qualification[field] !== lt[field])) {
      bad('local-test B policy differs from the signed lead and fixture pins');
    }
  }
  const map = child.provisional_hq_mapping;
  if (map.contract !== (localTest ? 'hq/local-test-v1' : 'hq/v1')
    || map.kind !== (localTest
      ? 'stage2a-provisional-member-map-local-test' : 'stage2a-provisional-member-map')
    || map.schema_version !== 1
    || ['profile_in_force', 'host_id', 'installation_id', 'soul_id', 'start_id', 'hq_epoch']
      .some((field) => map[field] !== a[field])
    || map.runtime_state !== 'provisional'
    || map.acp_authority !== 'withheld' || map.assignment_envelope_sha256 !== assignment.envelopeSha256
    || !Array.isArray(map.members) || map.members.length !== 2) bad('provisional H map differs');
  lifetime(map, now, latest);
  memberRows(child.members, CHILD_MEMBER, assignment);
  memberRows(policy.members, B_MEMBER, assignment);
  memberRows(ready.members, READY_MEMBER, assignment);
  for (let i = 0; i < 2; i++) {
    const member = a.members[i];
    const observed = child.members[i];
    const b = policy.members[i];
    const r = ready.members[i];
    const h = map.members[i];
    const admittedRuntime = admission.admitted_runtimes.find((runtime) => runtime.member_id === member.member_id);
    if (!exact(h, ['member_id', 'member_selector', 'runtime_id', 'channel_binding'])
      || !admittedRuntime || h.member_id !== member.member_id
      || h.member_selector !== member.member_selector
      || h.runtime_id !== admittedRuntime.runtime_id
      || h.channel_binding !== admittedRuntime.channel_binding
      || observed.runtime_id !== h.runtime_id || r.runtime_id !== h.runtime_id
      || b.adjacent_cli_path !== member.adjacent_cli_path
      || b.adjacent_cli_sha256 !== member.adjacent_cli_sha256
      || !(localTest
        ? (i === a.members.findIndex((candidate) => candidate.member_id === policy.local_test?.selected_member_id)
          ? exact(b.qualification, LOCAL_TEST_QUALIFICATION)
            && b.qualification.mode === 'observed-body-local-test/v1'
            && ['static_projection_sha256', 'owner_prompt_sha256', 'r_first_brief_sha256',
              'header_shape_sha256', 'client_key_sha256', 'response_text_sha256']
              .every((field) => SHA.test(b.qualification[field] ?? ''))
          : exact(b.qualification, ['mode']) && b.qualification.mode === 'disabled')
        : exact(b.qualification, QUALIFICATION)
          && ['request_sha256', 'headers_sha256', 'client_key_sha256']
            .every((field) => SHA.test(b.qualification[field] ?? '')))
      || !exact(observed.child_process, CHILD_PROCESS)
      || !SHA.test(observed.grant_sha256 ?? '')
      || !exact(observed.launcher_process, LAUNCHER_PROCESS)
      || observed.launcher_process.uid !== start.runnerUid
      || observed.launcher_process.gid !== start.runnerGid
      || !Number.isSafeInteger(observed.launcher_process.pid)
      || observed.launcher_process.pid <= 1
      || !Number.isSafeInteger(observed.launcher_process.start_seconds)
      || observed.launcher_process.start_seconds <= 0
      || !Number.isSafeInteger(observed.launcher_process.start_micros)
      || observed.launcher_process.start_micros < 0
      || observed.launcher_process.start_micros > 999999
      || observed.child_process.parent_pid !== observed.launcher_process.pid
      || observed.child_process.uid !== start.runnerUid
      || observed.child_process.gid !== start.runnerGid
      || !Number.isSafeInteger(observed.child_process.pid) || observed.child_process.pid <= 1
      || !Number.isSafeInteger(observed.child_process.process_group_id)
      || observed.child_process.process_group_id <= 1
      || !Number.isSafeInteger(observed.child_process.start_seconds)
      || observed.child_process.start_seconds <= 0
      || !Number.isSafeInteger(observed.child_process.start_micros)
      || observed.child_process.start_micros < 0 || observed.child_process.start_micros > 999999
      || !exact(r.bridge_arm, ARM)
      || r.bridge_arm.member_id !== member.member_id
      || r.bridge_arm.member_selector !== member.member_selector
      || r.bridge_arm.runtime_id !== h.runtime_id
      || r.bridge_arm.child_observation_envelope_sha256 !== result.child_observation_envelope_sha256
      || r.bridge_arm.bridge_uid !== a.bridge.uid
      || r.bridge_arm.relay_peer_rule !== 'a-attested-live-direct-child-of-adapter-v1'
      || r.bridge_arm.relay_peer_state !== 'unobserved'
      || r.bridge_arm.provider_ingress !== 'withheld-pending-per-peer-attestation'
      || r.bridge_arm.state !== 'armed'
      || !Number.isFinite(Date.parse(r.bridge_arm.armed_at))
      || Date.parse(r.bridge_arm.armed_at) > now
      || r.bridge_arm_receipt_sha256 !== sha(Buffer.from(canonicalize(r.bridge_arm)))
      || r.bridge_arm.adapter_pid !== observed.child_process?.pid
      || r.bridge_arm.adapter_uid !== observed.child_process?.uid
      || r.bridge_arm.adapter_gid !== observed.child_process?.gid
      || r.bridge_arm.adapter_start_seconds !== observed.child_process?.start_seconds
      || r.bridge_arm.adapter_start_micros !== observed.child_process?.start_micros
      || observed.child_process.executable_sha256 !== member.command_sha256) {
      bad('member child, B arm or H runtime differs from the signed assignment');
    }
  }
  if (child.members[0].launcher_process.pid === child.members[1].launcher_process.pid
    || child.members[0].child_process.pid === child.members[1].child_process.pid) {
    bad('signed child wrappers or ACP processes are not distinct');
  }
  if (ready.members.find((member) => member.member_id === result.member_id)?.runtime_id !== result.runtime_id
    || !exact(ready.bridge_process, BRIDGE_PROCESS)
    || ready.bridge_process.uid !== a.bridge.uid || ready.bridge_process.gid !== a.bridge.gid
    || !Number.isSafeInteger(ready.bridge_process.pid) || ready.bridge_process.pid <= 1
    || !Number.isSafeInteger(ready.bridge_process.start_seconds)
    || ready.bridge_process.start_seconds <= 0
    || !Number.isSafeInteger(ready.bridge_process.start_micros)
    || ready.bridge_process.start_micros < 0
    || ready.bridge_process.start_micros > 999999
    || (a.profile_in_force === 'managed-protected'
      && ready.bridge_process?.executable_sha256 !== start.launchInputRecords?.component_digests?.bridge)
    || Date.parse(result.expires_at) > Date.parse(ready.expires_at)) {
    bad('H attach is not bound to live aggregate Ready');
  }
  return Object.freeze({ child: Object.freeze(child), policy: Object.freeze(policy),
    ready: Object.freeze(ready), readyEnvelopeSha256: result.ready_envelope_sha256 });
}
