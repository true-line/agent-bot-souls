import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { canonicalize } from '../lib/contracts.mjs';
import { verifyMemberSetAdmission, verifyMemberSetAssignment, verifyMemberSetLaunch } from '../lib/member-set-assignment.mjs';
import { verifyMemberSetAttach } from '../lib/member-set-attach.mjs';
import { verifyCooperativeMemberSetAttach } from '../lib/cooperative-member-attach.mjs';

const purpose = 'agent-bot/stage2a-member-set-assignment/v1';
const hash = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
const jcs = (value) => Buffer.from(canonicalize(value));
const pair = generateKeyPairSync('ed25519');
const machinePin = pair.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
const stock = {
  adapter_id: 'claude-code', adapter_version: '0.109.0', executable: 'claude-agent-acp',
  executable_sha256: `sha256:${'a'.repeat(64)}`, adjacent_cli: 'claude',
  adjacent_cli_sha256: `sha256:${'b'.repeat(64)}`,
};
const soulInfoBytes = Buffer.from(JSON.stringify({ soul_id: 'agent_01234567-0123-4123-8123-0123456789ab',
  members: [
    { member_id: 'm_lead', role: 'lead', adapter_id: 'claude-code', adapter_version: '0.109.0' },
    { member_id: 'm_spec', role: 'specialist', adapter_id: 'claude-code', adapter_version: '0.109.0' },
  ] }));
const adapterManifestBytes = Buffer.from(JSON.stringify(stock));
const command = '/fixture/adapter/claude-agent-acp';
const cli = '/fixture/adapter/claude';
const hostProjection = { adapters: { 'claude-code': { command: [command], env: {} } },
  installation: { installation_id: 'inst_fixture' } };
const frozen = { soulInfoBytes, adapterManifestBytes, hostProjection,
  definitionMeasurement: `sha256:${'c'.repeat(64)}`,
  files: new Map([[command, stock.executable_sha256], [cli, stock.adjacent_cli_sha256]]) };
const reservation = `sha256:${'d'.repeat(64)}`;
const selector = (memberId, launchId) => 'mb_' + createHash('sha256')
  .update('agent-bot/stage2a-member-selector/v1\0').update(reservation).update('\0')
  .update(memberId).update('\0').update(launchId).digest('hex');
const members = ['m_lead', 'm_spec'].map((member_id, i) => {
  const launch_id = `ln_${String(i + 1).repeat(24)}`;
  return { member_id, role: i === 0 ? 'lead' : 'specialist', adapter_id: 'claude-code',
    adapter_version: '0.109.0', command_path: command, command_sha256: stock.executable_sha256,
    adjacent_cli_path: cli, adjacent_cli_sha256: stock.adjacent_cli_sha256,
    launch_id, member_selector: selector(member_id, launch_id) };
});
const projection = members.map(({ member_id, role, adapter_id, adapter_version,
  command_path, command_sha256, adjacent_cli_path, adjacent_cli_sha256 }) => ({
  member_id, role, adapter_id, adapter_version, command_path, command_sha256,
  adjacent_cli_path, adjacent_cli_sha256,
}));
const payload = {
  contract: 'machine/v3', kind: 'stage2a-member-set-assignment', schema_version: 1,
  profile_in_force: 'managed-protected', host_id: 'host_fixture',
  installation_id: 'inst_fixture', soul_id: 'agent_01234567-0123-4123-8123-0123456789ab',
  start_id: `st_${'1'.repeat(24)}`, hq_epoch: '2'.repeat(64), plan_id: 'plan_fixture',
  plan_digest: '3'.repeat(64), owner_plan_member_set_sha256: hash(jcs(projection)),
  reservation_sha256: reservation,
  b_authority: { purpose: 'agent-bot/stage2a-reservation/v3', envelope_sha256: reservation },
  soul_artifact_sha256: `sha256:${'4'.repeat(64)}`,
  frozen_soul_info_sha256: hash(soulInfoBytes),
  adapter_manifest_relpath: 'Contents/opt/stock-claude.json',
  frozen_adapter_manifest_sha256: hash(adapterManifestBytes),
  host_projection_sha256: hash(jcs(hostProjection)),
  definition_measurement: frozen.definitionMeasurement, runner_uid: 331, runner_gid: 331,
  bridge: { account: '_abm-b-fixture', uid: 332, gid: 332, endpoints: {} },
  members, issued_at: '2026-11-23T18:00:00Z', expires_at: '2026-11-23T18:00:20Z',
};
const expected = { ...Object.fromEntries(['profile_in_force', 'host_id', 'installation_id',
  'soul_id', 'start_id', 'hq_epoch', 'plan_id', 'plan_digest', 'reservation_sha256',
  'soul_artifact_sha256', 'definition_measurement', 'runner_uid', 'runner_gid',
  ].map((name) => [name, payload[name]])),
  b_authority_sha256: reservation, bridge: payload.bridge };
const envelope = (value, key = pair.privateKey) => {
  const bytes = jcs(value);
  return jcs({ schema_version: 1, purpose,
    issuer_public_key_base64url: machinePin.toString('base64url'), payload_sha256: hash(bytes),
    payload_base64url: bytes.toString('base64url'),
    signature_base64url: sign(null, Buffer.concat([Buffer.from(purpose + '\0'), bytes]), key).toString('base64url') });
};
const verify = (value, options = {}) => verifyMemberSetAssignment({ envelopeBytes: envelope(value),
  machinePin, expected, frozen, now: Date.parse('2026-11-23T18:00:10Z'), ...options });

test('A-signed exact frozen two-member assignment is only a pre-launch claim', () => {
  assert.equal(verify(payload).payload.members.length, 2);
});

test('member-set assignment rejects altered, missing, wrong-host, wrong-plan and stale claims', () => {
  assert.throws(() => verify({ ...payload, members: [members[0]] }), /invalid payload shape/);
  assert.throws(() => verify({ ...payload, members: [members[0], { ...members[1], role: 'lead' }] }), /measured stock files/);
  assert.throws(() => verify({ ...payload, members: [members[0], { ...members[1], adjacent_cli_sha256: `sha256:${'f'.repeat(64)}` }] }), /measured stock files/);
  assert.throws(() => verify({ ...payload, owner_plan_member_set_sha256: `sha256:${'f'.repeat(64)}` }), /owner-reviewed projection/);
  assert.throws(() => verify(payload, { expected: { ...expected, host_id: 'other-host' } }), /host_id differs/);
  assert.throws(() => verify(payload, { expected: { ...expected, runner_uid: 399 } }), /runner_uid differs/);
  assert.throws(() => verify(payload, { expected: { ...expected, bridge: { ...payload.bridge, uid: 399 } } }), /bridge differs/);
  assert.throws(() => verify(payload, { now: Date.parse('2026-11-23T18:00:21Z') }), /expired/);
  assert.throws(() => verify(payload, { machinePin: Buffer.alloc(32) }), /signer differs/);
  assert.throws(() => verify(payload, { frozen: { ...frozen, adapterManifestBytes: Buffer.from('{}') } }), /frozen measured inputs/);
  const withFallback = Buffer.from(JSON.stringify({ ...JSON.parse(soulInfoBytes), members: [
    { ...JSON.parse(soulInfoBytes).members[0], fallbacks: [{ adapter_id: 'other', adapter_version: '1.0.0' }] },
    JSON.parse(soulInfoBytes).members[1],
  ] }));
  assert.throws(() => verify({ ...payload, frozen_soul_info_sha256: hash(withFallback) },
    { frozen: { ...frozen, soulInfoBytes: withFallback } }), /stock adapter declaration/);
});

test('member-set assignment refuses a signed payload from another private key', () => {
  const other = generateKeyPairSync('ed25519');
  assert.throws(() => verifyMemberSetAssignment({ envelopeBytes: envelope(payload, other.privateKey),
    machinePin, expected, frozen, now: Date.parse('2026-11-23T18:00:10Z') }), /signature is invalid/);
});

test('final Hello and each ACP attach must match the signed member row', () => {
  const assignment = verify(payload);
  verifyMemberSetAdmission(assignment, [{ member_id: 'm_spec' }, { member_id: 'm_lead' }]);
  assert.throws(() => verifyMemberSetAdmission(assignment, [{ member_id: 'm_lead' }]), /exact signed two-member set/);
  assert.throws(() => verifyMemberSetAdmission(assignment, [{ member_id: 'm_lead' }, { member_id: 'm_lead' }]), /exact signed two-member set/);
  for (const member of members) {
    assert.equal(verifyMemberSetLaunch(assignment, member.member_id, {
      launch_id: member.launch_id, member_selector: member.member_selector }).member_id, member.member_id);
    assert.throws(() => verifyMemberSetLaunch(assignment, member.member_id, {
      launch_id: members[1 - members.indexOf(member)].launch_id,
      member_selector: member.member_selector }), /launch ID or selector/);
    assert.throws(() => verifyMemberSetLaunch(assignment, member.member_id, {
      launch_id: member.launch_id, member_selector: 'mb_wrong' }), /launch ID or selector/);
  }
});

test('prestarted attach requires the signed child, B policy and aggregate Ready chain', () => {
  const assignment = verify(payload);
  const authority = (purposeName, value, schemaVersion = 1) => {
    const bytes = jcs(value);
    return jcs({ schema_version: schemaVersion, purpose: purposeName,
      issuer_public_key_base64url: machinePin.toString('base64url'),
      payload_sha256: hash(bytes), payload_base64url: bytes.toString('base64url'),
      signature_base64url: sign(null, Buffer.concat([Buffer.from(purposeName + '\0'), bytes]),
        pair.privateKey).toString('base64url') });
  };
  const identity = Object.fromEntries(['profile_in_force', 'host_id', 'installation_id',
    'soul_id', 'start_id', 'hq_epoch'].map((field) => [field, payload[field]]));
  const runtimes = members.map((member) => ({ member_id: member.member_id,
    runtime_id: `runtime_${member.member_id}`, channel_binding: `binding_${member.member_id}` }));
  const map = { contract: 'hq/v1', kind: 'stage2a-provisional-member-map', schema_version: 1,
    ...identity, assignment_envelope_sha256: assignment.envelopeSha256,
    runtime_state: 'provisional', acp_authority: 'withheld',
    members: members.map((member, i) => ({ member_id: member.member_id,
      member_selector: member.member_selector, runtime_id: runtimes[i].runtime_id,
      channel_binding: runtimes[i].channel_binding })),
    issued_at: '2026-11-23T18:00:03Z', expires_at: '2026-11-23T18:00:19Z' };
  const observed = members.map((member, i) => ({ member_id: member.member_id,
    launch_id: member.launch_id, member_selector: member.member_selector,
    runtime_id: runtimes[i].runtime_id, grant_sha256: hash(`grant ${i}`),
    launcher_process: { pid: 4001 + i, uid: 331, gid: 331,
      start_seconds: 1795456803, start_micros: i },
    child_process: { pid: 4101 + i, uid: 331, gid: 331, parent_pid: 4001 + i,
      process_group_id: 4001 + i, start_seconds: 1795456804, start_micros: i,
      executable_sha256: member.command_sha256 } }));
  const child = { contract: 'machine/v3', kind: 'stage2a-member-set-child-observation',
    schema_version: 1, ...identity, reservation_sha256: reservation,
    assignment_envelope_sha256: assignment.envelopeSha256,
    provisional_hq_mapping_sha256: hash(jcs(map)), provisional_hq_mapping: map,
    members: observed, observed_at: '2026-11-23T18:00:04Z',
    issued_at: '2026-11-23T18:00:05Z', expires_at: '2026-11-23T18:00:19Z' };
  const childBytes = authority('agent-bot/stage2a-member-set-child-observation/v1', child);
  const policy = { contract: 'machine/v3', kind: 'stage2a-b-member-authority',
    schema_version: 1, ...identity, plan_id: payload.plan_id, plan_digest: payload.plan_digest,
    reservation_sha256: reservation,
    member_set_assignment_envelope_sha256: assignment.envelopeSha256,
    owner_plan_member_set_sha256: payload.owner_plan_member_set_sha256,
    b_authority: payload.b_authority, hq_uid: 309, runner_uid: 331, bridge: payload.bridge,
    members: members.map((member) => ({ member_id: member.member_id,
      launch_id: member.launch_id, member_selector: member.member_selector,
      adjacent_cli_path: member.adjacent_cli_path,
      adjacent_cli_sha256: member.adjacent_cli_sha256,
      qualification: { model: 'fixture', request_sha256: hash('request'),
        headers_sha256: hash('headers'), client_key_sha256: hash('key'),
        http_host: 'fixture.invalid', messages_query: '', response_text: 'fixture response' } })),
    issued_at: '2026-11-23T18:00:06Z', expires_at: '2026-11-23T18:00:19Z' };
  const policyBytes = authority('agent-bot/stage2a-b-member-authority/v1', policy);
  const readyRows = members.map((member, i) => {
    const arm = { member_id: member.member_id, member_selector: member.member_selector,
      runtime_id: runtimes[i].runtime_id,
      child_observation_envelope_sha256: hash(childBytes), bridge_uid: payload.bridge.uid,
      adapter_pid: observed[i].child_process.pid, adapter_uid: 331, adapter_gid: 331,
      adapter_start_seconds: observed[i].child_process.start_seconds,
      adapter_start_micros: observed[i].child_process.start_micros,
      relay_peer_rule: 'a-attested-live-direct-child-of-adapter-v1',
      relay_peer_state: 'unobserved', provider_ingress: 'withheld-pending-per-peer-attestation',
      state: 'armed', armed_at: '2026-11-23T18:00:07Z' };
    return { member_id: member.member_id, launch_id: member.launch_id,
      member_selector: member.member_selector, runtime_id: runtimes[i].runtime_id,
      bridge_arm: arm, bridge_arm_receipt_sha256: hash(jcs(arm)) };
  });
  const ready = { contract: 'machine/v3', kind: 'stage2a-member-set-ready',
    schema_version: 1, ...identity, reservation_sha256: reservation,
    assignment_envelope_sha256: assignment.envelopeSha256,
    child_observation_envelope_sha256: hash(childBytes),
    b_authority_sha256: payload.b_authority.envelope_sha256,
    member_b_authority_envelope_sha256: hash(policyBytes),
    provisional_hq_mapping_sha256: hash(jcs(map)),
    bridge_process: { pid: 3901, uid: payload.bridge.uid, gid: payload.bridge.gid,
      start_seconds: 1795456803, start_micros: 0, executable_sha256: hash('bridge') },
    members: readyRows, observed_at: '2026-11-23T18:00:07Z',
    issued_at: '2026-11-23T18:00:08Z', expires_at: '2026-11-23T18:00:18Z' };
  const readyBytes = authority('agent-bot/stage2a-member-set-ready/v1', ready);
  const memberEndpoint = { directory: '/fixture/member', owner_uid: 331, group_gid: 332,
    dir_mode: 0o2750, socket_mode: 0o660, peer_uids: [331, 332] };
  const start = { installationId: payload.installation_id, startId: payload.start_id,
    reservationSha256: reservation, machinePin, runnerUid: 331, runnerGid: 331, hqUid: 309,
    admissionSocket: '/fixture/admission.sock',
    memberEndpoint: { member_socket: '/fixture/member/one.sock', member_endpoint: memberEndpoint },
    launchInputRecords: { component_digests: { bridge: hash('bridge') } } };
  const result = { version: 'stage2a-member-attach/v1',
    installation_id: payload.installation_id, start_id: payload.start_id,
    member_id: members[0].member_id, member_selector: members[0].member_selector,
    runtime_id: runtimes[0].runtime_id, launch_id: members[0].launch_id,
    attach: 'a'.repeat(64), expires_at: '2026-11-23T18:00:17Z', cwd: '/fixture/home',
    member_socket: start.memberEndpoint.member_socket, member_endpoint: memberEndpoint,
    member_bridge_token: 'b'.repeat(48), bridge_ready_nonce: 'c'.repeat(64),
    runner_endpoint: { socketPath: start.admissionSocket, peerUid: 331,
      directory: '/fixture' },
    child_observation_envelope_base64url: childBytes.toString('base64url'),
    child_observation_envelope_sha256: hash(childBytes),
    member_b_authority_envelope_base64url: policyBytes.toString('base64url'),
    member_b_authority_envelope_sha256: hash(policyBytes),
    ready_envelope_base64url: readyBytes.toString('base64url'),
    ready_envelope_sha256: hash(readyBytes) };
  const at = Date.parse('2026-11-23T18:00:10Z');
  const verifyAttach = (candidate = result) => verifyMemberSetAttach(candidate,
    start, assignment, { admitted_runtimes: runtimes }, machinePin, at);
  assert.equal(verifyAttach().ready.members.length, 2);
  assert.throws(() => verifyAttach({ ...result, member_selector: members[1].member_selector }), /signed member or endpoint/);
  const badLauncherBytes = authority('agent-bot/stage2a-member-set-child-observation/v1', {
    ...child, members: [{ ...observed[0], launcher_process: {
      ...observed[0].launcher_process, start_micros: 1000000 } }, observed[1]] });
  const badReadyBytes = authority('agent-bot/stage2a-member-set-ready/v1', {
    ...ready, child_observation_envelope_sha256: hash(badLauncherBytes),
    members: readyRows.map((row) => {
      const bridge_arm = { ...row.bridge_arm,
        child_observation_envelope_sha256: hash(badLauncherBytes) };
      return { ...row, bridge_arm, bridge_arm_receipt_sha256: hash(jcs(bridge_arm)) };
    }),
  });
  assert.throws(() => verifyAttach({ ...result,
    child_observation_envelope_base64url: badLauncherBytes.toString('base64url'),
    child_observation_envelope_sha256: hash(badLauncherBytes),
    ready_envelope_base64url: badReadyBytes.toString('base64url'),
    ready_envelope_sha256: hash(badReadyBytes) }), /member child, B arm/);
  assert.throws(() => verifyAttach({ ...result, ready_envelope_sha256: hash('other') }), /envelope digest differs/);
  assert.throws(() => verifyAttach({ ...result, member_b_authority_envelope_sha256: hash('other') }), /envelope digest differs/);
  const wrongHostBytes = authority('agent-bot/stage2a-member-set-ready/v1', {
    ...ready, host_id: 'other-host' });
  assert.throws(() => verifyAttach({ ...result,
    ready_envelope_base64url: wrongHostBytes.toString('base64url'),
    ready_envelope_sha256: hash(wrongHostBytes) }), /differs from the signed assignment/);
  const wrongPolicy = JSON.parse(policyBytes.toString());
  wrongPolicy.signature_base64url = Buffer.alloc(64).toString('base64url');
  const wrongPolicyBytes = jcs(wrongPolicy);
  assert.throws(() => verifyAttach({ ...result,
    member_b_authority_envelope_base64url: wrongPolicyBytes.toString('base64url'),
    member_b_authority_envelope_sha256: hash(wrongPolicyBytes) }), /Machine signature is invalid/);
  const wrongReadyBytes = authority('agent-bot/stage2a-member-set-ready/v1', {
    ...ready, member_b_authority_envelope_sha256: hash('other') });
  assert.throws(() => verifyAttach({ ...result,
    ready_envelope_base64url: wrongReadyBytes.toString('base64url'),
    ready_envelope_sha256: hash(wrongReadyBytes) }), /evidence chain differs/);
  assert.throws(() => verifyMemberSetAttach(result, start, assignment,
    { admitted_runtimes: runtimes }, machinePin, Date.parse('2026-11-23T18:00:19Z')),
  /expired|stale|signed member or endpoint/);

  const cooperativeEndpoint = { directory: '/fixture/member',
    socket_path: '/fixture/member/one.sock', owner_uid: 331, group_gid: 332,
    dir_mode: 0o2750, socket_mode: 0o660, expected_peer_uid: 332,
    parent_device: '11', parent_inode: '12', parent_birthtime_ns: '13' };
  const cooperativeRelay = { ...cooperativeEndpoint, directory: '/fixture/relay',
    socket_path: '/fixture/relay/one.sock', owner_uid: 332, group_gid: 331,
    expected_peer_uid: 331, parent_device: '21', parent_inode: '22' };
  const cooperativeBridge = { ...payload.bridge, endpoints: {
    broker: { directory: '/fixture/broker', socket_path: '/fixture/broker/one.sock',
      owner_uid: 309, group_gid: 332, dir_mode: 0o2750, socket_mode: 0o660,
      expected_peer_uid: 332 },
    member: cooperativeEndpoint, relay: cooperativeRelay } };
  const cooperativePayload = { ...payload, profile_in_force: 'managed-cooperative',
    b_authority: { purpose: 'agent-bot/soul-cooperative-bridge-assignment/v3',
      envelope_sha256: reservation }, bridge: cooperativeBridge };
  const cooperativeAssignment = verify(cooperativePayload, { expected: {
    ...expected, profile_in_force: 'managed-cooperative', bridge_uid: 332,
    bridge_gid: 332, member_endpoint: cooperativeEndpoint,
    relay_endpoint: cooperativeRelay } });
  const cooperativeIdentity = { ...identity, profile_in_force: 'managed-cooperative' };
  const cooperativeMap = { ...map, ...cooperativeIdentity,
    assignment_envelope_sha256: cooperativeAssignment.envelopeSha256 };
  const cooperativeChild = { ...child, ...cooperativeIdentity,
    assignment_envelope_sha256: cooperativeAssignment.envelopeSha256,
    provisional_hq_mapping: cooperativeMap,
    provisional_hq_mapping_sha256: hash(jcs(cooperativeMap)) };
  const cooperativeChildBytes = authority('agent-bot/stage2a-member-set-child-observation/v1',
    cooperativeChild);
  const cooperativePolicy = { ...policy, ...cooperativeIdentity,
    member_set_assignment_envelope_sha256: cooperativeAssignment.envelopeSha256,
    b_authority: cooperativePayload.b_authority, bridge: cooperativeBridge };
  const cooperativePolicyBytes = authority('agent-bot/stage2a-b-member-authority/v1',
    cooperativePolicy);
  const cooperativeRows = readyRows.map((row) => {
    const bridge_arm = { ...row.bridge_arm,
      child_observation_envelope_sha256: hash(cooperativeChildBytes) };
    return { ...row, bridge_arm, bridge_arm_receipt_sha256: hash(jcs(bridge_arm)) };
  });
  const observedB = { contract: 'machine/v3', kind: 'soul-cooperative-b-observed',
    schema_version: 3, reservation_sha256: reservation,
    bridge_assignment_sha256: cooperativePayload.b_authority.envelope_sha256,
    bind_receipt_sha256: hash('H bind'), installation_id: payload.installation_id,
    start_id: payload.start_id, launch_id: `ln_${'3'.repeat(24)}`,
    plan_id: payload.plan_id, plan_digest: payload.plan_digest,
    hq_epoch: payload.hq_epoch, grant_nonce: Buffer.alloc(32, 1).toString('base64url'),
    launcher: { pid: 3901, uid: 332, gid: 332,
      start_seconds: 1795456803, start_micros: 0 },
    bridge: { pid: 3902, uid: 332, gid: 332,
      start_seconds: 1795456804, start_micros: 0 },
    relay_socket: { path: cooperativeRelay.socket_path,
      socket: { uid: 332, gid: 331, device: '21', inode: '22', mode: 0o660 } },
    relay_socket_birthtime_ns: '23', observed_at: '2026-11-23T18:00:08Z',
    expires_at: '2026-11-23T18:00:19Z' };
  const observedBBytes = authority('agent-bot/soul-cooperative-b-observed/v3', observedB, 3);
  const cooperativeReady = { contract: 'machine/v3', kind: 'soul-cooperative-member-ready',
    schema_version: 3, profile_in_force: 'managed-cooperative',
    host_id: payload.host_id, installation_id: payload.installation_id,
    start_id: payload.start_id, hq_epoch: payload.hq_epoch,
    reservation_sha256: reservation,
    assignment_envelope_sha256: cooperativeAssignment.envelopeSha256,
    child_observation_envelope_sha256: hash(cooperativeChildBytes),
    member_b_authority_envelope_sha256: hash(cooperativePolicyBytes),
    provisional_hq_mapping_sha256: hash(jcs(cooperativeMap)),
    bridge_observed_sha256: hash(observedBBytes),
    members: cooperativeRows.map((row, i) => ({ member_id: row.member_id,
      member_launch_id: row.launch_id, member_selector: row.member_selector,
      grant_sha256: observed[i].grant_sha256,
      launcher_process: observed[i].launcher_process,
      child_process: observed[i].child_process,
      h_observation_sha256: hash(`H observation ${i}`),
      b_arm_receipt_sha256: row.bridge_arm_receipt_sha256 })),
    issued_at: '2026-11-23T18:00:09Z', expires_at: '2026-11-23T18:00:17Z' };
  const cooperativeReadyBytes = authority('agent-bot/soul-cooperative-member-ready/v3',
    cooperativeReady, 3);
  const cooperativeResult = { ...result, member_socket: cooperativeEndpoint.socket_path,
    member_endpoint: cooperativeEndpoint,
    child_observation_envelope_base64url: cooperativeChildBytes.toString('base64url'),
    child_observation_envelope_sha256: hash(cooperativeChildBytes),
    member_b_authority_envelope_base64url: cooperativePolicyBytes.toString('base64url'),
    member_b_authority_envelope_sha256: hash(cooperativePolicyBytes),
    ready_envelope_base64url: cooperativeReadyBytes.toString('base64url'),
    ready_envelope_sha256: hash(cooperativeReadyBytes),
    bridge_observed_envelope_base64url: observedBBytes.toString('base64url'),
    bridge_arm_rows_base64url: cooperativeRows.map((row) =>
      jcs(row.bridge_arm).toString('base64url')) };
  const cooperativeStart = { ...start, adapterTransport: 'brokered-b',
    memberEndpoint: cooperativeEndpoint, memberSocket: cooperativeEndpoint.socket_path,
    relayEndpoint: cooperativeRelay, relaySocket: cooperativeRelay.socket_path,
    launchId: observedB.launch_id };
  const relayCheck = (candidateStart, identity) => {
    assert.equal(candidateStart, cooperativeStart);
    assert.deepEqual(identity, { path: cooperativeRelay.socket_path, uid: 332, gid: 331,
      mode: 0o660, device: '21', inode: '22', birthtime_ns: '23' });
  };
  const verifyCooperative = (candidate = cooperativeResult, candidateStart = cooperativeStart) =>
    verifyCooperativeMemberSetAttach(candidate, candidateStart, cooperativeAssignment,
      { admitted_runtimes: runtimes }, machinePin, at, relayCheck);
  assert.equal(verifyCooperative().ready.members.length, 2);
  assert.throws(() => verifyMemberSetAttach(cooperativeResult, cooperativeStart,
    cooperativeAssignment, { admitted_runtimes: runtimes }, machinePin, at),
  /endpoint parent is unavailable|relay socket is unavailable/);
  assert.throws(() => verifyCooperative({ ...cooperativeResult, member_endpoint: {
    ...cooperativeEndpoint, parent_inode: '99' } }), /signed member or endpoint/);
  assert.throws(() => verifyCooperative({ ...cooperativeResult,
    bridge_observed_envelope_base64url: observedBBytes.toString('base64url').slice(1) }),
  /envelope digest differs|canonical/);
  const wrongBBytes = authority('agent-bot/soul-cooperative-b-observed/v3', {
    ...observedB, relay_socket_birthtime_ns: '24' }, 3);
  assert.throws(() => verifyCooperative({ ...cooperativeResult,
    bridge_observed_envelope_base64url: wrongBBytes.toString('base64url') }),
  /envelope digest differs/);
  const signedChangedB = (change) => {
    const bytes = authority('agent-bot/soul-cooperative-b-observed/v3',
      { ...observedB, ...change }, 3);
    const updatedReadyBytes = authority('agent-bot/soul-cooperative-member-ready/v3',
      { ...cooperativeReady, bridge_observed_sha256: hash(bytes) }, 3);
    return { ...cooperativeResult,
      bridge_observed_envelope_base64url: bytes.toString('base64url'),
      ready_envelope_base64url: updatedReadyBytes.toString('base64url'),
      ready_envelope_sha256: hash(updatedReadyBytes) };
  };
  assert.throws(() => verifyCooperative(signedChangedB({ installation_id: 'inst_other' })),
    /B observation differs/);
  assert.throws(() => verifyCooperative(signedChangedB({ launcher: {
    ...observedB.launcher, uid: 331, gid: 331 } })), /A-observed B process/);
  assert.throws(() => verifyCooperative(signedChangedB({ expires_at: '2026-11-23T18:00:10Z' })),
    /expired or stale|exceeds signed/);
  assert.throws(() => verifyCooperative(signedChangedB({ relay_socket_birthtime_ns: '24' })),
    /Expected values to be strictly deep-equal/);
  const wrongHostReady = authority('agent-bot/soul-cooperative-member-ready/v3',
    { ...cooperativeReady, host_id: 'host_other' }, 3);
  assert.throws(() => verifyCooperative({ ...cooperativeResult,
    ready_envelope_base64url: wrongHostReady.toString('base64url'),
    ready_envelope_sha256: hash(wrongHostReady) }), /Ready or B observation differs/);
  const otherArm = { ...cooperativeRows[0].bridge_arm, adapter_pid: 9999 };
  assert.throws(() => verifyCooperative({ ...cooperativeResult,
    bridge_arm_rows_base64url: [jcs(otherArm).toString('base64url'),
      cooperativeResult.bridge_arm_rows_base64url[1]] }), /member child, B arm/);
  assert.throws(() => verifyCooperative({ ...cooperativeResult,
    bridge_arm_rows_base64url: [...cooperativeResult.bridge_arm_rows_base64url].reverse() }),
  /member child, B arm/);
  assert.throws(() => verifyCooperative({ ...cooperativeResult,
    bridge_arm_rows_base64url: cooperativeResult.bridge_arm_rows_base64url.slice(0, 1) }),
  /member rows/);
  assert.throws(() => verifyCooperative({ ...cooperativeResult,
    bridge_arm_rows_base64url: [cooperativeResult.bridge_arm_rows_base64url[0],
      cooperativeResult.bridge_arm_rows_base64url[1] + '='] }), /noncanonical base64url/);
  // Keep all grown strings within their published schema maxima while
  // measuring the complete encoded H result at the exact profile cap.
  const longPolicy = { ...cooperativePolicy, members: cooperativePolicy.members.map((row) => ({
    ...row, qualification: { ...row.qualification, response_text: 'x'.repeat(2048) } })) };
  const longPolicyBytes = authority('agent-bot/stage2a-b-member-authority/v1', longPolicy);
  const longReadyBytes = authority('agent-bot/soul-cooperative-member-ready/v3', {
    ...cooperativeReady, member_b_authority_envelope_sha256: hash(longPolicyBytes) }, 3);
  const baseBoundary = { ...cooperativeResult,
    member_b_authority_envelope_base64url: longPolicyBytes.toString('base64url'),
    member_b_authority_envelope_sha256: hash(longPolicyBytes),
    ready_envelope_base64url: longReadyBytes.toString('base64url'),
    ready_envelope_sha256: hash(longReadyBytes) };
  const withDirectory = (length) => {
    const directory = '/fixture/' + 'd'.repeat(length);
    const socketPath = directory + '/a.sock';
    return { result: { ...baseBoundary, runner_endpoint: {
      socketPath, peerUid: 331, directory } },
    start: { ...cooperativeStart, admissionSocket: socketPath } };
  };
  let low = 0; let high = 4000;
  while (low < high) {
    const mid = Math.ceil((low + high) / 2);
    if (Buffer.byteLength(canonicalize(withDirectory(mid).result)) <= 32768) low = mid;
    else high = mid - 1;
  }
  const nearCap = withDirectory(low);
  const headroom = 32768 - Buffer.byteLength(canonicalize(nearCap.result));
  assert.ok(headroom >= 0 && headroom <= 4096 - nearCap.result.cwd.length);
  const atCap = { ...nearCap.result, cwd: nearCap.result.cwd + 'x'.repeat(headroom) };
  assert.equal(Buffer.byteLength(canonicalize(atCap)), 32768);
  const verifyAtCap = (candidate) => verifyCooperativeMemberSetAttach(candidate,
    nearCap.start, cooperativeAssignment, { admitted_runtimes: runtimes }, machinePin, at,
    (_candidateStart, identity) => assert.equal(identity.birthtime_ns, '23'));
  assert.equal(verifyAtCap(atCap).ready.kind, 'soul-cooperative-member-ready');
  assert.throws(() => verifyAtCap({ ...atCap, cwd: atCap.cwd + 'x' }),
    /invalid cooperative H attach result/);
  assert.throws(() => verifyCooperative(cooperativeResult, {
    ...cooperativeStart, startId: `st_${'9'.repeat(24)}` }), /invalid cooperative H attach result/);
});
