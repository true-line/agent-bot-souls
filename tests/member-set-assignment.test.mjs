import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { canonicalize } from '../lib/contracts.mjs';
import { verifyMemberSetAdmission, verifyMemberSetAssignment, verifyMemberSetLaunch } from '../lib/member-set-assignment.mjs';

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
