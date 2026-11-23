// An A-signed member set is a pre-launch claim. It never makes a runtime
// usable or permits ACP input; HQ must separately prove observed children and
// the armed bridge before finalizing Hello.
import { createHash, createPublicKey, verify } from 'node:crypto';
import { basename, dirname, join } from 'node:path';
import { canonicalize, parseStrict } from './contracts.mjs';

const PURPOSE = 'agent-bot/stage2a-member-set-assignment/v1';
const SHA = /^sha256:[0-9a-f]{64}$/;
const FIELDS = ['schema_version', 'purpose', 'issuer_public_key_base64url',
  'payload_sha256', 'payload_base64url', 'signature_base64url'];
const PAYLOAD = ['contract', 'kind', 'schema_version', 'profile_in_force', 'host_id',
  'installation_id', 'soul_id', 'start_id', 'hq_epoch', 'plan_id', 'plan_digest',
  'owner_plan_member_set_sha256', 'reservation_sha256', 'b_authority',
  'soul_artifact_sha256', 'frozen_soul_info_sha256', 'adapter_manifest_relpath',
  'frozen_adapter_manifest_sha256', 'host_projection_sha256',
  'definition_measurement', 'runner_uid', 'runner_gid', 'bridge', 'members',
  'issued_at', 'expires_at'];
const MEMBER = ['member_id', 'role', 'adapter_id', 'adapter_version', 'command_path',
  'command_sha256', 'adjacent_cli_path', 'adjacent_cli_sha256', 'launch_id',
  'member_selector'];
const bad = (message) => { throw new Error(`member-set assignment: ${message}`); };
const exact = (value, fields) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === fields.length && fields.every((field) => Object.hasOwn(value, field));
const sha = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const bytesOf = (value, length) => {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) bad('invalid base64url');
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.toString('base64url') !== value || (length !== undefined && bytes.length !== length)) bad('invalid base64url');
  return bytes;
};
const jcs = (bytes) => {
  let text, value;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    value = parseStrict(text);
  } catch { return bad('invalid signed JSON'); }
  if (canonicalize(value) !== text) bad('signed JSON is not canonical');
  return value;
};

// `expected` comes from the authenticated one-use Machine reservation and
// owner-reviewed installed plan. `frozen` comes from the measured snapshots,
// not a member-controlled path. This function deliberately has no IO.
export function verifyMemberSetAssignment({ envelopeBytes, machinePin, expected, frozen,
  now = Date.now() }) {
  if (!Buffer.isBuffer(envelopeBytes) || envelopeBytes.length < 1 || envelopeBytes.length > 32768
    || !Buffer.isBuffer(machinePin) || machinePin.length !== 32) bad('signed input is unavailable');
  const envelope = jcs(envelopeBytes);
  if (!exact(envelope, FIELDS) || envelope.schema_version !== 1 || envelope.purpose !== PURPOSE
    || !SHA.test(envelope.payload_sha256)) bad('unsupported envelope');
  if (!bytesOf(envelope.issuer_public_key_base64url, 32).equals(machinePin)) bad('signer differs from Machine pin');
  const payloadBytes = bytesOf(envelope.payload_base64url);
  if (sha(payloadBytes) !== envelope.payload_sha256) bad('payload digest differs');
  const key = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), machinePin]),
    format: 'der', type: 'spki' });
  if (!verify(null, Buffer.concat([Buffer.from(PURPOSE + '\0'), payloadBytes]), key,
    bytesOf(envelope.signature_base64url, 64))) bad('signature is invalid');
  const payload = jcs(payloadBytes);
  if (!exact(payload, PAYLOAD) || payload.contract !== 'machine/v3'
    || payload.kind !== 'stage2a-member-set-assignment' || payload.schema_version !== 1
    || !Array.isArray(payload.members) || payload.members.length !== 2
    || !payload.members.every((m) => exact(m, MEMBER))) bad('invalid payload shape');
  for (const field of ['profile_in_force', 'host_id', 'installation_id', 'soul_id',
    'start_id', 'hq_epoch', 'plan_id', 'plan_digest', 'reservation_sha256',
    'soul_artifact_sha256', 'definition_measurement', 'runner_uid', 'runner_gid']) {
    if (payload[field] !== expected?.[field]) bad(`${field} differs from the reviewed start`);
  }
  // A checked the installed owner plan before signing. R independently
  // recomputes this digest from its measured eight-field member projection
  // below; an unsigned copy of the digest on fd3 would add no authority.
  if (!SHA.test(payload.owner_plan_member_set_sha256 ?? '')) bad('owner-plan member digest is invalid');
  const issued = Date.parse(payload.issued_at);
  const expires = Date.parse(payload.expires_at);
  if (!Number.isFinite(now) || !Number.isFinite(issued) || !Number.isFinite(expires)
    || issued > now || expires <= now || expires <= issued || expires - issued > 30000) {
    bad('assignment is expired or has an invalid lifetime');
  }
  if (!exact(payload.b_authority, ['purpose', 'envelope_sha256'])
    || payload.b_authority.purpose !== (payload.profile_in_force === 'managed-protected'
      ? 'agent-bot/stage2a-reservation/v3' : 'agent-bot/soul-cooperative-bridge-assignment/v3')
    || payload.b_authority.envelope_sha256 !== expected?.b_authority_sha256) {
    bad('B authority differs from the reviewed start');
  }
  if (!expected?.bridge || canonicalize(payload.bridge) !== canonicalize(expected.bridge)) {
    bad('bridge differs from the reviewed start');
  }
  if (!Buffer.isBuffer(frozen?.soulInfoBytes) || !Buffer.isBuffer(frozen?.adapterManifestBytes)
    || sha(frozen.soulInfoBytes) !== payload.frozen_soul_info_sha256
    || sha(frozen.adapterManifestBytes) !== payload.frozen_adapter_manifest_sha256
    || payload.adapter_manifest_relpath !== 'Contents/opt/stock-claude.json'
    || sha(Buffer.from(canonicalize(frozen.hostProjection))) !== payload.host_projection_sha256
    || payload.definition_measurement !== frozen.definitionMeasurement) {
    bad('assignment differs from frozen measured inputs');
  }
  let info, manifest;
  try { info = parseStrict(frozen.soulInfoBytes); manifest = parseStrict(frozen.adapterManifestBytes); }
  catch { return bad('frozen source JSON is invalid'); }
  if (info.soul_id !== payload.soul_id || !Array.isArray(info.members) || info.members.length !== 2
    || info.members.some((member) => member.fallbacks !== undefined)
    || manifest.adapter_id !== 'claude-code' || manifest.executable !== 'claude-agent-acp'
    || manifest.adjacent_cli !== 'claude'
    || !SHA.test(manifest.executable_sha256 ?? '') || !SHA.test(manifest.adjacent_cli_sha256 ?? '')) {
    bad('frozen stock adapter declaration is invalid');
  }
  const sorted = [...info.members].sort((a, b) => Buffer.compare(Buffer.from(a.member_id), Buffer.from(b.member_id)));
  const projection = [];
  for (const [i, member] of payload.members.entries()) {
    const declared = sorted[i];
    const adapter = frozen.hostProjection?.adapters?.[member.adapter_id];
    if (!declared || member.member_id !== declared.member_id || member.role !== declared.role
      || member.adapter_id !== declared.adapter_id || member.adapter_version !== declared.adapter_version
      || member.adapter_id !== manifest.adapter_id || member.adapter_version !== manifest.adapter_version
      || !Array.isArray(adapter?.command) || adapter.command.length !== 1
      || adapter.command[0] !== member.command_path || Object.keys(adapter.env ?? {}).length !== 0
      || basename(member.command_path) !== manifest.executable
      || member.adjacent_cli_path !== join(dirname(member.command_path), manifest.adjacent_cli)
      || member.command_sha256 !== manifest.executable_sha256
      || member.adjacent_cli_sha256 !== manifest.adjacent_cli_sha256
      || frozen.files?.get(member.command_path) !== member.command_sha256
      || frozen.files?.get(member.adjacent_cli_path) !== member.adjacent_cli_sha256) {
      bad(`member ${i} differs from measured stock files`);
    }
    const selector = 'mb_' + createHash('sha256').update('agent-bot/stage2a-member-selector/v1\0')
      .update(payload.reservation_sha256).update('\0').update(member.member_id).update('\0')
      .update(member.launch_id).digest('hex');
    if (member.member_selector !== selector) bad('member selector differs from assignment');
    projection.push(Object.fromEntries(['member_id', 'role', 'adapter_id', 'adapter_version',
      'command_path', 'command_sha256', 'adjacent_cli_path', 'adjacent_cli_sha256']
      .map((field) => [field, member[field]])));
  }
  if (payload.members[0].member_id >= payload.members[1].member_id
    || payload.members.filter((m) => m.role === 'lead').length !== 1
    || payload.members[0].launch_id === payload.members[1].launch_id
    || payload.members[0].member_selector === payload.members[1].member_selector
    || sha(Buffer.from(canonicalize(projection))) !== payload.owner_plan_member_set_sha256) {
    bad('member set is not the exact owner-reviewed projection');
  }
  return Object.freeze({ payload: Object.freeze(payload), envelopeSha256: sha(envelopeBytes) });
}
