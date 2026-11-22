import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { once } from 'node:events';
import { test } from 'node:test';
import { canonicalize } from '../lib/contracts.mjs';
import { MACHINE_PIN, verifyProtectedStart } from '../lib/protected-start.mjs';
import { BIN } from './harness.mjs';

const ROOT = '/tmp/stage2a-frozen.soul';
const APPROVED_SOURCE = '/tmp/stage2a-approved-source.soul';
const INSTALLATION = 'inst_fixture';
const START = 'st_' + 'a1'.repeat(12);
const LAUNCH = 'ln_' + 'b2'.repeat(12);
const EPOCH = 'c3'.repeat(32);
const PURPOSE = 'agent-bot/stage2a-reservation/v2';
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const digest = (bytes) => 'sha256:' + hash(bytes);
const account = '_abm-sr-' + hash(INSTALLATION).slice(0, 20);
const stateRoot = '/var/agent-bot-soul-runner-' + account + '/state';
const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const pin = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
const b64 = (bytes) => Buffer.from(bytes).toString('base64url');
const records = { files: [], host_projection: {}, selected_command: '/tmp/adapter',
  argv: ['/tmp/adapter'], environment: {}, effective_config: {}, system_images: {},
  sandbox_policy_digest: digest('policy'), component_digests: {} };
const launchMeasurement = digest(Buffer.concat([
  Buffer.from('agent-bot/stage2a-launch-inputs/v1\0'), Buffer.from(canonicalize(records)),
]));

function signedStart(now = Date.now()) {
  const issued = new Date(now - 1000).toISOString();
  const expires = new Date(now + 20_000).toISOString();
  const member = { directory: '/tmp/member', socket_path: '/tmp/member/one.sock',
    owner_uid: process.getuid(), group_gid: process.getgid(), dir_mode: 0o2750,
    socket_mode: 0o660, peer_uids: [process.getuid(), process.getuid() + 1] };
  const payload = {
    contract: 'machine/v2', kind: 'stage2a-reservation', schema_version: 2,
    host_id: 'host_fixture', issued_at: issued, expires_at: expires,
    installed_plan_receipt_sha256: digest('receipt'),
    assignment: {
      schema: 'agent-bot-machine/soul-start-assignment/v2',
      installation_id: INSTALLATION, soul_id: 'agent_11111111-1111-1111-1111-111111111111',
      start_id: START, launch_id: LAUNCH, hq_epoch: EPOCH,
      plan_id: 'plan_fixture', plan_digest: hash('plan'),
      package_sha256: hash('package'), soul_artifact_sha256: hash('soul'),
      package_root: APPROVED_SOURCE, runner_uid: process.getuid(), runner_gid: process.getgid(),
      machine_uid: process.getuid() + 1000, runner_account: account,
      expires_at: expires, admission: { socket_path: '/tmp/admission.sock' },
      relay: { socket_path: '/tmp/relay.sock' }, member,
    },
    member_endpoint: { member_socket: member.socket_path,
      member_endpoint: { directory: member.directory, owner_uid: member.owner_uid,
        group_gid: member.group_gid, dir_mode: member.dir_mode, socket_mode: member.socket_mode,
        peer_uids: member.peer_uids } },
    measurement_binding: {
      contract: 'machine/v2', kind: 'stage2a-measurement-binding', schema_version: 2,
      host_id: 'host_fixture', installation_id: INSTALLATION,
      soul_id: 'agent_11111111-1111-1111-1111-111111111111',
      start_id: START, launch_id: LAUNCH, hq_epoch: EPOCH,
      plan_id: 'plan_fixture', installed_plan_digest: hash('plan'),
      package_sha256: hash('package'), soul_artifact_sha256: hash('soul'),
      profile_in_force: 'managed-protected',
      claimed_definition_digest: digest('claim'), definition_measurement: digest('definition'),
      launch_input_measurement: launchMeasurement,
      snapshots: {
        definition: { root_path: ROOT, owner_uid: process.getuid() + 1000, owner_gid: process.getgid() },
        launch_inputs: { root_path: '/tmp/launch-inputs', owner_uid: process.getuid() + 1000, owner_gid: process.getgid() },
      },
    },
    admission_challenge_sha256: digest('challenge'),
  };
  const payloadBytes = Buffer.from(canonicalize(payload));
  const envelope = {
    schema_version: 2, purpose: PURPOSE,
    issuer_public_key_base64url: b64(pin), payload_sha256: digest(payloadBytes),
    payload_base64url: b64(payloadBytes),
    signature_base64url: b64(sign(null, Buffer.concat([Buffer.from(PURPOSE + '\0'), payloadBytes]), privateKey)),
  };
  const envelopeBytes = Buffer.from(canonicalize(envelope));
  const input = { schema: 'agent-bot-souls/protected-start/v1',
    reservation_envelope_base64url: b64(envelopeBytes),
    reservation_sha256: digest(envelopeBytes), machine_pin_path: MACHINE_PIN,
    launch_input_records: records, state_root: stateRoot };
  return { input, payload, envelope, now };
}

test('signed fd 3 handoff binds frozen measurements, dedicated runner and exact sockets', () => {
  const { input, payload, now } = signedStart();
  const start = verifyProtectedStart(input, ROOT, pin, now);
  assert.equal(start.stateRoot, stateRoot);
  assert.equal(start.launchInputMeasurement, launchMeasurement);
  assert.equal(start.admissionSocket, '/tmp/admission.sock');
  assert.equal(start.brokerSocket, '/tmp/relay.sock');
  assert.equal(start.reservationSha256, input.reservation_sha256);
  assert.notEqual(payload?.assignment?.package_root, ROOT);
});

test('signed handoff refuses altered records, wrong signer, stale start, wrong identity and host', () => {
  const { input, payload, envelope, now } = signedStart();
  assert.throws(() => verifyProtectedStart({ ...input, launch_input_records: { ...records, argv: ['/tmp/other'] } }, ROOT, pin, now), /launch input records differ/);
  assert.throws(() => verifyProtectedStart({ ...input, unreviewed: true }, ROOT, pin, now), /invalid fd 3 input fields/);
  assert.throws(() => verifyProtectedStart(input, ROOT, Buffer.alloc(32), now), /signer differs/);
  assert.throws(() => verifyProtectedStart(input, ROOT, pin, now + 30_000), /live runner/);
  assert.throws(() => verifyProtectedStart(input, '/tmp/other.soul', pin, now), /live runner/);
  assert.throws(() => verifyProtectedStart({ ...input, state_root: '/tmp/other/state' }, ROOT, pin, now), /live runner/);
  const altered = { ...envelope, signature_base64url: b64(Buffer.alloc(64)) };
  const bytes = Buffer.from(canonicalize(altered));
  assert.throws(() => verifyProtectedStart({ ...input, reservation_envelope_base64url: b64(bytes),
    reservation_sha256: digest(bytes) }, ROOT, pin, now), /invalid reservation signature/);
  const otherHost = { ...payload, measurement_binding: { ...payload.measurement_binding, host_id: 'other_host' } };
  const signedOtherHost = Buffer.from(canonicalize(otherHost));
  const otherEnvelope = { ...envelope, payload_base64url: b64(signedOtherHost),
    payload_sha256: digest(signedOtherHost),
    signature_base64url: b64(sign(null, Buffer.concat([Buffer.from(PURPOSE + '\0'), signedOtherHost]), privateKey)) };
  const otherBytes = Buffer.from(canonicalize(otherEnvelope));
  assert.throws(() => verifyProtectedStart({ ...input, reservation_envelope_base64url: b64(otherBytes),
    reservation_sha256: digest(otherBytes) }, ROOT, pin, now), /live runner/);
});

test('run reads a bounded strict fd 3 pipe before touching ACP stdout', async () => {
  const pipeExec = [
    'import os, sys',
    'read_fd, write_fd = os.pipe()',
    'pid = os.fork()',
    'if pid == 0:',
    '    os.close(write_fd)',
    '    os.dup2(read_fd, 3)',
    '    os.set_inheritable(3, True)',
    '    os.execv(sys.argv[1], sys.argv[1:])',
    'os.close(read_fd)',
    'os.write(write_fd, b\'{"schema":"a","schema":"b"}\')',
    'os.close(write_fd)',
    '_, status = os.waitpid(pid, 0)',
    'os._exit(os.waitstatus_to_exitcode(status))',
  ].join('\n');
  const child = spawn('/usr/bin/python3', ['-c', pipeExec, process.execPath, BIN, 'run', '--soul', ROOT,
    '--admission-socket', '/tmp/admission.sock', '--broker-socket', '/tmp/relay.sock',
    '--profile', 'managed-protected', '--protected-start-fd', '3'],
  { stdio: ['ignore', 'pipe', 'pipe'] });
  const exited = once(child, 'exit');
  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8').on('data', chunk => { stdout += chunk; });
  child.stderr.setEncoding('utf8').on('data', chunk => { stderr += chunk; });
  const [code] = await exited;
  assert.equal(code, 1);
  assert.equal(stdout, '');
  assert.match(stderr, /fd 3 is invalid UTF-8 JSON.*duplicate key/);
});
