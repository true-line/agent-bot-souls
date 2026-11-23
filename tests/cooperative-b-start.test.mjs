import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { chmodSync, lstatSync, mkdtempSync, mkdirSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { createServer } from 'node:net';
import { join } from 'node:path';
import { test } from 'node:test';
import { canonicalize } from '../lib/contracts.mjs';
import { attachCooperative, verifyCooperativeBMemberPath, verifyCooperativeBParents, verifyCooperativeBPublishOutcome, verifyCooperativeBRelaySocket, verifyCooperativeStart } from '../lib/cooperative-start.mjs';
import { MACHINE_PIN } from '../lib/protected-start.mjs';

const vector = JSON.parse(readFileSync(new URL('./fixtures/cooperative-start-b.synthetic.json', import.meta.url)));
const envelope = JSON.parse(vector.reservation_envelope_jcs);
const payload = JSON.parse(Buffer.from(envelope.payload_base64url, 'base64url').toString());
const pin = Buffer.from(vector.issuer_public_key_base64url, 'base64url');
const now = Date.parse('2026-11-22T14:15:20Z');
const identity = { uid: 331, euid: 331, gid: 331, egid: 331 };
const sha = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

function fd3(bytes = Buffer.from(vector.reservation_envelope_jcs)) {
  return {
    schema: 'agent-bot-souls/cooperative-start/v2',
    reservation_envelope_base64url: bytes.toString('base64url'),
    reservation_sha256: sha(bytes),
    machine_pin_path: MACHINE_PIN,
    launch_input_records: structuredClone(vector.launch_input_records),
    state_root: payload.assignment.state_root,
    admission_challenge_base64url: vector.admission_challenge_base64url,
    member_socket_path: payload.endpoints.member.socket_path,
    relay_socket_path: payload.endpoints.relay.socket_path,
    publish_outcome_envelope_base64url: 'AA',
    request_identity: { device: '12', inode: '345', birthtime_ns: '6789',
      owner_uid: payload.assignment.machine_uid, group_gid: payload.assignment.runner_gid, mode: 0o640 },
  };
}

function resigned(change) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const changed = structuredClone(payload);
  change(changed);
  const bytes = Buffer.from(canonicalize(changed));
  const rawPin = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  const signed = {
    ...envelope,
    issuer_public_key_base64url: rawPin.toString('base64url'),
    payload_sha256: sha(bytes),
    payload_base64url: bytes.toString('base64url'),
    signature_base64url: sign(null, Buffer.concat([Buffer.from(`${envelope.purpose}\0`), bytes]), privateKey).toString('base64url'),
  };
  return { value: fd3(Buffer.from(canonicalize(signed))), pin: rawPin, privateKey };
}

function publishOutcome(reservation, change = () => {}) {
  const start = verifyCooperativeStart(reservation.value, payload.assignment.package_root,
    reservation.pin, now, identity);
  const request = structuredClone(reservation.value);
  delete request.member_socket_path;
  delete request.relay_socket_path;
  delete request.publish_outcome_envelope_base64url;
  delete request.request_identity;
  request.schema = 'agent-bot-souls/cooperative-start/v1';
  const requestBytes = Buffer.from(canonicalize(request));
  const requestIdentity = { device: '12', inode: '345', birthtime_ns: '6789' };
  const outcome = {
    contract: 'machine/v3', kind: 'soul-cooperative-publish-outcome', schema_version: 3,
    reservation_sha256: start.reservationSha256,
    bridge_assignment_sha256: `sha256:${'c'.repeat(64)}`,
    order_sha256: `sha256:${'d'.repeat(64)}`,
    request_sha256: sha(requestBytes),
    request_device: requestIdentity.device, request_inode: requestIdentity.inode,
    request_birthtime_ns: requestIdentity.birthtime_ns,
    installation_id: start.installationId, start_id: start.startId, launch_id: start.launchId,
    published_at: '2026-11-22T14:15:19Z', expires_at: '2026-11-22T14:15:35Z',
  };
  change(outcome);
  const payloadBytes = Buffer.from(canonicalize(outcome));
  const signed = {
    schema_version: 3, purpose: 'agent-bot/soul-cooperative-publish-outcome/v3',
    issuer_public_key_base64url: reservation.pin.toString('base64url'),
    payload_sha256: sha(payloadBytes), payload_base64url: payloadBytes.toString('base64url'),
    signature_base64url: sign(null, Buffer.concat([
      Buffer.from('agent-bot/soul-cooperative-publish-outcome/v3\0'), payloadBytes,
    ]), reservation.privateKey).toString('base64url'),
  };
  return { value: { ...reservation.value,
    publish_outcome_envelope_base64url: Buffer.from(canonicalize(signed)).toString('base64url') },
    requestBytes, requestIdentity, start };
}

test('B publication requires a separate pinned, signed outcome for the exact request inode', () => {
  const reservation = resigned(() => {});
  const valid = publishOutcome(reservation);
  const verify = (x = valid, pin = reservation.pin, at = now) =>
    verifyCooperativeBPublishOutcome(x.value, x.start, pin, at);
  assert.equal(verify().request_inode, valid.requestIdentity.inode);
  assert.throws(() => verify({ ...valid, value: { ...valid.value, state_root: '/wrong/state' } }),
    /observed request and signed start/);
  assert.throws(() => verify({ ...valid, value: { ...valid.value,
    request_identity: { ...valid.value.request_identity, inode: '346' } } }),
    /observed request and signed start/);
  assert.throws(() => verify(valid, Buffer.alloc(32)), /signer differs/);
  assert.throws(() => verify(valid, reservation.pin, Date.parse('2026-11-22T14:15:35Z')),
    /observed request and signed start/);
  const wrongLaunch = publishOutcome(reservation, (outcome) => { outcome.launch_id = 'ln_ffffffffffffffffffffffff'; });
  assert.throws(() => verify(wrongLaunch), /observed request and signed start/);
  const alteredEnvelope = Buffer.from(valid.value.publish_outcome_envelope_base64url, 'base64url');
  alteredEnvelope[alteredEnvelope.length - 2] ^= 1;
  assert.throws(() => verify({ ...valid, value: { ...valid.value,
    publish_outcome_envelope_base64url: alteredEnvelope.toString('base64url') } }));
});

test('Contracts #78 B reservation binds only R-visible member, relay and bridge commitment', () => {
  const plan = verifyCooperativeStart(fd3(), payload.assignment.package_root, pin, now, identity);
  assert.equal(plan.adapterTransport, 'brokered-b');
  assert.equal(plan.memberSocket, payload.endpoints.member.socket_path);
  assert.equal(plan.relaySocket, payload.endpoints.relay.socket_path);
  assert.equal(plan.bridgeLaunchSha256, payload.bridge_launch_sha256);
  assert.equal(plan.brokerSocket, undefined);
  assert.equal(payload.endpoints.member.expected_peer_uid, 333);
});

test('B FD3 refuses altered endpoints, commitment and private bridge data', () => {
  const member = fd3();
  member.member_socket_path = '/wrong/member.sock';
  assert.throws(() => verifyCooperativeStart(member, payload.assignment.package_root, pin, now, identity), /reservation does not bind/);
  const relay = fd3();
  relay.relay_socket_path = '/wrong/relay.sock';
  assert.throws(() => verifyCooperativeStart(relay, payload.assignment.package_root, pin, now, identity), /reservation does not bind/);
  const commitment = fd3();
  commitment.launch_input_records.bridge_launch_sha256 = `sha256:${'a'.repeat(64)}`;
  assert.throws(() => verifyCooperativeStart(commitment, payload.assignment.package_root, pin, now, identity), /adapter transport differs/);
  const privateAssignment = fd3();
  privateAssignment.bridge_assignment = {};
  assert.throws(() => verifyCooperativeStart(privateAssignment, payload.assignment.package_root, pin, now, identity), /invalid fd 3 input fields/);
});

test('B reservation refuses signed wrong bridge UID, endpoint derivation and host', () => {
  const uid = resigned((changed) => { changed.endpoints.member.expected_peer_uid = 602; });
  assert.throws(() => verifyCooperativeStart(uid.value, payload.assignment.package_root, uid.pin, now, identity), /reservation does not bind/);
  const path = resigned((changed) => { changed.endpoints.member.socket_path = '/private/var/run/agent-bot/member/wrong.sock'; });
  assert.throws(() => verifyCooperativeStart(path.value, payload.assignment.package_root, path.pin, now, identity), /reservation does not bind/);
  const host = resigned((changed) => { changed.host_id = 'wrong-host'; });
  assert.throws(() => verifyCooperativeStart(host.value, payload.assignment.package_root, host.pin, now, identity), /reservation does not bind/);
});

test('B reservation refuses wrong runner identity and expired signed lease', () => {
  assert.throws(() => verifyCooperativeStart(fd3(), payload.assignment.package_root, pin, now,
    { ...identity, uid: 332, euid: 332 }), /reservation does not bind/);
  assert.throws(() => verifyCooperativeStart(fd3(), payload.assignment.package_root, pin,
    Date.parse(payload.expires_at) + 1, identity), /reservation does not bind/);
});

test('B parent recheck refuses a changed inode, mode or symlink before launch', () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'souls-b-parents-')));
  try {
    const member = join(root, 'member');
    const relay = join(root, 'relay');
    mkdirSync(member);
    mkdirSync(relay);
    chmodSync(member, 0o2750);
    chmodSync(relay, 0o2750);
    const observed = (directory) => {
      const st = lstatSync(directory, { bigint: true });
      return { directory, owner_uid: Number(st.uid), group_gid: Number(st.gid),
        parent_device: st.dev.toString(), parent_inode: st.ino.toString(),
        parent_birthtime_ns: st.birthtimeNs.toString() };
    };
    const start = { adapterTransport: 'brokered-b', memberEndpoint: observed(member), relayEndpoint: observed(relay) };
    assert.doesNotThrow(() => verifyCooperativeBParents(start));
    start.memberEndpoint.parent_inode = '1';
    assert.throws(() => verifyCooperativeBParents(start), /parent differs/);
    start.memberEndpoint = observed(member);
    chmodSync(relay, 0o750);
    assert.throws(() => verifyCooperativeBParents(start), /parent differs/);
    chmodSync(relay, 0o2750);
    const linked = join(root, 'linked');
    symlinkSync(member, linked);
    start.memberEndpoint = { ...observed(member), directory: linked };
    assert.throws(() => verifyCooperativeBParents(start), /parent differs/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('B member socket refuses any pre-existing assigned leaf', () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'souls-b-member-leaf-')));
  try {
    const memberSocket = join(root, 'member.sock');
    const start = { adapterTransport: 'brokered-b', memberSocket,
      memberEndpoint: { socket_path: memberSocket } };
    assert.equal(verifyCooperativeBMemberPath(start), memberSocket);
    writeFileSync(memberSocket, 'occupied');
    assert.throws(() => verifyCooperativeBMemberPath(start), /path is occupied/);
    assert.equal(readFileSync(memberSocket, 'utf8'), 'occupied');
    assert.throws(() => verifyCooperativeBMemberPath({ ...start, memberSocket: join(root, 'other.sock') }),
      /socket is unavailable/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('B relay refuses changed live socket identity before attach', async () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'sb-relay-')));
  const server = createServer();
  try {
    const member = join(root, 'member');
    const relay = join(root, 'relay');
    mkdirSync(member);
    mkdirSync(relay);
    chmodSync(member, 0o2750);
    chmodSync(relay, 0o2750);
    const parent = (directory) => {
      const st = lstatSync(directory, { bigint: true });
      return { directory, owner_uid: Number(st.uid), group_gid: Number(st.gid),
        parent_device: st.dev.toString(), parent_inode: st.ino.toString(),
        parent_birthtime_ns: st.birthtimeNs.toString() };
    };
    const path = join(relay, 's.sock');
    const start = { adapterTransport: 'brokered-b', relaySocket: path,
      memberEndpoint: parent(member), relayEndpoint: {
        ...parent(relay), socket_path: path, socket_mode: 0o660,
      } };
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(path, () => { server.off('error', reject); resolve(); });
    });
    chmodSync(path, 0o660);
    const st = lstatSync(path, { bigint: true });
    const identity = { path, uid: Number(st.uid), gid: Number(st.gid),
      mode: Number(st.mode & 0o7777n), device: st.dev.toString(),
      inode: st.ino.toString(), birthtime_ns: st.birthtimeNs.toString() };
    assert.equal(verifyCooperativeBRelaySocket(start, identity), path);
    assert.throws(() => verifyCooperativeBRelaySocket(start, { ...identity, inode: '1' }),
      /socket differs/);
    assert.throws(() => verifyCooperativeBRelaySocket(start, { ...identity, uid: identity.uid + 1 }),
      /identity differs/);
    chmodSync(path, 0o600);
    assert.throws(() => verifyCooperativeBRelaySocket(start, identity), /socket differs/);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    rmSync(root, { recursive: true, force: true });
  }
});

test('B CLI accepts only the assigned member and relay pair with FD3', () => {
  const bin = new URL('../bin/agent-bot-souls.mjs', import.meta.url);
  const args = ['run', '--soul', payload.assignment.package_root,
    '--admission-socket', payload.endpoints.admission.socket_path,
    '--member-socket', payload.endpoints.member.socket_path,
    '--relay-socket', payload.endpoints.relay.socket_path,
    '--profile', 'managed-cooperative', '--cooperative-start-fd', '3'];
  const absentFd = spawnSync(process.execPath, [bin.pathname, ...args], { encoding: 'utf8' });
  assert.equal(absentFd.status, 1);
  assert.match(absentFd.stderr, /fd 3 (is unavailable|read failed|must be a pipe)/);
  const mixed = spawnSync(process.execPath, [bin.pathname, ...args, '--broker-socket', '/wrong/broker.sock'],
    { encoding: 'utf8' });
  assert.equal(mixed.status, 1);
  assert.match(mixed.stderr, /one exact socket layout/);
  const incomplete = spawnSync(process.execPath, [bin.pathname, ...args.filter((arg, i) =>
    arg !== '--relay-socket' && args[i - 1] !== '--relay-socket')], { encoding: 'utf8' });
  assert.equal(incomplete.status, 1);
  assert.match(incomplete.stderr, /one exact socket layout/);
});

test('B start cannot consume the direct C attach reply or expose a broker path', async () => {
  const start = verifyCooperativeStart(fd3(), payload.assignment.package_root, pin, now, identity);
  let requested = false;
  await assert.rejects(attachCooperative({ request: async () => { requested = true; } }, fd3(), start),
    /B attach and live bridge bind are not available/);
  assert.equal(requested, false);
});
