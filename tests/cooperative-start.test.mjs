import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { closeSync, constants, mkdtempSync, openSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { canonicalize } from '../lib/contracts.mjs';
import { attachCooperative, connectCooperativeAdmission, verifyCooperativeStart } from '../lib/cooperative-start.mjs';
import { startSoul } from '../lib/entry-point.mjs';
import { MACHINE_PIN } from '../lib/protected-start.mjs';

const vector = JSON.parse(readFileSync(new URL('./fixtures/cooperative-start.synthetic.json', import.meta.url)));
const envelopeBytes = Buffer.from(vector.reservation_envelope_jcs);
const envelope = JSON.parse(vector.reservation_envelope_jcs);
const payload = JSON.parse(Buffer.from(envelope.payload_base64url, 'base64url').toString());
const root = payload.assignment.package_root;
const pin = Buffer.from(vector.issuer_public_key_base64url, 'base64url');
const now = Date.parse('2026-11-22T14:15:20Z');
const identity = { uid: 331, euid: 331, gid: 331, egid: 331 };
const digest = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const challenge = vector.admission_challenge_base64url;

async function readFd3(bytes) {
  const directory = mkdtempSync(join(tmpdir(), 'cooperative-fd3-'));
  const fifo = join(directory, 'start.pipe');
  const made = spawnSync('mkfifo', [fifo]);
  assert.equal(made.status, 0, made.stderr?.toString());
  const moduleUrl = new URL('../lib/cooperative-start.mjs', import.meta.url);
  const script = `import { readCooperativeStart } from ${JSON.stringify(moduleUrl.href)};\n`
    + 'try { process.stdout.write(JSON.stringify(readCooperativeStart(3))); }\n'
    + 'catch (error) { process.stderr.write(error.message); process.exitCode = 1; }';
  try {
    const reader = openSync(fifo, constants.O_RDONLY | constants.O_NONBLOCK);
    try {
      const writer = openSync(fifo, constants.O_WRONLY);
      let child;
      try {
        child = spawn(process.execPath, ['--input-type=module', '-e', script],
          { stdio: ['ignore', 'pipe', 'pipe', reader] });
        writeFileSync(writer, bytes);
      } finally { closeSync(writer); }
      let stdout = '', stderr = '';
      child.stdout.setEncoding('utf8').on('data', (chunk) => { stdout += chunk; });
      child.stderr.setEncoding('utf8').on('data', (chunk) => { stderr += chunk; });
      const code = await new Promise((resolve) => child.once('close', resolve));
      return { code, stdout, stderr };
    } finally { closeSync(reader); }
  } finally { rmSync(directory, { recursive: true, force: true }); }
}

function wrapper(bytes = envelopeBytes) {
  return {
    schema: 'agent-bot-souls/cooperative-start/v1',
    reservation_envelope_base64url: bytes.toString('base64url'),
    reservation_sha256: digest(bytes),
    machine_pin_path: MACHINE_PIN,
    launch_input_records: structuredClone(vector.launch_input_records),
    state_root: payload.assignment.state_root,
    admission_challenge_base64url: challenge,
  };
}

test('cooperative attach sends only signed envelope and challenge on the existing HQ connection', async () => {
  const value = wrapper();
  const start = { admissionChallengeBase64url: challenge, reservationSha256: value.reservation_sha256,
    startId: payload.assignment.start_id, launchId: payload.assignment.launch_id,
    brokerSocket: payload.endpoints.broker.socket_path };
  const calls = [];
  const hq = { async request(op, body) {
    calls.push([op, body]);
    return { schema: 'hq/cooperative-attach/v3', reservation_sha256: start.reservationSha256,
      start_id: start.startId, launch_id: start.launchId, broker_socket_path: start.brokerSocket,
      acp_ticket_base64url: Buffer.alloc(32, 0x33).toString('base64url') };
  } };
  await attachCooperative(hq, value, start);
  assert.deepEqual(calls, [['cooperative.attach.v3', {
    reservation_envelope_base64url: value.reservation_envelope_base64url,
    admission_challenge_base64url: challenge,
  }]]);
  await assert.rejects(attachCooperative({ request: async () => ({ ...await hq.request('cooperative.attach.v3', {}),
    broker_socket_path: '/wrong/broker.sock' }) }, value, start), /reply differs/);
});

function resigned(change) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const rawPin = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  const changed = structuredClone(payload);
  change(changed);
  const payloadBytes = Buffer.from(canonicalize(changed));
  const signed = {
    ...envelope,
    issuer_public_key_base64url: rawPin.toString('base64url'),
    payload_sha256: digest(payloadBytes),
    payload_base64url: payloadBytes.toString('base64url'),
    signature_base64url: sign(null, Buffer.concat([Buffer.from(`${envelope.purpose}\0`), payloadBytes]), privateKey).toString('base64url'),
  };
  return { value: wrapper(Buffer.from(canonicalize(signed))), pin: rawPin };
}

test('Contracts #78 direct-Comms reservation is signature-verified and bound to its frozen roots', () => {
  const plan = verifyCooperativeStart(wrapper(), root, pin, now, identity);
  assert.equal(payload.adapter_transport, 'direct-comms');
  assert.equal(vector.launch_input_records.adapter_transport, 'direct-comms');
  assert.equal(plan.hostId, 'synthetic-host');
  assert.equal(plan.runtimeRoot, payload.assignment.runtime_root);
  assert.equal(plan.definitionRoot, root);
  assert.equal(plan.launchInputMeasurement, payload.measurement_binding.launch_input_measurement);
  assert.equal(plan.rInventory.sidecar.sha256, payload.measurement_binding.r_inventory.sidecar.sha256);
  assert.equal(plan.expiresAt, payload.expires_at);
});

test('direct fd 3 refuses a signed B transport or a changed launch-record transport', () => {
  const wrongMode = resigned((changed) => { changed.adapter_transport = 'brokered-b'; });
  assert.throws(() => verifyCooperativeStart(wrongMode.value, root, wrongMode.pin, now, identity),
    /reservation does not bind/);
  const changedRecords = wrapper();
  changedRecords.launch_input_records.adapter_transport = 'brokered-b';
  assert.throws(() => verifyCooperativeStart(changedRecords, root, pin, now, identity),
    /adapter transport differs/);
  const addedBridge = wrapper();
  addedBridge.launch_input_records.bridge_launch_sha256 = `sha256:${'a'.repeat(64)}`;
  assert.throws(() => verifyCooperativeStart(addedBridge, root, pin, now, identity),
    /adapter transport differs/);
});

test('first C connect retries only a transient socket race before signed expiry', async () => {
  let time = now;
  const start = { admissionSocket: '/assigned/C.sock', expiresAt: new Date(now + 1000).toISOString() };
  const transient = Object.assign(new Error('connect /assigned/C.sock: ENOENT'),
    { op: 'connect', transport: true });
  let attempts = 0;
  const hq = { destroy() { throw new Error('unexpected destroy'); } };
  const options = { now: () => time, delay: async (ms) => { time += ms; }, maxWaitMs: 150 };
  assert.equal(await connectCooperativeAdmission(start, async (path, signal) => {
    assert.equal(path, start.admissionSocket);
    assert.equal(signal.aborted, false);
    if (++attempts < 3) throw transient;
    return hq;
  }, options), hq);
  assert.equal(attempts, 3);
  await assert.rejects(connectCooperativeAdmission(start, async () => {
    throw Object.assign(new Error('connect /assigned/C.sock: EACCES'), { op: 'connect', transport: true });
  }, options), /EACCES/);
  time = now;
  await assert.rejects(connectCooperativeAdmission(start, async () => { throw transient; },
    { ...options, maxWaitMs: 100 }), /did not become available/);
});

test('fd 3 accepts one bounded canonical JSON object through a pipe and rejects trailing bytes', async () => {
  const value = wrapper();
  const raw = Buffer.from(canonicalize(value));
  const accepted = await readFd3(raw);
  assert.equal(accepted.code, 0, accepted.stderr);
  assert.deepEqual(JSON.parse(accepted.stdout), value);
  const trailing = await readFd3(Buffer.concat([raw, Buffer.from('\n')]));
  assert.equal(trailing.code, 1);
  assert.match(trailing.stderr, /JSON is not canonical/);
});

test('cooperative CLI requires its fixed fd and assigned sockets before reading a Soul', () => {
  const bin = new URL('../bin/agent-bot-souls.mjs', import.meta.url);
  const args = ['run', '--soul', '/missing-definition', '--admission-socket', '/assigned/admission.sock',
    '--broker-socket', '/assigned/broker.sock', '--profile', 'managed-cooperative'];
  const wrongFd = spawnSync(process.execPath, [bin.pathname, ...args, '--cooperative-start-fd', '4'], { encoding: 'utf8' });
  assert.equal(wrongFd.status, 1);
  assert.match(wrongFd.stderr, /requires inherited fd 3/);
  const noFd = spawnSync(process.execPath, [bin.pathname, ...args, '--cooperative-start-fd', '3'], { encoding: 'utf8' });
  assert.equal(noFd.status, 1);
  assert.match(noFd.stderr, /fd 3 (is unavailable|read failed|must be a pipe)/);
});

test('unverified cooperative fd 3 input cannot fall through to editable package startup', async () => {
  await assert.rejects(startSoul({ root: '/missing-definition', requestedProfile: 'managed-cooperative',
    cooperativeStart: {}, admissionSocket: '/assigned/admission.sock', brokerSocket: '/assigned/broker.sock' }),
  { code: 'profile_insufficient' });
});

test('cooperative start rejects changed launch records, envelope bytes and signer', () => {
  const changed = wrapper();
  changed.launch_input_records.argv[1] = '/changed/entry.mjs';
  assert.throws(() => verifyCooperativeStart(changed, root, pin, now, identity), /launch input records differ/);
  const damaged = wrapper();
  damaged.reservation_envelope_base64url = Buffer.from(canonicalize({ ...envelope, purpose: 'wrong-purpose' })).toString('base64url');
  assert.throws(() => verifyCooperativeStart(damaged, root, pin, now, identity), /envelope digest differs/);
  assert.throws(() => verifyCooperativeStart(wrapper(), root, Buffer.alloc(32), now, identity), /signer differs/);
  const wrongChallenge = wrapper();
  wrongChallenge.admission_challenge_base64url = Buffer.alloc(32, 0x42).toString('base64url');
  assert.throws(() => verifyCooperativeStart(wrongChallenge, root, pin, now, identity), /does not bind/);
});

test('cooperative start rejects wrong definition, runner, host cross-binding and expired lease', () => {
  assert.throws(() => verifyCooperativeStart(wrapper(), '/other/definition', pin, now, identity), /does not bind/);
  assert.throws(() => verifyCooperativeStart(wrapper(), root, pin, now, { ...identity, uid: 332 }), /does not bind/);
  assert.throws(() => verifyCooperativeStart(wrapper(), root, pin, Date.parse('2026-11-22T14:15:36Z'), identity), /does not bind/);
  const host = resigned((p) => { p.host_id = 'other-host'; });
  assert.throws(() => verifyCooperativeStart(host.value, root, host.pin, now, identity), /does not bind/);
});
