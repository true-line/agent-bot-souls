import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { canonicalize } from '../lib/contracts.mjs';
import { verifyCooperativeStart } from '../lib/cooperative-start.mjs';
import { MACHINE_PIN } from '../lib/protected-start.mjs';

const vector = JSON.parse(readFileSync(new URL('./fixtures/cooperative-start.synthetic.json', import.meta.url)));
const ordinaryEnvelope = JSON.parse(vector.reservation_envelope_jcs);
const ordinaryPayload = JSON.parse(Buffer.from(ordinaryEnvelope.payload_base64url, 'base64url'));
const PURPOSE = 'agent-bot/soul-cooperative-qualification-candidate-reservation/v1';
const now = Date.parse('2026-11-22T14:15:20Z');
const identity = { uid: 331, euid: 331, gid: 331, egid: 331 };
const sha = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

function signedCandidate(change = () => {}, purpose = PURPOSE) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const pin = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  const payload = structuredClone(ordinaryPayload);
  const adapter = { ...payload.measurement_binding.adapter_release,
    status: 'uncertified-qualification-candidate' };
  delete adapter.release_attestation_sha256;
  delete payload.measurement_binding.adapter_release;
  payload.measurement_binding.adapter_candidate = adapter;
  payload.kind = 'soul-cooperative-qualification-candidate-reservation';
  payload.qualification_only = true;
  payload.reviewed_start_id = payload.assignment.start_id;
  payload.q_plan_id = 'plan-20261122T141516Z-1234';
  payload.q_plan_digest = 'a'.repeat(64);
  payload.test_plan_sha256 = `sha256:${'b'.repeat(64)}`;
  payload.provider_config_sha256 = payload.qualification_provider.config_sha256;
  change(payload);
  const payloadBytes = Buffer.from(canonicalize(payload));
  const envelope = {
    ...ordinaryEnvelope, purpose,
    issuer_public_key_base64url: pin.toString('base64url'),
    payload_sha256: sha(payloadBytes), payload_base64url: payloadBytes.toString('base64url'),
    signature_base64url: sign(null, Buffer.concat([Buffer.from(`${purpose}\0`), payloadBytes]),
      privateKey).toString('base64url'),
  };
  const envelopeBytes = Buffer.from(canonicalize(envelope));
  const value = {
    schema: 'agent-bot-souls/cooperative-start/v1',
    reservation_envelope_base64url: envelopeBytes.toString('base64url'),
    reservation_sha256: sha(envelopeBytes), machine_pin_path: MACHINE_PIN,
    launch_input_records: structuredClone(vector.launch_input_records),
    state_root: payload.assignment.state_root,
    admission_challenge_base64url: vector.admission_challenge_base64url,
  };
  return { value, payload, pin };
}

const verify = ({ value, payload, pin }) => verifyCooperativeStart(value,
  payload.assignment.package_root, pin, now, identity);

test('one-use cooperative candidate accepts only its distinct signed purpose, kind and Q pins', () => {
  const candidate = signedCandidate();
  const start = verify(candidate);
  assert.equal(start.qualificationCandidate, true);
  assert.equal(start.adapterTransport, 'direct-comms');
  assert.equal(start.reservationSha256, candidate.value.reservation_sha256);
  assert.equal(start.startId, candidate.payload.reviewed_start_id);
  assert.throws(() => verify(signedCandidate(() => {}, 'agent-bot/soul-cooperative-reservation/v3')),
    /reservation does not bind|ordinary reservation/);
  assert.throws(() => verify(signedCandidate((p) => { p.kind = 'soul-cooperative-reservation'; })),
    /reservation does not bind/);
  assert.throws(() => verify({ ...candidate, value: { ...candidate.value,
    schema: 'agent-bot-souls/cooperative-start/v2', member_socket_path: '/wrong',
    relay_socket_path: '/wrong', publish_outcome_envelope_base64url: 'AA', request_identity: {} } }),
  /invalid fd 3 input fields|unsupported reservation envelope/);
});

test('candidate refuses missing or changed Q, provider, and selected R authority', () => {
  for (const change of [
    (p) => { delete p.qualification_only; },
    (p) => { p.qualification_only = false; },
    (p) => { p.reviewed_start_id = 'st_ffffffffffffffffffffffff'; },
    (p) => { p.q_plan_digest = 'f'.repeat(64); p.q_plan_id = ''; },
    (p) => { p.provider_config_sha256 = `sha256:${'f'.repeat(64)}`; },
    (p) => { p.measurement_binding.adapter_candidate.status = 'released'; },
    (p) => { p.measurement_binding.adapter_candidate.executable_sha256 = `sha256:${'f'.repeat(64)}`; },
    (p) => { p.measurement_binding.adapter_candidate.package_sha256 = `sha256:${'f'.repeat(64)}`; },
    (p) => { p.measurement_binding.adapter_release = structuredClone(p.measurement_binding.adapter_candidate); },
  ]) {
    assert.throws(() => verify(signedCandidate(change)),
      /reservation does not bind|qualification candidate/);
  }
});
