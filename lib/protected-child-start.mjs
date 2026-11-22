// The Machine-signed child receipt proves which stock ACP process was started
// for this one-use R/B reservation. HQ transports it unchanged on R's private
// control pipe; it cannot substitute its own process claim.
import { createHash, createPublicKey, verify } from 'node:crypto';
import { canonicalize, parseStrict } from './contracts.mjs';
import { dirname, join } from 'node:path';
import { readMachinePin } from './protected-start.mjs';

const PURPOSE = 'agent-bot/stage2a-child-start/v1';
const FRAME = ['schema', 'reservation_sha256', 'start_id', 'launch_id', 'hello_finalization_sha256', 'hello_finalization_envelope_base64url', 'child_start_sha256', 'child_start_envelope_base64url'];
const ENVELOPE = ['schema_version', 'purpose', 'issuer_public_key_base64url', 'payload_sha256', 'payload_base64url', 'signature_base64url'];
const PAYLOAD = ['schema', 'reservation_sha256', 'installation_id', 'start_id', 'launch_id', 'plan_id', 'plan_digest', 'hq_epoch', 'finalization_sha256', 'hello_finalization_sha256', 'bind_receipt_sha256', 'grant_sha256', 'runner', 'bridge', 'child_launcher', 'child', 'executable', 'executable_sha256', 'sandbox_path', 'sandbox_sha256', 'relay_socket', 'environment_sha256', 'started_at_ms', 'expires_at_ms'];
const ROLE = ['pid', 'uid', 'gid', 'start_seconds', 'start_micros'];
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const exact = (value, fields) => value !== null && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === fields.length && fields.every((field) => Object.hasOwn(value, field));
const digest = (bytes) => 'sha256:' + createHash('sha256').update(bytes).digest('hex');
const bad = (reason) => { throw new Error('protected child start: ' + reason); };

function decode(value, length) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) bad('noncanonical base64url');
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.toString('base64url') !== value || (length !== undefined && bytes.length !== length)) bad('noncanonical base64url');
  return bytes;
}

function signedJson(bytes) {
  let raw, value;
  try { raw = new TextDecoder('utf-8', { fatal: true }).decode(bytes); value = parseStrict(raw); }
  catch { bad('invalid signed JSON'); }
  if (canonicalize(value) !== raw) bad('signed JSON is not canonical');
  return value;
}

const role = (value, uid, gid) => exact(value, ROLE) && Number.isSafeInteger(value.pid) && value.pid > 1
  && value.uid === uid && value.gid === gid && Number.isSafeInteger(value.start_seconds)
  && value.start_seconds > 0 && Number.isSafeInteger(value.start_micros)
  && value.start_micros >= 0 && value.start_micros < 1_000_000;

function expectedChildEnvironment(start) {
  const account = '_abm-sr-' + createHash('sha256').update(start.installationId).digest('hex').slice(0, 20);
  const slot = createHash('sha256').update('agent-bot-soul-endpoint-start/v1\0')
    .update(start.installationId).update('\0').update(start.startId).digest('hex').slice(0, 20);
  const root = join(dirname(start.stateRoot), 'state', 'child-' + slot);
  const tmp = join(root, 'tmpdir');
  if (dirname(start.stateRoot) !== join('/var', 'agent-bot-soul-runner-' + account)) {
    bad('signed runner state is not the Machine-derived child root');
  }
  return { PATH: '/usr/bin:/bin', HOME: join(root, 'home'), TMPDIR: tmp, TMP: tmp,
    TEMP: tmp, CLAUDE_CODE_TMPDIR: tmp, XDG_CONFIG_HOME: join(root, 'xdg_config_home'),
    XDG_CONFIG_DIRS: join(root, 'xdg_config_home'), XDG_CACHE_HOME: join(root, 'xdg_cache_home'),
    XDG_DATA_HOME: join(root, 'xdg_data_home'), XDG_DATA_DIRS: join(root, 'xdg_data_home'),
    XDG_STATE_HOME: join(root, 'xdg_state_home'), XDG_RUNTIME_DIR: join(root, 'xdg_runtime_dir'),
    ANTHROPIC_UNIX_SOCKET: start.brokerSocket, ANTHROPIC_API_KEY: 'ssh-placeholder',
    ANTHROPIC_BASE_URL: 'http://fixture.invalid',
    ANTHROPIC_MODEL: start.launchInputRecords.effective_config.adapter_child_env.model,
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: '1' };
}

function verifySignedEnvelope(encoded, sha256, purpose, pin) {
  if (!SHA256.test(sha256)) bad('signed envelope digest is invalid');
  const envelopeBytes = decode(encoded);
  if (envelopeBytes.length > 12 * 1024 || digest(envelopeBytes) !== sha256) bad('envelope digest differs');
  const envelope = signedJson(envelopeBytes);
  if (!exact(envelope, ENVELOPE) || envelope.schema_version !== 1 || envelope.purpose !== purpose
    || !SHA256.test(envelope.payload_sha256) || !decode(envelope.issuer_public_key_base64url, 32).equals(pin)) {
    bad('signer differs from installed Machine authority');
  }
  const payloadBytes = decode(envelope.payload_base64url);
  if (digest(payloadBytes) !== envelope.payload_sha256) bad('payload digest differs');
  const key = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), pin]), format: 'der', type: 'spki' });
  if (!verify(null, Buffer.concat([Buffer.from(purpose + '\0'), payloadBytes]), key,
    decode(envelope.signature_base64url, 64))) bad('invalid Machine signature');
  return signedJson(payloadBytes);
}

export function verifyProtectedChildStart(frame, start, activation, live, pin, now = Date.now()) {
  if (!exact(frame, FRAME) || frame.schema !== 'agent-bot-souls/protected-child-start/v1'
    || frame.reservation_sha256 !== start.reservationSha256 || frame.start_id !== start.startId
    || frame.launch_id !== start.launchId || !SHA256.test(frame.child_start_sha256)
    || !Buffer.isBuffer(pin) || pin.length !== 32) bad('private frame differs from signed start');
  const hello = verifySignedEnvelope(frame.hello_finalization_envelope_base64url,
    frame.hello_finalization_sha256, 'agent-bot/stage2a-hello-finalization/v1', pin);
  const expected = hello?.expected;
  if (hello?.schema !== 'agent-bot-machine/stage2a-hello-finalization/v1'
    || hello.reservation_sha256 !== start.reservationSha256
    || hello.installation_id !== start.installationId || hello.start_id !== start.startId
    || hello.launch_id !== start.launchId || hello.plan_id !== start.planId
    || hello.plan_digest !== start.planDigest || hello.hq_epoch !== start.hqEpoch
    || !SHA256.test(hello.start_envelope_sha256)
    || expected?.reservation_sha256 !== start.reservationSha256
    || expected.start_id !== start.startId || expected.launch_id !== start.launchId
    || expected.hq_epoch !== start.hqEpoch || expected.soul_id !== start.soulId
    || expected.installation_id !== start.installationId
    || expected.definition_digest !== start.claimedDefinitionDigest
    || expected.definition_measurement !== start.definitionMeasurement
    || expected.launch_input_measurement !== start.launchInputMeasurement
    || expected.profile_in_force !== 'managed-protected'
    || expected.hq_broker_bind_receipt_sha256 !== activation.bindReceiptSha256
    || !Number.isFinite(Date.parse(hello.finalized_at))) bad('Hello finalization differs from this admission');
  const payload = verifySignedEnvelope(frame.child_start_envelope_base64url,
    frame.child_start_sha256, PURPOSE, pin);
  const input = start.launchInputRecords;
  const adapter = input?.host_projection?.adapters?.[input.effective_config.adapter_id];
  const sandbox = input?.effective_config?.adapter_child_sandbox;
  const profile = input?.files?.find((file) => file.path === 'policy/soul-child-egress.sb');
  if (!exact(payload, PAYLOAD) || payload.schema !== 'agent-bot-machine/stage2a-child-start/v1'
    || payload.reservation_sha256 !== start.reservationSha256
    || payload.installation_id !== start.installationId || payload.start_id !== start.startId
    || payload.launch_id !== start.launchId || payload.plan_id !== start.planId
    || payload.plan_digest !== start.planDigest || payload.hq_epoch !== start.hqEpoch
    || payload.finalization_sha256 !== activation.finalizationSha256
    || payload.hello_finalization_sha256 !== frame.hello_finalization_sha256
    || payload.bind_receipt_sha256 !== activation.bindReceiptSha256 || !SHA256.test(payload.grant_sha256)
    || !role(payload.runner, start.runnerUid, start.runnerGid)
    || !role(payload.bridge, start.bridgeUid, start.bridgeGid)
    || !role(payload.child_launcher, start.runnerUid, start.runnerGid)
    || !role(payload.child, start.runnerUid, start.runnerGid)
    || canonicalize(payload.runner) !== canonicalize(live.runner)
    || canonicalize(payload.bridge) !== canonicalize(live.bridge)
    || payload.runner.pid !== activation.runnerWrapperPid || payload.bridge.pid !== activation.bridgePid
    || payload.child_launcher.pid === payload.child.pid || payload.child.pid === payload.runner.pid
    || payload.executable !== adapter?.command?.[0]
    || payload.executable_sha256 !== input?.component_digests?.adapter
    || payload.sandbox_path !== '/Library/Application Support/ai.true-line.agent-bot-hq/soul-child-egress.sb'
    || payload.sandbox_path !== sandbox?.path || payload.sandbox_sha256 !== sandbox?.sha256
    || payload.sandbox_sha256 !== `sha256:${profile?.sha256}`
    || payload.relay_socket !== start.brokerSocket
    || payload.environment_sha256 !== digest(Buffer.from(canonicalize(expectedChildEnvironment(start))))
    || !Number.isSafeInteger(payload.started_at_ms) || !Number.isSafeInteger(payload.expires_at_ms)
    || payload.started_at_ms > now || payload.expires_at_ms <= now
    || payload.expires_at_ms <= payload.started_at_ms
    || payload.expires_at_ms - payload.started_at_ms > 5_000) bad('signed child start differs from this live reservation');
  return Object.freeze({ sha256: frame.child_start_sha256,
    helloFinalizationSha256: frame.hello_finalization_sha256,
    childLauncher: Object.freeze(payload.child_launcher), child: Object.freeze(payload.child), payload: Object.freeze(payload) });
}

export function checkProtectedChildStart(frame, start, activation, live) {
  return verifyProtectedChildStart(frame, start, activation, live, readMachinePin());
}
