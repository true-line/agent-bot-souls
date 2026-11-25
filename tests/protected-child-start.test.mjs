import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { test } from 'node:test';
import { canonicalize } from '../lib/contracts.mjs';
import { verifyProtectedChildStart } from '../lib/protected-child-start.mjs';

const sha = (bytes) => 'sha256:' + createHash('sha256').update(bytes).digest('hex');
const now = 1_800_000_000_000;

test('R binds signed Hello and child start to this R/B reservation, host, executable and expiry', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const pin = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  const signEnvelope = (purpose, payload) => {
    const bytes = Buffer.from(canonicalize(payload));
    const envelope = Buffer.from(canonicalize({ schema_version: 1, purpose,
      issuer_public_key_base64url: pin.toString('base64url'), payload_sha256: sha(bytes),
      payload_base64url: bytes.toString('base64url'),
      signature_base64url: sign(null, Buffer.concat([Buffer.from(purpose + '\0'), bytes]), privateKey).toString('base64url') }));
    return { encoded: envelope.toString('base64url'), sha256: sha(envelope) };
  };
  const installationId = 'inst_fixture';
  const account = '_abm-sr-' + createHash('sha256').update(installationId).digest('hex').slice(0, 20);
  const startId = 'st_' + '1'.repeat(24);
  const slot = createHash('sha256').update('agent-bot-soul-endpoint-start/v1\0' + installationId + '\0' + startId).digest('hex').slice(0, 20);
  const root = `/var/agent-bot-soul-runner-${account}/state/child-${slot}`;
  const tmp = root + '/tmpdir';
  const relay = '/private/var/run/fixture-relay.sock';
  const model = 'fixture-model';
  const environment = { PATH: '/usr/bin:/bin', HOME: root + '/home', TMPDIR: tmp, TMP: tmp, TEMP: tmp,
    CLAUDE_CODE_TMPDIR: tmp, XDG_CONFIG_HOME: root + '/xdg_config_home', XDG_CONFIG_DIRS: root + '/xdg_config_home',
    XDG_CACHE_HOME: root + '/xdg_cache_home', XDG_DATA_HOME: root + '/xdg_data_home',
    XDG_DATA_DIRS: root + '/xdg_data_home', XDG_STATE_HOME: root + '/xdg_state_home',
    XDG_RUNTIME_DIR: root + '/xdg_runtime_dir', ANTHROPIC_UNIX_SOCKET: relay,
    ANTHROPIC_API_KEY: 'ssh-placeholder', ANTHROPIC_BASE_URL: 'http://fixture.invalid',
    ANTHROPIC_MODEL: model, CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: '1' };
  const sandboxPath = '/Library/Application Support/ai.true-line.agent-bot-hq/soul-child-egress.sb';
  const sandboxBareSha = 'a'.repeat(64);
  const start = { reservationSha256: sha('reservation'), installationId, startId,
    launchId: 'ln_' + '2'.repeat(24), planId: 'plan_fixture', planDigest: '3'.repeat(64),
    hqEpoch: '4'.repeat(64), soulId: 'soul_fixture', claimedDefinitionDigest: sha('definition'),
    definitionMeasurement: sha('definition-measurement'), launchInputMeasurement: sha('inputs'),
    runnerUid: 501, runnerGid: 20, bridgeUid: 502, bridgeGid: 20,
    stateRoot: `/var/agent-bot-soul-runner-${account}/state`, brokerSocket: relay,
    launchInputRecords: { effective_config: { adapter_id: 'adapter', adapter_child_env: { model },
      adapter_child_sandbox: { path: sandboxPath, sha256: `sha256:${sandboxBareSha}` } },
    host_projection: { adapters: { adapter: { command: ['/usr/local/bin/fixture-adapter'] } } },
    component_digests: { adapter: sha('adapter') },
    files: [{ path: 'policy/soul-child-egress.sb', sha256: sandboxBareSha }] } };
  const activation = { finalizationSha256: sha('finalization'), bindReceiptSha256: sha('bind'),
    runnerWrapperPid: 1001, bridgePid: 1002 };
  const admission = { helloPayloadSha256: sha('hello'), decisionId: 'decision',
    installationEpoch: 1, admittedRuntimes: [] };
  const runner = { pid: 1001, uid: 501, gid: 20, start_seconds: 1_700_000_000, start_micros: 1 };
  const bridge = { pid: 1002, uid: 502, gid: 20, start_seconds: 1_700_000_000, start_micros: 2 };
  const childLauncher = { pid: 1003, uid: 501, gid: 20, start_seconds: 1_700_000_000, start_micros: 3 };
  const child = { pid: 1004, uid: 501, gid: 20, start_seconds: 1_700_000_000, start_micros: 4 };
  const selectors = { reservation_sha256: start.reservationSha256, installation_id: installationId,
    start_id: startId, launch_id: start.launchId, plan_id: start.planId,
    plan_digest: start.planDigest, hq_epoch: start.hqEpoch };
  const hello = signEnvelope('agent-bot/stage2a-hello-finalization/v1', {
    schema: 'agent-bot-machine/stage2a-hello-finalization/v1', ...selectors,
    start_envelope_sha256: sha('hello-start'), finalized_at: new Date(now - 100).toISOString(),
    expected: { reservation_sha256: start.reservationSha256, start_id: startId,
      launch_id: start.launchId, hq_epoch: start.hqEpoch, soul_id: start.soulId,
      installation_id: installationId, definition_digest: start.claimedDefinitionDigest,
      definition_measurement: start.definitionMeasurement,
      launch_input_measurement: start.launchInputMeasurement, hello_payload_sha256: sha('hello'),
      admission_decision_id: 'decision', installation_epoch: 1,
      profile_in_force: 'managed-protected', hq_broker_bind_receipt_sha256: activation.bindReceiptSha256,
      admitted_runtimes: [] } });
  const payload = { schema: 'agent-bot-machine/stage2a-child-start/v1', ...selectors,
    finalization_sha256: activation.finalizationSha256, hello_finalization_sha256: hello.sha256,
    bind_receipt_sha256: activation.bindReceiptSha256, grant_sha256: sha('grant'),
    runner, bridge, child_launcher: childLauncher, child,
    executable: '/usr/local/bin/fixture-adapter', executable_sha256: sha('adapter'),
    sandbox_path: sandboxPath, sandbox_sha256: `sha256:${sandboxBareSha}`,
    relay_socket: relay, environment_sha256: sha(Buffer.from(canonicalize(environment))),
    started_at_ms: now - 100, expires_at_ms: now + 4_000 };
  const frameFor = (body) => {
    const receipt = signEnvelope('agent-bot/stage2a-child-start/v1', body);
    return { schema: 'agent-bot-souls/protected-child-start/v1', reservation_sha256: start.reservationSha256,
      start_id: startId, launch_id: start.launchId,
      hello_finalization_sha256: hello.sha256, hello_finalization_envelope_base64url: hello.encoded,
      child_start_sha256: receipt.sha256, child_start_envelope_base64url: receipt.encoded };
  };
  const live = { runner, bridge };
  const good = frameFor(payload);
  assert.equal(verifyProtectedChildStart(good, start, activation, live, pin, now, admission).sha256, good.child_start_sha256);
  assert.throws(() => verifyProtectedChildStart({ ...good, child_start_sha256: sha('altered') }, start, activation, live, pin, now, admission), /digest differs/);
  assert.throws(() => verifyProtectedChildStart(frameFor({ ...payload, child: { ...child, uid: 999 } }), start, activation, live, pin, now, admission), /signed child start differs/);
  assert.throws(() => verifyProtectedChildStart(frameFor({ ...payload, expires_at_ms: now - 1 }), start, activation, live, pin, now, admission), /signed child start differs/);
  assert.throws(() => verifyProtectedChildStart(good, { ...start, brokerSocket: '/wrong-host.sock' }, activation, live, pin, now, admission), /signed child start differs/);
  assert.throws(() => verifyProtectedChildStart(good, start, activation, live, pin, now,
    { ...admission, helloPayloadSha256: sha('other Hello') }), /Hello finalization differs/);
  assert.throws(() => verifyProtectedChildStart(good, start, activation, live, pin, now,
    { ...admission, decisionId: 'other-decision' }), /Hello finalization differs/);
  assert.throws(() => verifyProtectedChildStart(good, start, activation, live, pin, now,
    { ...admission, installationEpoch: 2 }), /Hello finalization differs/);
  assert.throws(() => verifyProtectedChildStart(good, start, activation, live, pin, now,
    { ...admission, admittedRuntimes: [{ member_id: 'm_lead', runtime_id: 'rt_other', profile_in_force: 'managed-protected' }] }), /Hello finalization differs/);
});
