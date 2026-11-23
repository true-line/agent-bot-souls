import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { test } from 'node:test';
import { startSoul } from '../lib/entry-point.mjs';
import { readProtectedSoulLayout, SoulError } from '../lib/soul.mjs';

const SOUL = 'agent_11111111-1111-1111-1111-111111111111';
const INSTALLATION = 'inst_fixture';
const CLAIM = `sha256:${'94'.repeat(32)}`;
const RUNNER_UID = 340;
const HQ_ENV = { AGENT_BOT_SOULS_REQUIRE_HQ_LAUNCH: '1', AGENT_BOT_SOUL_CONTRACTS: '/missing-contracts' };
const CHECKER = 'Contents/opt/quickstart-check.mjs';
const DEFINITION = [
  'Contents', 'Contents/SoulInfo.json', 'Contents/SoulLock.json', 'Contents/opt', 'Contents/opt/empty',
  'Contents/opt/quickstart-adapter.mjs', CHECKER, 'Contents/primitives', 'Contents/primitives/quickstart-task.json',
];
const PROJECTION = ['host/adapters.json', 'host/installation.json'];
const COMPONENTS = {
  machine: 'bin/machine', hq: 'bin/hq', souls: 'bin/souls', bridge: 'bin/bridge',
  comms_broker: 'bin/comms-broker', adapter: 'bin/claude-agent-acp', harness: 'bin/harness', test_provider: 'bin/test-provider',
};
const SANDBOX_POLICY = 'policy/harness-egress.sb';
const LAUNCH_FILES = [...PROJECTION, ...Object.values(COMPONENTS), SANDBOX_POLICY].sort();
const SYSTEM_IMAGE = { path: '/usr/lib/libSystem.B.dylib', signing_requirement: 'anchor apple', cdhash: '34'.repeat(20) };
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const sortedKeys = (_, value) => value && typeof value === 'object' && !Array.isArray(value)
  ? Object.fromEntries(Object.keys(value).sort().map(key => [key, value[key]]))
  : value;
const recordDigest = (purpose, records) => `sha256:${hash(`${purpose}\0${JSON.stringify(records, sortedKeys)}`)}`;
const launchDigest = (records) => recordDigest(records.effective_config?.profile === 'managed-cooperative'
  ? 'agent-bot/stage2a-cooperative-launch-inputs/v3' : 'agent-bot/stage2a-launch-inputs/v1', records);

function record(path, file) {
  const stat = fs.statSync(file);
  const mode = (stat.mode & 0o7777).toString(8).padStart(4, '0');
  if (stat.isDirectory()) return { path, kind: 'directory', mode };
  return { path, kind: 'regular', mode, size: stat.size, sha256: hash(fs.readFileSync(file)) };
}

// Account ownership is modeled; directory entries, modes, file descriptors
// and bytes are real. The reviewed inventory is named explicitly.
async function withProjection(t, check) {
  const scratch = fs.mkdtempSync(join(fs.realpathSync(tmpdir()), 'protected-layout-'));
  const root = join(scratch, 'installed');
  const contents = join(root, 'Contents');
  const launchInputRoot = join(scratch, 'launch-inputs');
  const hostProjectionRoot = join(launchInputRoot, 'host');
  const stateRoot = join(scratch, 'state', INSTALLATION);
  const executable = join(contents, 'opt', 'quickstart-adapter.mjs');
  const ownerOverrides = new Map();
  const runner = { uid: RUNNER_UID };
  fs.mkdirSync(hostProjectionRoot, { recursive: true });
  fs.mkdirSync(join(launchInputRoot, 'bin'));
  fs.mkdirSync(join(launchInputRoot, 'policy'));
  for (const path of [...Object.values(COMPONENTS), SANDBOX_POLICY]) fs.writeFileSync(join(launchInputRoot, path), `reviewed fixture ${path}\n`, { mode: path === COMPONENTS.adapter ? 0o755 : 0o644 });
  fs.mkdirSync(stateRoot, { recursive: true, mode: 0o700 });
  fs.mkdirSync(join(contents, 'primitives'), { recursive: true, mode: 0o755 });
  fs.mkdirSync(join(contents, 'opt', 'empty'), { recursive: true, mode: 0o755 });
  fs.chmodSync(join(contents, 'opt', 'empty'), 0o755);
  const projectCommand = (command, env = { TEST_ONLY: 'fixture' }) => fs.writeFileSync(join(hostProjectionRoot, 'adapters.json'), JSON.stringify({ adapter: { command, env } }, sortedKeys));
  const writeJson = (path, value) => fs.writeFileSync(path, `${JSON.stringify(value)}\n`);
  writeJson(join(contents, 'SoulInfo.json'), {
    soul_id: SOUL,
    members: [{ member_id: 'lead', role: 'lead', adapter_id: 'adapter', adapter_version: '1.0.0' }],
  });
  writeJson(join(contents, 'SoulLock.json'), { definition_digest: CLAIM });
  writeJson(join(contents, 'primitives', 'quickstart-task.json'), { objective: 'Repair the fixture' });
  fs.writeFileSync(executable, 'import { checkAnswer } from "./quickstart-check.mjs";\nexport const adapter = checkAnswer();\n', { mode: 0o755 });
  fs.writeFileSync(join(root, CHECKER), 'export const checkAnswer = () => true;\n');
  fs.writeFileSync(join(hostProjectionRoot, 'installation.json'), JSON.stringify({ installation_id: INSTALLATION }));
  projectCommand([executable, '--serve']);
  const makePlan = (codeRecords = []) => {
    const definitionRecords = DEFINITION.map(path => record(path, join(root, path)));
    const files = [...codeRecords, ...LAUNCH_FILES.map(path => record(path, join(launchInputRoot, path)))];
    files.sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)));
    const digests = new Map(files.map(({ path, sha256 }) => [path, `sha256:${sha256}`]));
    const adapters = JSON.parse(fs.readFileSync(join(hostProjectionRoot, 'adapters.json'), 'utf8'));
    const installation = JSON.parse(fs.readFileSync(join(hostProjectionRoot, 'installation.json'), 'utf8'));
    const { command: argv, env } = adapters.adapter;
    const launchInputRecords = {
      files,
      host_projection: { adapters, installation },
      selected_command: argv[0],
      argv,
      environment: { ...env, HOME: stateRoot, TMPDIR: join(stateRoot, 'tmp') },
      effective_config: { policy: 'fixture', profile: 'managed-protected' },
      system_images: { product_version: '15.3', build_version: '24D60', darwin_kernel: '24.3.0', selected: [SYSTEM_IMAGE] },
      sandbox_policy_digest: digests.get(SANDBOX_POLICY),
      component_digests: Object.fromEntries(Object.entries(COMPONENTS).map(([component, path]) => [component, digests.get(path)])),
    };
    return {
      launchInputRoot,
      stateRoot,
      installationId: INSTALLATION,
      runnerUid: RUNNER_UID,
      definitionMeasurement: recordDigest('agent-bot/stage2a-definition-opt-closure/v1', definitionRecords),
      launchInputRecords,
      launchInputMeasurement: launchDigest(launchInputRecords),
    };
  };
  const lstat = fs.lstatSync;
  const fstat = fs.fstatSync;
  const mocks = [
    t.mock.method(process, 'getuid', () => runner.uid),
    t.mock.method(process, 'geteuid', () => runner.uid),
    t.mock.method(fs, 'lstatSync', (path, options) => {
      const stat = lstat(path, options);
      if (stat) {
        stat.uid = ownerOverrides.get(path) ?? (path === stateRoot ? RUNNER_UID : 0);
        if (!path.startsWith(scratch)) stat.mode &= ~0o022;
      }
      return stat;
    }),
    t.mock.method(fs, 'fstatSync', (fd, options) => Object.assign(fstat(fd, options), { uid: 0 })),
  ];
  syncBuiltinESMExports();
  try {
    await check({ root, contents, scratch, launchInputRoot, hostProjectionRoot, stateRoot, executable, ownerOverrides, runner, makePlan, plan: makePlan(), projectCommand });
  } finally {
    for (const mock of mocks) mock.mock.restore();
    syncBuiltinESMExports();
    fs.rmSync(scratch, { recursive: true, force: true });
  }
}

test('preflight measures the full definition and Reconstructible trees independently of launch inputs', (t) => withProjection(t, async ({ root, hostProjectionRoot, stateRoot, plan }) => {
  const candidate = readProtectedSoulLayout(root, stateRoot, plan);
  assert.equal(candidate.soulId, SOUL);
  assert.equal(candidate.installationId, INSTALLATION);
  assert.equal(candidate.stateRoot, stateRoot);
  assert.equal(candidate.claimedDefinitionDigest, CLAIM);
  assert.equal(candidate.definitionMeasurement, plan.definitionMeasurement);
  assert.equal(candidate.launchInputMeasurement, plan.launchInputMeasurement);
  assert.match(candidate.launchInputRecords.selected_command, /\/Contents\/opt\/quickstart-adapter\.mjs$/);
  assert.deepEqual(candidate.definitionRecords.map(({ path }) => path), DEFINITION);
  assert.equal(candidate.definitionRecords.filter(({ kind }) => kind === 'regular').length, 5);
  assert.equal(candidate.definitionRecords.find(({ path }) => path === CHECKER).kind, 'regular');
  assert.deepEqual(candidate.definitionRecords.find(({ path }) => path === 'Contents/opt/empty'), {
    path: 'Contents/opt/empty', kind: 'directory', mode: '0755',
  });
  assert.deepEqual(candidate.launchInputRecords, plan.launchInputRecords);
  assert.equal(Object.hasOwn(candidate, 'definition_digest'), false);

  await assert.rejects(startSoul({ root, protectedStateRoot: stateRoot, protectedInputs: { ...plan, runnerUid: RUNNER_UID + 1 }, requestedProfile: 'managed-protected', env: HQ_ENV }), /runtime UID differs from the reviewed installation runner UID/);
  await assert.rejects(startSoul({ root, protectedStateRoot: stateRoot, protectedInputs: plan, requestedProfile: 'managed-protected', env: HQ_ENV }), {
    code: 'profile_insufficient', reason: 'Machine-authenticated protected Soul launch inputs are unavailable',
  });
  assert.deepEqual(fs.readdirSync(stateRoot), []);
  assert.deepEqual(fs.readdirSync(hostProjectionRoot).sort(), PROJECTION.map(path => basename(path)));
}));

test('signed entry launch measures the fixed Souls Node invocation separately from member commands', (t) => withProjection(t, ({ root, hostProjectionRoot, launchInputRoot, stateRoot, makePlan, projectCommand }) => {
  projectCommand([join(launchInputRoot, COMPONENTS.adapter)], {});
  fs.writeFileSync(join(hostProjectionRoot, 'installation.json'), JSON.stringify({ installation_id: INSTALLATION, id: INSTALLATION }));
  const plan = makePlan();
  const node = join(launchInputRoot, 'bin', 'node');
  const entry = join(launchInputRoot, 'bin', 'agent-bot-souls.mjs');
  fs.writeFileSync(node, 'fixture Node', { mode: 0o755 });
  fs.writeFileSync(entry, 'fixture Souls entry');
  const admissionSocket = '/tmp/assigned-admission.sock';
  const brokerSocket = '/tmp/assigned-relay.sock';
  const launchInputRecords = {
    ...plan.launchInputRecords,
    files: [...plan.launchInputRecords.files, record('bin/node', node), record('bin/agent-bot-souls.mjs', entry)]
      .sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path))),
    selected_command: node,
    argv: [node, entry, 'run', '--soul', root, '--admission-socket', admissionSocket,
      '--broker-socket', brokerSocket, '--profile', 'managed-protected', '--protected-start-fd', '3'],
    environment: { PATH: '/usr/bin:/bin', HOME: join(stateRoot, '..'), AGENT_BOT_SOULS_REQUIRE_HQ_LAUNCH: '1' },
    effective_config: { ...plan.launchInputRecords.effective_config, adapter_id: 'adapter', adapter_child_env: {
      schema: 'agent-bot-souls/adapter-child-env/v1', provider: 'anthropic-messages',
      base_url: 'http://fixture.invalid', http_host: 'fixture.invalid',
      client_key_sha256: 'sha256:da4fec28d868ca5cf8f00f43869f703f138bd4211683b8637a751b904860ddf0',
      model: 'pilot-model', messages_query: '', disable_nonessential_traffic: true,
    } },
  };
  const entryPlan = { ...plan, entryLaunch: true, admissionSocket, brokerSocket,
    launchInputRecords, launchInputMeasurement: launchDigest(launchInputRecords) };
  assert.equal(readProtectedSoulLayout(root, stateRoot, entryPlan).launchInputMeasurement, entryPlan.launchInputMeasurement);
  const cooperativeRecords = {
    ...launchInputRecords,
    argv: [...launchInputRecords.argv.slice(0, -3), 'managed-cooperative', '--cooperative-start-fd', '3'],
    component_digests: Object.fromEntries(Object.entries(launchInputRecords.component_digests)
      .filter(([name]) => name !== 'bridge')),
    effective_config: { ...launchInputRecords.effective_config, profile: 'managed-cooperative' },
  };
  const cooperativePlan = { ...entryPlan, launchInputRecords: cooperativeRecords,
    launchInputMeasurement: launchDigest(cooperativeRecords) };
  const definitionBefore = fs.readdirSync(join(root, 'Contents')).sort();
  const stateBefore = fs.readdirSync(stateRoot);
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, cooperativePlan, 'managed-cooperative'),
    /Frozen R runtime/);
  assert.deepEqual(fs.readdirSync(join(root, 'Contents')).sort(), definitionBefore);
  assert.deepEqual(fs.readdirSync(stateRoot), stateBefore);
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, cooperativePlan), /effective profile differs/);
  const wrongArgv = { ...launchInputRecords, argv: [...launchInputRecords.argv] };
  wrongArgv.argv[wrongArgv.argv.length - 1] = '4';
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, { ...entryPlan,
    launchInputRecords: wrongArgv, launchInputMeasurement: launchDigest(wrongArgv) }), /fixed Souls entry argv differs/);
  const wrongEnv = { ...launchInputRecords, environment: { ...launchInputRecords.environment, HOME: '/tmp/wrong' } };
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, { ...entryPlan,
    launchInputRecords: wrongEnv, launchInputMeasurement: launchDigest(wrongEnv) }), /fixed Souls entry environment differs/);
  const wrongChild = { ...launchInputRecords, effective_config: { ...launchInputRecords.effective_config,
    adapter_child_env: { ...launchInputRecords.effective_config.adapter_child_env, client_key_sha256: `sha256:${'0'.repeat(64)}` } } };
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, { ...entryPlan,
    launchInputRecords: wrongChild, launchInputMeasurement: launchDigest(wrongChild) }), /signed stock child environment is invalid/);
}));

test('closure refuses file additions, missing files, and byte or permission changes', (t) => withProjection(t, ({ root, contents, stateRoot, plan }) => {
  const extra = join(contents, 'opt', 'unlisted.mjs');
  fs.writeFileSync(extra, '');
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, plan), /definition: measurement differs/);
  fs.unlinkSync(extra);

  const primitive = join(contents, 'primitives', 'quickstart-task.json');
  const initial = fs.readFileSync(primitive);
  fs.unlinkSync(primitive);
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, plan), /definition: measurement differs/);
  fs.writeFileSync(primitive, Buffer.concat([initial, Buffer.from(' ')]));
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, plan), /definition: measurement differs/);
  fs.writeFileSync(primitive, initial);
  fs.chmodSync(contents, 0o555);
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, plan), /definition: measurement differs/);
  fs.chmodSync(contents, 0o755);
  fs.chmodSync(join(contents, 'opt', 'empty'), 0o555);
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, plan), /definition: measurement differs/);
}));

test('preflight refuses unknown and mutable classes in the definition and checks ancestor ownership', (t) => withProjection(t, ({ root, contents, hostProjectionRoot, stateRoot, ownerOverrides, plan }) => {
  for (const name of ['unknown', 'workspaces', 'host']) {
    const path = join(contents, name);
    fs.mkdirSync(path);
    assert.throws(() => readProtectedSoulLayout(root, stateRoot, plan), /Contents: unexpected projection entries/);
    fs.rmdirSync(path);
  }
  ownerOverrides.set(contents, RUNNER_UID);
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, plan), /Contents.*owner differs from root/);
  ownerOverrides.delete(contents);
  fs.chmodSync(hostProjectionRoot, 0o775);
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, plan), /host.*group or other may write/);
  fs.chmodSync(hostProjectionRoot, 0o755);
  ownerOverrides.set(join(stateRoot, '..'), RUNNER_UID);
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, plan), /state ancestry.*owner differs from root/);
}));

test('preflight refuses links, special files, names outside ASCII and ambiguous JSON', (t) => withProjection(t, ({ root, contents, stateRoot, executable, plan, makePlan }) => {
  const opt = join(contents, 'opt');
  const link = join(opt, 'linked');
  fs.symlinkSync(executable, link);
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, plan), /linked.*real directory or regular file/);
  fs.unlinkSync(link);
  fs.linkSync(executable, link);
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, plan), /single link/);
  fs.unlinkSync(link);
  assert.equal(spawnSync('/usr/bin/mkfifo', [link]).status, 0);
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, plan), /linked.*real directory or regular file/);
  fs.unlinkSync(link);
  const nonAscii = join(opt, 'e\u0301');
  fs.writeFileSync(nonAscii, '');
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, plan), /invalid ASCII entry name/);
  fs.unlinkSync(nonAscii);
  fs.writeFileSync(join(contents, 'SoulLock.json'), `{"definition_digest":"${CLAIM}","definition_digest":"${CLAIM}"}`);
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, makePlan()), /SoulLock.json:.*duplicate/i);
}));

test('preflight sorts readdir results and refuses a case-fold alias', (t) => withProjection(t, ({ root, contents, stateRoot, plan }) => {
  const readdir = fs.readdirSync;
  let alias = false;
  const mock = t.mock.method(fs, 'readdirSync', (path, options) => {
    const names = readdir(path, options).reverse();
    if (alias && path === join(contents, 'opt')) names.push(Buffer.from('QUICKSTART-ADAPTER.mjs'));
    return names;
  });
  syncBuiltinESMExports();
  try {
    assert.equal(readProtectedSoulLayout(root, stateRoot, plan).definitionMeasurement, plan.definitionMeasurement);
    alias = true;
    assert.throws(() => readProtectedSoulLayout(root, stateRoot, plan), /case-fold duplicate/);
  } finally {
    mock.mock.restore();
    syncBuiltinESMExports();
  }
}));

test('preflight checks frozen source limits before measurement', (t) => withProjection(t, ({ root, contents, stateRoot, plan }) => {
  const opt = join(contents, 'opt');
  const large = join(opt, 'large');
  fs.closeSync(fs.openSync(large, 'w'));
  fs.truncateSync(large, 256 * 1024 ** 2 + 1);
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, plan), /per-file size limit/);
  fs.unlinkSync(large);
  for (let i = 0; i < 5; i++) {
    const path = join(opt, `large-${i}`);
    fs.closeSync(fs.openSync(path, 'w'));
    fs.truncateSync(path, 256 * 1024 ** 2);
  }
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, plan), /aggregate size limit/);
  for (let i = 0; i < 512; i++) fs.writeFileSync(join(opt, `entry-${i}`), '');
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, plan), /exceeds 512 entries/);
}));

test('launch projection changes and unknown or mutable code are refused', (t) => withProjection(t, ({ root, launchInputRoot, hostProjectionRoot, stateRoot, plan, makePlan, projectCommand }) => {
  fs.appendFileSync(join(hostProjectionRoot, 'adapters.json'), '\n');
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, plan), /launch input: measurement differs/);
  const reformatted = readProtectedSoulLayout(root, stateRoot, makePlan());
  assert.deepEqual(reformatted.launchInputRecords.host_projection, plan.launchInputRecords.host_projection);
  assert.notEqual(reformatted.launchInputMeasurement, plan.launchInputMeasurement);

  const lifeCode = join(stateRoot, 'check.mjs');
  fs.writeFileSync(lifeCode, '');
  projectCommand(['reviewed-adapter']);
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, makePlan()), /selected command: needs a normalized absolute path/);
  projectCommand([lifeCode]);
  for (const invalid of [lifeCode, '../state/inst_fixture/check.mjs', 'bin/./node', 'bin//node']) {
    assert.throws(() => readProtectedSoulLayout(root, stateRoot, makePlan([record(invalid, lifeCode)])), /invalid root-relative record path/);
  }
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, makePlan()), /executable is outside the reviewed code inventory/);

  const adapterPath = 'bin/reviewed-adapter';
  const external = join(launchInputRoot, adapterPath);
  fs.symlinkSync(lifeCode, external);
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, makePlan([record(adapterPath, lifeCode)])), /bin\/reviewed-adapter.*must be a real file/);
  fs.unlinkSync(external);
  fs.writeFileSync(external, '', { mode: 0o644 });
  projectCommand([external, '--serve']);
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, makePlan([record(adapterPath, external)])), /executable is outside the reviewed code inventory/);
  fs.chmodSync(external, 0o755);
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, makePlan()), /launch input projection: unexpected projection entries/);
  const externalPlan = makePlan([record(adapterPath, external)]);
  const candidate = readProtectedSoulLayout(root, stateRoot, externalPlan);
  assert.equal(candidate.members[0].routes[0].command[0], external);
  assert.deepEqual(candidate.launchInputRecords.files.map(({ path }) => path), [adapterPath, ...LAUNCH_FILES].sort());
  const reversed = { ...externalPlan.launchInputRecords, files: [...externalPlan.launchInputRecords.files].reverse() };
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, { ...externalPlan, launchInputRecords: reversed, launchInputMeasurement: launchDigest(reversed) }), /strict path order/);
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, { ...externalPlan, launchInputMeasurement: externalPlan.definitionMeasurement }), /launch input: measurement differs/);
  fs.appendFileSync(external, 'altered');
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, externalPlan), /launch input: measurement differs/);
}));

test('launch inputs refuse excessive argv, environment and host/config metadata before measuring files', (t) => withProjection(t, ({ root, hostProjectionRoot, stateRoot, plan, makePlan }) => {
  const base = plan.launchInputRecords;
  const refuses = (fields, error) => {
    const launchInputRecords = { ...base, ...fields };
    assert.throws(() => readProtectedSoulLayout(root, stateRoot, { ...plan, launchInputRecords, launchInputMeasurement: launchDigest(launchInputRecords) }), error);
  };
  const properties = Object.fromEntries(Array.from({ length: 257 }, (_, i) => [`ENTRY_${i}`, 'x']));
  const paddedEnvironment = Object.fromEntries(Array.from({ length: 9 }, (_, i) => [`ENTRY_${i}`, 'x'.repeat(8000)]));
  refuses({ argv: [base.argv[0], ...Array(128).fill('x')] }, /argument count or length limit/);
  refuses({ argv: [base.argv[0], 'x'.repeat(4097)] }, /argument count or length limit/);
  refuses({ argv: [base.argv[0], ...Array(17).fill('x'.repeat(4096))] }, /argv: exceeds the 65536-byte/);
  refuses({ environment: properties }, /environment exceeds the property, key or value limits/);
  refuses({ environment: { 'invalid-name': 'x' } }, /environment exceeds the property, key or value limits/);
  refuses({ environment: { VALUE: 'x'.repeat(8193) } }, /environment exceeds the property, key or value limits/);
  refuses({ environment: { ['A'.repeat(65537)]: 'x' } }, /environment: exceeds the 65536-byte/);
  refuses({ environment: paddedEnvironment }, /environment: exceeds the 65536-byte/);
  refuses({ host_projection: { ...base.host_projection, adapters: properties } }, /host adapters: exceeds the property limit/);
  refuses({ host_projection: { ...base.host_projection, installation: { payload: 'x'.repeat(65537) } } }, /host installation: exceeds the 65536-byte/);
  const deep = Array.from({ length: 17 }).reduce(value => ({ child: value }), 'leaf');
  refuses({ effective_config: { ...base.effective_config, deep } }, /effective config: exceeds the JSON depth or node limit/);
  refuses({ effective_config: { ...base.effective_config, broad: Array(4097).fill(0) } }, /effective config: exceeds the JSON node limit/);
  fs.appendFileSync(join(hostProjectionRoot, 'installation.json'), ' '.repeat(65536));
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, makePlan()), /installation.json: exceeds the 65536-byte raw host JSON limit/);
}));

test('selected system images bind exact macOS constraints and reject oversize or aliased inventories', (t) => withProjection(t, ({ root, stateRoot, plan }) => {
  const base = plan.launchInputRecords;
  const refuses = (system_images, error) => {
    const launchInputRecords = { ...base, system_images };
    assert.throws(() => readProtectedSoulLayout(root, stateRoot, { ...plan, launchInputRecords, launchInputMeasurement: launchDigest(launchInputRecords) }), error);
  };
  const images = base.system_images;
  const updated = { ...images, selected: [{ ...SYSTEM_IMAGE, cdhash: 'ae'.repeat(20) }] };
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, { ...plan, launchInputRecords: { ...base, system_images: updated } }), /launch input: measurement differs/);
  refuses({ ...images, product_version: '' }, /requires bounded product version/);
  refuses({ ...images, build_version: 'x'.repeat(129) }, /requires bounded product version/);
  refuses({ ...images, darwin_kernel: 20 }, /requires bounded product version/);
  refuses({ ...images, selected: [] }, /1–256 selected images/);
  refuses({ ...images, selected: Array(257).fill(SYSTEM_IMAGE) }, /1–256 selected images/);
  refuses({ ...images, selected: [{ ...SYSTEM_IMAGE, signing_requirement: 'x'.repeat(4097) }] }, /bounded signing requirement/);
  refuses({ ...images, selected: [{ ...SYSTEM_IMAGE, cdhash: 'AA'.repeat(20) }] }, /lowercase CDHash/);
  refuses({ ...images, selected: [{ ...SYSTEM_IMAGE, path: '/usr/lib/../lib/libSystem.B.dylib' }] }, /system image: needs a normalized absolute path/);
  refuses({ ...images, selected: [SYSTEM_IMAGE, { ...SYSTEM_IMAGE, path: '/usr/lib/libsystem.b.dylib' }] }, /duplicate or case-fold alias/);
  refuses({ ...images, selected: [SYSTEM_IMAGE, { ...SYSTEM_IMAGE, path: '/usr/lib/first.dylib' }] }, /strict path order/);
  const selected = Array.from({ length: 130 }, (_, i) => ({
    ...SYSTEM_IMAGE, path: `/usr/lib/image-${String(i).padStart(3, '0')}.dylib`, signing_requirement: 'x'.repeat(4096),
  }));
  refuses({ ...images, selected }, /system images: exceeds the 524288-byte/);
}));

test('complete launch measurement enforces its aggregate canonical byte ceiling', (t) => withProjection(t, ({ root, stateRoot, plan }) => {
  const base = plan.launchInputRecords;
  const config = 'x'.repeat(63000);
  const launchInputRecords = {
    ...base,
    files: Array.from({ length: 64 }, (_, i) => ({ ...base.files[0], path: `p${String(i).padStart(2, '0')}/${'x'.repeat(4070)}` })),
    argv: [base.argv[0], ...Array(15).fill('x'.repeat(4090))],
    environment: Object.fromEntries(Array.from({ length: 8 }, (_, i) => [`ENTRY_${i}`, 'x'.repeat(8000)])),
    host_projection: { adapters: { config }, installation: { config } },
    effective_config: { ...base.effective_config, config },
    system_images: {
      ...base.system_images,
      selected: Array.from({ length: 122 }, (_, i) => ({
        ...SYSTEM_IMAGE, path: `/usr/lib/image-${String(i).padStart(3, '0')}.dylib`, signing_requirement: 'x'.repeat(4096),
      })),
    },
  };
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, { ...plan, launchInputRecords, launchInputMeasurement: launchDigest(launchInputRecords) }), /launch input: exceeds the 1048576-byte/);
}));

test('launch measurement binds ordered argv, including argv[0], and environment independently of file bytes', (t) => withProjection(t, ({ root, stateRoot, plan }) => {
  const base = plan.launchInputRecords;
  const argvOnly = { ...base, argv: [...base.argv, '--unreviewed'] };
  const argv0Only = { ...base, argv: ['alternate-argv0', ...base.argv.slice(1)] };
  const envOnly = { ...base, environment: { ...base.environment, TEST_ONLY: 'changed' } };
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, { ...plan, launchInputRecords: argvOnly }), /launch input: measurement differs/);
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, { ...plan, launchInputRecords: argvOnly, launchInputMeasurement: launchDigest(argvOnly) }), /adapter argv differs/);
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, { ...plan, launchInputRecords: argv0Only, launchInputMeasurement: launchDigest(argv0Only) }), /full argv must begin with the selected command/);
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, { ...plan, launchInputRecords: envOnly }), /launch input: measurement differs/);
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, { ...plan, launchInputRecords: envOnly, launchInputMeasurement: launchDigest(envOnly) }), /adapter environment differs/);
  for (const scope of ['bridge', 'comms_broker']) {
    const component_digests = { ...base.component_digests };
    delete component_digests[scope];
    const incomplete = { ...base, component_digests };
    assert.throws(() => readProtectedSoulLayout(root, stateRoot, { ...plan, launchInputRecords: incomplete, launchInputMeasurement: launchDigest(incomplete) }), /component digests differ from the selected profile/);
    const unmeasured = { ...base, component_digests: { ...base.component_digests, [scope]: `sha256:${hash('unmeasured fixture')}` } };
    assert.throws(() => readProtectedSoulLayout(root, stateRoot, { ...plan, launchInputRecords: unmeasured, launchInputMeasurement: launchDigest(unmeasured) }), new RegExp(`${scope} has no measured file`));
  }
  const misplacedProof = { ...base, environment: { ...base.environment, B_ONLY_TOKEN: 'fixture-marker' } };
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, { ...plan, launchInputRecords: misplacedProof, launchInputMeasurement: launchDigest(misplacedProof) }), /bridge-only proof is forbidden/);
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, { ...plan, launchInputRecords: base.files, launchInputMeasurement: launchDigest(base.files) }), /complete reviewed launch input object/);
}));

test('the cooperative replay changes the launch measurement while preserving the frozen definition', (t) => withProjection(t, ({ root, stateRoot, plan }) => {
  const replay = {
    ...plan.launchInputRecords,
    component_digests: Object.fromEntries(Object.entries(plan.launchInputRecords.component_digests)
      .filter(([name]) => name !== 'bridge')),
    effective_config: { ...plan.launchInputRecords.effective_config, profile: 'managed-cooperative' },
  };
  const replayPlan = { ...plan, launchInputRecords: replay, launchInputMeasurement: launchDigest(replay) };
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, replayPlan), /effective profile differs from the expected profile/);
  const candidate = readProtectedSoulLayout(root, stateRoot, replayPlan, 'managed-cooperative');
  assert.equal(candidate.definitionMeasurement, plan.definitionMeasurement);
  assert.notEqual(candidate.launchInputMeasurement, plan.launchInputMeasurement);
  const coreOnly = { ...replay, component_digests: Object.fromEntries(Object.entries(replay.component_digests)
    .filter(([name]) => name !== 'harness' && name !== 'test_provider')) };
  assert.equal(readProtectedSoulLayout(root, stateRoot, { ...replayPlan, launchInputRecords: coreOnly,
    launchInputMeasurement: launchDigest(coreOnly) }, 'managed-cooperative').launchInputMeasurement, launchDigest(coreOnly));
  const halfQualification = { ...replay, component_digests: { ...coreOnly.component_digests,
    harness: replay.component_digests.harness } };
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, { ...replayPlan, launchInputRecords: halfQualification,
    launchInputMeasurement: launchDigest(halfQualification) }, 'managed-cooperative'), /component digests differ/);
  const bridgeClaim = { ...replay, component_digests: plan.launchInputRecords.component_digests };
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, { ...replayPlan,
    launchInputRecords: bridgeClaim, launchInputMeasurement: launchDigest(bridgeClaim),
  }, 'managed-cooperative'), /component digests differ from the selected profile/);
}));

test('runner state must be a disjoint private directory for the projected installation', (t) => withProjection(t, ({ root, scratch, stateRoot, ownerOverrides, plan }) => {
  assert.throws(() => readProtectedSoulLayout(root, join(root, INSTALLATION), plan), /projection must be disjoint/);
  const linkedParent = join(scratch, 'linked-state');
  fs.symlinkSync(join(stateRoot, '..'), linkedParent, 'dir');
  const stateThroughLink = join(linkedParent, INSTALLATION);
  assert.throws(() => readProtectedSoulLayout(root, stateThroughLink, { ...plan, stateRoot: stateThroughLink }), /state ancestry.*must be a real directory/);
  fs.chmodSync(join(stateRoot, '..'), 0o777);
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, plan), /state ancestry.*group or other may write/);
  fs.chmodSync(join(stateRoot, '..'), 0o755);
  fs.chmodSync(stateRoot, 0o755);
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, plan), /mode must be 0700/);
  fs.chmodSync(stateRoot, 0o700);
  ownerOverrides.set(stateRoot, 0);
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, plan), /state: owner differs from the runtime account/);
  const namedForSoul = join(stateRoot, '..', SOUL);
  fs.renameSync(stateRoot, namedForSoul);
  ownerOverrides.set(namedForSoul, RUNNER_UID);
  assert.throws(() => readProtectedSoulLayout(root, namedForSoul, { ...plan, stateRoot: namedForSoul }), /directory name differs from the installation ID/);
  fs.symlinkSync(namedForSoul, stateRoot, 'dir');
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, plan), /state: must be a real directory/);
}));

test('two installations of the same Soul require their own runtime UID, projection and state path', (t) => withProjection(t, ({ root, scratch, launchInputRoot, stateRoot, ownerOverrides, runner, plan }) => {
  const otherInstallationId = 'inst_other';
  const otherRunnerUid = RUNNER_UID + 1;
  const otherStateRoot = join(stateRoot, '..', otherInstallationId);
  const otherProjectionRoot = join(scratch, 'other-host-projection');
  fs.mkdirSync(otherStateRoot, { mode: 0o700 });
  ownerOverrides.set(otherStateRoot, otherRunnerUid);
  fs.cpSync(launchInputRoot, otherProjectionRoot, { recursive: true });
  fs.writeFileSync(join(otherProjectionRoot, 'host', 'installation.json'), JSON.stringify({ installation_id: otherInstallationId }));
  const otherLaunchInputs = {
    ...plan.launchInputRecords,
    files: LAUNCH_FILES.map(path => record(path, join(otherProjectionRoot, path))),
    host_projection: { ...plan.launchInputRecords.host_projection, installation: { installation_id: otherInstallationId } },
    environment: { ...plan.launchInputRecords.environment, HOME: otherStateRoot, TMPDIR: join(otherStateRoot, 'tmp') },
  };
  const otherPlan = {
    ...plan,
    installationId: otherInstallationId,
    runnerUid: otherRunnerUid,
    stateRoot: otherStateRoot,
    launchInputRoot: otherProjectionRoot,
    launchInputRecords: otherLaunchInputs,
    launchInputMeasurement: launchDigest(otherLaunchInputs),
  };

  const first = readProtectedSoulLayout(root, stateRoot, plan);
  assert.throws(() => readProtectedSoulLayout(root, otherStateRoot, otherPlan), /runtime UID differs from the reviewed installation runner UID/);
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, { ...plan, runnerUid: String(RUNNER_UID) }), /runtime UID differs/);
  runner.uid = otherRunnerUid;
  assert.throws(() => readProtectedSoulLayout(root, stateRoot, otherPlan), /path differs from the reviewed installation state path/);
  assert.throws(() => readProtectedSoulLayout(root, otherStateRoot, { ...otherPlan, installationId: INSTALLATION }), /host projection: installation ID differs/);
  const second = readProtectedSoulLayout(root, otherStateRoot, otherPlan);
  assert.equal(first.soulId, second.soulId);
  assert.notEqual(first.installationId, second.installationId);
  assert.notEqual(first.stateRoot, second.stateRoot);
}));

test('HQ-started protected requests cannot fall through to the cooperative package reader', async () => {
  await assert.rejects(startSoul({ requestedProfile: 'managed-protected', env: HQ_ENV }), {
    code: 'profile_insufficient', reason: 'Machine-authenticated protected Soul launch inputs are unavailable',
  });
  await assert.rejects(startSoul({ requestedProfile: 'managed-protected', protectedInputs: {}, env: HQ_ENV }), {
    code: 'profile_insufficient', reason: 'the HQ-started protected Soul has no separate runtime state directory',
  });
  await assert.rejects(startSoul({ requestedProfile: 'managed-protected', protectedStateRoot: '/untrusted', env: {} }), {
    code: 'profile_insufficient', reason: 'the installed projection requires an HQ-started managed-protected launch',
  });
  await assert.rejects(startSoul({ requestedProfile: 'managed-cooperative', protectedStateRoot: '/untrusted',
    protectedInputs: {}, env: HQ_ENV }), {
    code: 'profile_insufficient', reason: 'the installed projection requires an HQ-started managed-protected launch',
  });
  assert.throws(() => readProtectedSoulLayout('/installed', '../mutable'), (error) => error instanceof SoulError);
});
