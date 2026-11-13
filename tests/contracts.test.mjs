// Refs #5. Every shared fixture is loaded from the verified release, not
// copied here and not validated by importing HQ's test validator.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { cpSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { canonicalDigest, canonicalize, checkRequiredCapabilities, CONTRACT_PIN, ContractError, loadContracts, negotiateVersions, parseStrict, SCHEMAS, SUPPORTED_VERSIONS } from '../lib/contracts.mjs';
import { checkout } from './pinned.mjs';

const contracts = loadContracts();
const root = contracts.directory;
const read = (path) => readFileSync(join(root, path));
const load = (path) => JSON.parse(read(path));
const list = (kind) => readdirSync(join(root, 'fixtures', kind)).filter((f) => f.endsWith('.json')).sort().map((file) => [file, load(`fixtures/${kind}/${file}`)]);
const positives = list('positive');
const negatives = list('negative');

test('runtime schemas/strict parser reproduce every shared fixture verdict', () => {
  const seen = new Set();
  for (const [name, fixture] of [...positives, ...negatives]) {
    seen.add(fixture.schema);
    if (fixture.expect.parse === 'invalid') {
      assert.throws(() => contracts.decode(fixture.schema, fixture.input_raw), (error) => error.code === 'host.invalid_json', name);
    } else if (fixture.expect.schema === 'valid') {
      assert.deepEqual(contracts.decode(fixture.schema, JSON.stringify(fixture.input)), fixture.input, name);
    } else {
      assert.throws(() => contracts.decode(fixture.schema, JSON.stringify(fixture.input)), ContractError, name);
    }
    if (fixture.base) {
      const bytes = read(`fixtures/${fixture.base.fixture}`);
      assert.equal(`sha256:${createHash('sha256').update(bytes).digest('hex')}`, fixture.base.sha256, `${name}: negative base byte pin`);
    }
  }
  // A new contract record cannot escape the consumer coverage silently.
  const schemas = (dir, prefix = '') => readdirSync(dir, { withFileTypes: true }).flatMap((entry) => entry.isDirectory() ? schemas(join(dir, entry.name), `${prefix}${entry.name}/`) : entry.name.endsWith('.schema.json') ? [`${prefix}${entry.name}`] : []);
  assert.deepEqual([...seen].sort(), schemas(join(root, 'schemas')).sort());
  assert.equal(positives.length, 33);
  assert.equal(negatives.length, 55);
});

test('runtime canonicalization matches every positive and all JCS vectors', () => {
  for (const [name, fixture] of positives) assert.equal(canonicalDigest(fixture.input), fixture.canonical_sha256, name);
  for (const vector of load('fixtures/canonicalization/jcs.json').vectors) {
    assert.equal(canonicalize(vector.input), vector.canonical, vector.id);
    assert.equal(canonicalDigest(vector.input), vector.canonical_sha256, vector.id);
  }
});

test('runtime independently refuses the T14 unsupported-version and capability fixtures', () => {
  const version = load('fixtures/negative/hello.unsupported-version.json');
  contracts.record(version.schema, version.input); // this negative is schema-valid
  assert.throws(() => negotiateVersions(version.input.supported_versions, SUPPORTED_VERSIONS), (e) => e.code === version.expect.error);
  const capability = load('fixtures/negative/wire-frame.unknown-required-capability.json');
  assert.throws(() => contracts.frame(capability.input, capability.context.negotiated_capabilities), (e) => e.code === capability.expect.error);
  assert.doesNotThrow(() => checkRequiredCapabilities(['sealed-inner-v1'], ['sealed-inner-v1']));
  const hello = load('fixtures/positive/hello.first-start.json').input;
  const result = load('fixtures/positive/admission-result.ok.json').input;
  contracts.admission(result, hello);
  assert.throws(() => contracts.admission({ ...result, negotiated_versions: { hq: 3, wire: 1 } }, hello), (e) => e.code === 'unsupported_version');
  assert.throws(() => contracts.admission({ ...result, request_id: 'req_other' }, hello), /does not answer/);
  assert.throws(() => contracts.admission(result, { ...hello, supported_versions: { hq: [2], wire: [1] } }), (e) => e.code === 'unsupported_version');
});

test('missing or tampered contract dependencies refuse instead of disabling validation', (t) => {
  const work = mkdtempSync(join(tmpdir(), 'souls-contract-pin-'));
  t.after(() => rmSync(work, { recursive: true, force: true }));
  assert.throws(() => loadContracts({ directory: join(work, 'missing') }), (e) => e.code === 'souls.contracts_unavailable');
  const copy = join(work, 'release');
  cpSync(root, copy, { recursive: true });
  assert.doesNotThrow(() => loadContracts({ directory: copy }));
  const schema = join(copy, 'schemas', SCHEMAS.hello);
  writeFileSync(schema, '{}\n');
  assert.throws(() => loadContracts({ directory: copy }), /does not match the release manifest/);
});

test('vendored SDK codec bytes match their pinned source and the runtime contract pin agrees with HQ', () => {
  const vendor = new URL('../lib/vendor/agent-bot-sdk/', import.meta.url);
  const source = JSON.parse(readFileSync(new URL('source.json', vendor), 'utf8'));
  const hq = checkout('agent-bot-hq');
  assert.equal(source.commit, JSON.parse(readFileSync(new URL('../governance/pins.json', import.meta.url), 'utf8'))['agent-bot-hq'].commit);
  for (const [path, digest] of Object.entries(source.files)) {
    const bytes = readFileSync(new URL(path.replace(/^sdk\//, ''), vendor));
    assert.equal(createHash('sha256').update(bytes).digest('hex'), digest, path);
    assert.ok(bytes.equals(readFileSync(join(hq, path))), `${path}: equals pinned SDK`);
  }
  assert.deepEqual(CONTRACT_PIN, JSON.parse(readFileSync(join(hq, 'governance/soul-contracts.json'), 'utf8')));
  // Strict parsing is the same production function used on HQ/member sockets.
  assert.throws(() => parseStrict('{"ok":true,"ok":false}'), (e) => e.code === 'host.invalid_json');
});
