// Shared setup: the real HQ from agent-bot-hq with agent-comms's broker
// plugin serving broker.sock, a Soul package in a temporary directory whose
// members run the fake adapter, and the entry point started on it.
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { startSoul } from '../lib/entry-point.mjs';
import { checkout } from './pinned.mjs';

const hqDir = checkout('agent-bot-hq');
const commsDir = checkout('agent-bot-comms');
const load = (dir, rel) => import(pathToFileURL(join(dir, rel)).href);
const hqHarness = await load(hqDir, 'tests/hq-harness.mjs');
const { brokerPlugin } = await load(commsDir, 'lib/hq-plugin/broker.mjs');
export const { validate } = await load(hqDir, 'sdk/wire/schema.mjs');
export const { connectSocket } = await load(hqDir, 'hq/socket.mjs');
export const { bindProof: hqBindProof } = await load(hqDir, 'hq/admission.mjs');
export const { SOUL, DIGEST, hello } = hqHarness;
export const schema = (rel) => JSON.parse(readFileSync(join(hqHarness.contracts, 'schemas', rel), 'utf8'));
export const fixture = (rel) => JSON.parse(readFileSync(join(hqHarness.contracts, 'fixtures', rel), 'utf8'));

export const BIN = fileURLToPath(new URL('../bin/agent-bot-souls.mjs', import.meta.url));
export const FAKE = [process.execPath, BIN, 'fake-adapter'];
const scenarioEnv = (scenario) => (scenario ? { FAKE_ADAPTER_SCENARIO: JSON.stringify(scenario) } : {});

export const startHQ = (options = {}) => hqHarness.startHQ({ plugins: [brokerPlugin()], ...options });

// A Soul package: a lead and a specialist on fake adapters. `lead` and
// `spec` are fake-adapter scenarios. `info`, `lock` and `adapters` replace
// the generated files.
export function makeSoul({ lead, spec, info, lock, adapters } = {}) {
  const root = mkdtempSync(join(tmpdir(), 's-'));
  const contents = join(root, 'Contents');
  mkdirSync(join(contents, 'host'), { recursive: true });
  const write = (rel, value) => writeFileSync(join(contents, rel), `${JSON.stringify(value, null, 2)}\n`);
  write('SoulInfo.json', info ?? {
    soul_id: SOUL,
    members: [
      { member_id: 'm_lead', role: 'lead', adapter_id: 'fake-lead', adapter_version: '0.1.0' },
      { member_id: 'm_spec', role: 'specialist', adapter_id: 'fake-specialist', adapter_version: '0.1.0' },
    ],
  });
  write('SoulLock.json', lock ?? { definition_digest: DIGEST });
  write('host/adapters.json', adapters ?? {
    'fake-lead': { command: FAKE, env: scenarioEnv(lead) },
    'fake-specialist': { command: FAKE, env: scenarioEnv(spec) },
  });
  return root;
}
export const fake = (scenario, extra = {}) => ({ command: FAKE, env: scenarioEnv(scenario), ...extra });

export async function setup({ soul: soulOptions, hq: hqOptions } = {}) {
  const t = await startHQ(hqOptions);
  const root = makeSoul(soulOptions);
  const delays = [];
  let soul;
  try {
    soul = await startSoul({ root, hqHome: t.home, delay: async (ms) => { delays.push(ms); }, renewEveryMs: 0 });
  } catch (e) {
    await t.done();
    rmSync(root, { recursive: true, force: true });
    throw e;
  }
  const owner = await t.owner();
  let n = 0;
  const offer = async (over = {}) => {
    n += 1;
    const res = await owner.request('tasks.offer', { operation_id: `offer_${n}`, objective: 'Repair the seeded issue.', done_criteria: 'Checks pass.', accountable_soul: SOUL, write_scope: [`workspace:scratch-${n}`], ...over });
    if (!res.ok) throw new Error(JSON.stringify(res));
    return res.result.task_id;
  };
  const task = async (taskId) => (await owner.request('tasks.get', { task_id: taskId })).result;
  const receipts = (kind) => t.hq.core.receipts.filter((r) => r.kind === kind);
  const done = async () => {
    await soul.stop();
    await t.done();
    rmSync(root, { recursive: true, force: true });
  };
  return { ...t, root, contents: join(root, 'Contents'), soul, delays, owner, offer, task, receipts, done };
}
