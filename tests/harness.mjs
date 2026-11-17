// Shared setup: the real HQ from agent-bot-hq with agent-comms's broker
// plugin serving broker.sock, a Soul package in a temporary directory whose
// members run the fake adapter, and the entry point started on it.
import { spawn as nodeSpawn } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { connect as netConnect, createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pipeline } from 'node:stream';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { startSoul } from '../lib/entry-point.mjs';
import { readLines, writeLine } from '../lib/ndjson.mjs';
import { checkout } from './pinned.mjs';

const hqDir = checkout('agent-bot-hq');
const commsDir = checkout('agent-bot-comms');
const load = (dir, rel) => import(pathToFileURL(join(dir, rel)).href);
const hqHarness = await load(hqDir, 'tests/hq-harness.mjs');
const { brokerPlugin } = await load(commsDir, 'lib/hq-plugin/broker.mjs');
export const { validate } = await load(hqDir, 'sdk/wire/schema.mjs');
export const { connectSocket } = await load(hqDir, 'hq/socket.mjs');
export const { bindProof: hqBindProof } = await load(hqDir, 'hq/admission.mjs');
export const { SOUL, DIGEST, hello, helloOn, harnessLayout, fakeSudo } = hqHarness;
export const schema = (rel) => JSON.parse(readFileSync(join(hqHarness.contracts, 'schemas', rel), 'utf8'));
export const fixture = (rel) => JSON.parse(readFileSync(join(hqHarness.contracts, 'fixtures', rel), 'utf8'));

export const BIN = fileURLToPath(new URL('../bin/agent-bot-souls.mjs', import.meta.url));
export const FAKE = [process.execPath, BIN, 'fake-adapter'];
const scenarioEnv = (scenario) => (scenario ? { FAKE_ADAPTER_SCENARIO: JSON.stringify(scenario) } : {});

export const startHQ = (options = {}) => hqHarness.startHQ({ plugins: [brokerPlugin()], ...options });

// A transparent test proxy for admission replies. It keeps the real pinned
// HQ on both sides of the boundary while allowing a regression to corrupt or
// downgrade one selected reply. Broker traffic is forwarded unchanged.
export async function hqProxy(hq, transformReply = ({ reply }) => reply) {
  const home = mkdtempSync(join(tmpdir(), 'souls-hq-proxy-'));
  const servers = [];
  const sockets = new Set();
  const counts = new Map();
  const listen = async (name, connection) => {
    const server = createServer(connection);
    servers.push(server);
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(join(home, name), resolve); });
  };
  await listen('admission.sock', (client) => {
    const upstream = netConnect(join(hq.home, 'admission.sock'));
    sockets.add(client); sockets.add(upstream);
    const pending = new Map();
    const close = () => { client.destroy(); upstream.destroy(); };
    for (const socket of [client, upstream]) {
      socket.on('error', close);
      socket.on('close', () => sockets.delete(socket));
    }
    readLines(client, (line) => {
      const request = JSON.parse(line);
      pending.set(request.id, request);
      writeLine(upstream, request);
    }, close);
    readLines(upstream, (line) => {
      const reply = JSON.parse(line);
      const request = pending.get(reply.id);
      pending.delete(reply.id);
      const op = request?.op ?? request?.method;
      const count = (counts.get(op) ?? 0) + 1;
      counts.set(op, count);
      Promise.resolve(transformReply({ op, request, reply, count })).then(
        (output) => writeLine(client, output),
        close,
      );
    }, close);
  });
  await listen('broker.sock', (client) => {
    const upstream = netConnect(join(hq.home, 'broker.sock'));
    sockets.add(client); sockets.add(upstream);
    const close = () => { client.destroy(); upstream.destroy(); };
    for (const socket of [client, upstream]) {
      socket.on('error', close);
      socket.on('close', () => sockets.delete(socket));
    }
    pipeline(client, upstream, (error) => { if (error) close(); });
    pipeline(upstream, client, (error) => { if (error) close(); });
  });
  return {
    home,
    async done() {
      for (const socket of sockets) socket.destroy();
      await Promise.all(servers.map((server) => new Promise((resolve) => server.close(resolve))));
      rmSync(home, { recursive: true, force: true });
    },
  };
}

// Execute HQ's exact injected sudo argv as this test user. The real-account
// kernel boundary remains HQ's CI lane; this gives Souls a real pinned HQ,
// real launch/attach streams, the fixed wrapper, and real adapter processes.
export function accountLaunch(layout) {
  const calls = [];
  const spawn = (file, args, options) => {
    if (file !== '/usr/bin/sudo') throw new Error(`unexpected launcher ${file}`);
    const split = args.indexOf('--');
    if (split === -1 || !args[split + 1]) throw new Error(`unexpected sudo argv ${JSON.stringify(args)}`);
    const account = args[1] === '-H' ? args[3] : args[2];
    const launch = args[1] === '-H';
    const child = nodeSpawn(args[split + 1], args.slice(split + 2), {
      ...options,
      ...(launch ? { env: { ...options.env, HOME: layout.homes[account] } } : {}),
    });
    calls.push({ file, args, options, child });
    return child;
  };
  return { spawn, calls };
}

export function accountHQ(layout = harnessLayout()) {
  const launch = accountLaunch(layout);
  return {
    layout,
    launch,
    options: {
      platform: 'linux', accounts: layout.resolve, harnessLstat: layout.lstat, launch: { spawn: launch.spawn },
      config: { acceptedDefinitions: { [SOUL]: [DIGEST] }, harnesses: { dir: layout.dir, accounts: { 'fake-lead': 'hqm_a', 'fake-specialist': 'hqm_b' } } },
    },
  };
}

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

export async function setup({ soul: soulOptions, hq: hqOptions, runtime: runtimeOptions } = {}) {
  const t = await startHQ(hqOptions);
  const root = makeSoul(soulOptions);
  const delays = [];
  let soul;
  try {
    soul = await startSoul({ root, hqHome: t.home, delay: async (ms) => { delays.push(ms); }, renewEveryMs: 0, ...runtimeOptions });
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
