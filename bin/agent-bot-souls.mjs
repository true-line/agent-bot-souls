#!/usr/bin/env node
// agent-bot-souls: the Soul runtime's executable (platform PDR-0037),
// reached through the shim as `agent-bot souls …`.
//
//   agent-bot-souls run  --soul DIR [--hq-home DIR] [--profile PROFILE]   the ACP front door, on stdio
//   agent-bot-souls chat --soul DIR [--hq-home DIR] [--profile PROFILE]   a terminal chat with the Soul
//   agent-bot-souls member <op> [JSON]                a member's requests, from inside a member
//   agent-bot-souls fake-adapter                      the fake ACP adapter (testing and demos)
//
// DIR for --soul is the package directory (the one that holds Contents/).
// --hq-home is HQ's state directory: $AGENT_BOT_HQ_HOME, else ~/.agent-bot-hq.
import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { startSoul } from '../lib/entry-point.mjs';
import { runFakeAdapter } from '../lib/fake-adapter.mjs';
import { chat, serveAcp } from '../lib/front-door.mjs';
import { connectMember } from '../lib/member.mjs';

const USAGE = `usage:
  agent-bot-souls run  --soul DIR [--hq-home DIR | --admission-socket PATH --broker-socket PATH] [--profile managed-cooperative|managed-protected]
  agent-bot-souls chat --soul DIR [--hq-home DIR | --admission-socket PATH --broker-socket PATH] [--profile managed-cooperative|managed-protected]
  agent-bot-souls member <runtime|directives|handoffs|get|commit|route|note> [JSON]
  agent-bot-souls fake-adapter
  agent-bot-souls --version`;

const MEMBER_OPS = {
  runtime: (m) => m.runtime(),
  directives: (m) => m.directives(),
  handoffs: (m) => m.handoffs(),
  get: (m, a) => m.get(a.task_id),
  commit: (m, a) => m.commit(a),
  route: (m, a) => m.route(a.role, a.prompt, { task_id: a.task_id }),
  note: (m, a) => m.note(a),
};

function options(argv) {
  const out = {};
  const optionsWithValues = ['--soul', '--hq-home', '--admission-socket', '--broker-socket', '--profile'];
  for (let i = 0; i < argv.length; i += 2) {
    const option = argv[i];
    if (!optionsWithValues.includes(option)) throw new Error(`unknown argument ${option}`);
    const value = argv[i + 1];
    if (!value || optionsWithValues.includes(value)) throw new Error(`${option} requires a value`);
    if (Object.hasOwn(out, option.slice(2))) throw new Error(`${option} may only be supplied once`);
    out[option.slice(2)] = value;
  }
  if (!out.soul) throw new Error('--soul DIR is required');
  const explicit = out['admission-socket'] !== undefined || out['broker-socket'] !== undefined;
  return { root: out.soul, ...(explicit
    ? { admissionSocket: out['admission-socket'], brokerSocket: out['broker-socket'], ...(out['hq-home'] !== undefined ? { hqHome: out['hq-home'] } : {}) }
    : { hqHome: out['hq-home'] ?? process.env.AGENT_BOT_HQ_HOME ?? join(homedir(), '.agent-bot-hq') }), requestedProfile: out.profile ?? 'managed-cooperative' };
}

async function main([cmd, ...rest]) {
  if (cmd === '--version') {
    process.stdout.write(`${JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version}\n`);
    return 0;
  }
  if (cmd === 'fake-adapter') { runFakeAdapter(); return undefined; }
  if (cmd === 'member') {
    const [op, json] = rest;
    if (!Object.hasOwn(MEMBER_OPS, op ?? '')) throw new Error(USAGE);
    const member = await connectMember();
    try {
      process.stdout.write(`${JSON.stringify(await MEMBER_OPS[op](member, json ? JSON.parse(json) : {}), null, 2)}\n`);
    } finally { await member.close(); }
    return 0;
  }
  if (cmd === 'run' || cmd === 'chat') {
    const soul = await startSoul({ ...options(rest), log: (e) => { if (cmd === 'run' || e.event !== 'member-stderr') process.stderr.write(`${JSON.stringify(e)}\n`); } });
    let stop;
    const signal = new Promise((resolve) => { stop = () => resolve(); });
    process.on('SIGINT', stop);
    process.on('SIGTERM', stop);
    let failure;
    try {
      const frontDoor = cmd === 'run' ? serveAcp : chat;
      const serving = frontDoor({ soul, input: process.stdin, output: process.stdout }).catch((error) => { failure = error; });
      await Promise.race([serving, signal]);
      try { await soul.stop(); }
      catch (error) {
        if (failure) throw new AggregateError([failure, error], `${failure.message}\n${error.message}`);
        throw error;
      }
      if (failure) throw failure;
    } finally {
      process.off('SIGINT', stop);
      process.off('SIGTERM', stop);
    }
    return 0;
  }
  throw new Error(USAGE);
}

function exitFailure(error) {
  process.stderr.write(`agent-bot-souls: ${error.message}\n`, () => process.exit(1));
}

main(process.argv.slice(2)).then(
  (code) => { if (code !== undefined) process.exit(code); },
  exitFailure,
);
