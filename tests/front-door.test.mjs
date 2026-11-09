// The front door, through the executable as the owner's tools would run it:
// `agent-bot-souls run` is an ACP agent on stdio, and `agent-bot-souls chat`
// is a terminal chat. Both give one conversation, which is the lead's.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { readFileSync, rmSync } from 'node:fs';
import { rpcPeer } from '../lib/jsonrpc.mjs';
import { BIN, makeSoul, SOUL, startHQ } from './harness.mjs';

async function world(soulOptions) {
  const t = await startHQ();
  const root = makeSoul(soulOptions);
  const owner = await t.owner();
  const offer = async () => (await owner.request('tasks.offer', { operation_id: `offer_${Date.now()}`, objective: 'Repair the seeded issue.', done_criteria: 'Checks pass.', accountable_soul: SOUL })).result.task_id;
  const task = async (taskId) => (await owner.request('tasks.get', { task_id: taskId })).result.task;
  const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^(AGENT_BOT_|QWTS_AGENT_)/.test(k)));
  const run = (cmd) => spawn(process.execPath, [BIN, cmd, '--soul', root, '--hq-home', t.home], { env, stdio: ['pipe', 'pipe', 'pipe'] });
  return { ...t, root, offer, task, run, done: async () => { await t.done(); rmSync(root, { recursive: true, force: true }); } };
}

test('agent-bot-souls run is an ACP agent: initialize, a session, a prompt streamed from the lead, end_turn', async () => {
  const t = await world();
  const child = t.run('run');
  try {
    const updates = [];
    const client = rpcPeer({ input: child.stdout, output: child.stdin, onNotify: (method, params) => updates.push([method, params]) });
    const init = await client.request('initialize', { protocolVersion: 1, clientCapabilities: {} });
    assert.equal(init.protocolVersion, 1);
    assert.deepEqual(init.authMethods, []);
    assert.equal(init.agentCapabilities.loadSession, false);

    const { sessionId } = await client.request('session/new', { cwd: t.root, mcpServers: [] });
    const other = await client.request('session/new', { cwd: t.root, mcpServers: [] });
    assert.notEqual(other.sessionId, sessionId, 'a new session of the same Soul');

    const taskId = await t.offer();
    const result = await client.request('session/prompt', { sessionId, prompt: [{ type: 'text', text: 'Please work the waiting task.' }] });
    assert.deepEqual(result, { stopReason: 'end_turn' });
    assert.ok(updates.length > 0);
    for (const [method, params] of updates) {
      assert.equal(method, 'session/update');
      assert.equal(params.sessionId, sessionId, 'updates go to the session that prompted');
      assert.equal(params.update.sessionUpdate, 'agent_message_chunk');
    }
    assert.match(updates.map(([, p]) => p.update.content.text).join(''), new RegExp(`Completed ${taskId}`));
    assert.equal((await t.task(taskId)).status, 'completed');

    // Refused, as JSON-RPC errors: an unknown session, a prompt that is not text, an unknown method.
    await assert.rejects(client.request('session/prompt', { sessionId: 'sess_other', prompt: [{ type: 'text', text: 'x' }] }), { code: -32602 });
    await assert.rejects(client.request('session/prompt', { sessionId, prompt: [{ type: 'image', data: 'x' }] }), { code: -32602 });
    await assert.rejects(client.request('fs/read_text_file', { path: '/etc/passwd' }), { code: -32601 });

    // The client leaving ends the Soul's run cleanly.
    child.stdin.end();
    const [code] = await once(child, 'exit');
    assert.equal(code, 0);
    assert.equal((await (await t.owner()).request('souls.list', {})).result[0].soul_id, SOUL);
  } finally { child.kill('SIGKILL'); await t.done(); }
});

test('an unavailable Soul answers the prompt with the reason and stopReason refusal', async () => {
  const t = await world({ lead: { fail: 'credential' } });
  const child = t.run('run');
  try {
    const updates = [];
    const client = rpcPeer({ input: child.stdout, output: child.stdin, onNotify: (method, params) => updates.push(params) });
    await client.request('initialize', { protocolVersion: 1 });
    const { sessionId } = await client.request('session/new', { cwd: t.root, mcpServers: [] });
    assert.deepEqual(await client.request('session/prompt', { sessionId, prompt: [{ type: 'text', text: 'work' }] }), { stopReason: 'refusal' });
    assert.match(updates.map((u) => u.update.content.text).join(''), /the Soul is waiting: credential_unavailable/);
  } finally { child.kill('SIGKILL'); await t.done(); }
});

test('agent-bot-souls chat is the same conversation in a terminal', async () => {
  const t = await world();
  const child = t.run('chat');
  try {
    let out = '';
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (text) => { out += text; });
    const taskId = await t.offer();
    child.stdin.write('Please work the waiting task.\n/status\n/quit\n');
    const [code] = await once(child, 'exit');
    assert.equal(code, 0);
    assert.match(out, new RegExp(`Completed ${taskId} from m_spec's proposal`));
    const status = JSON.parse(out.slice(out.indexOf('{')));
    assert.deepEqual([status.state, status.soul_id, status.profile], ['ready', SOUL, 'managed-cooperative']);
    assert.equal((await t.task(taskId)).status, 'completed');
  } finally { child.kill('SIGKILL'); await t.done(); }
});

test('the executable reports its version and refuses what it does not know', () => {
  const version = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;
  assert.equal(execFileSync(process.execPath, [BIN, '--version'], { encoding: 'utf8' }).trim(), version);
  for (const argv of [[], ['dance'], ['run'], ['run', '--soul'], ['chat', '--soul', '/tmp/x', '--bogus'], ['member', 'steal']]) {
    assert.throws(() => execFileSync(process.execPath, [BIN, ...argv], { stdio: 'pipe' }), (e) => e.status === 1 && /agent-bot-souls: /.test(e.stderr.toString()), argv.join(' '));
  }
  // `member` outside a member process says why.
  assert.throws(() => execFileSync(process.execPath, [BIN, 'member', 'runtime'], { stdio: 'pipe', env: { PATH: process.env.PATH } }), (e) => /not started by agent-bot-souls/.test(e.stderr.toString()));
});
