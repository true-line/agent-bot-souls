// The front door, through the executable as the owner's tools would run it:
// `agent-bot-souls run` is an ACP agent on stdio, and `agent-bot-souls chat`
// is a terminal chat. Both give one conversation, which is the lead's.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile, execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { existsSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { rpcPeer } from '../lib/jsonrpc.mjs';
import { BIN, fake, makeSoul, SOUL, startHQ } from './harness.mjs';

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

test('ACP cancellation targets the named session and the lead can continue afterwards', { timeout: 15_000 }, async () => {
  const adapter = `
    import { rpcPeer, RpcError } from ${JSON.stringify(new URL('../lib/jsonrpc.mjs', import.meta.url).href)};
    const sessionId = 'native_session';
    let finish;
    let cancellations = 0;
    const peer = rpcPeer({ input: process.stdin, output: process.stdout, methods: {
      initialize: async () => ({ protocolVersion: 1 }),
      'session/new': async () => ({ sessionId }),
      'session/cancel': async (params) => {
        if (params.sessionId !== sessionId) return;
        cancellations++;
        finish?.();
        finish = undefined;
      },
      'session/prompt': async (params) => {
        const text = params.prompt.at(-1).text;
        const say = (reply) => peer.notify('session/update', { sessionId, update: {
          sessionUpdate: 'agent_message_chunk', content: { type: 'text', text: reply },
        } });
        if (text.startsWith('hold')) {
          await new Promise((resolve) => {
            finish = text === 'hold until disconnect' ? () => process.exit(70) : resolve;
            say('turn in progress');
          });
          if (text === 'hold with request cancelled') throw new RpcError(-32800, 'fixture acknowledged cancellation');
          if (text === 'hold with provider failure') throw new RpcError(-32603, 'fixture provider failed');
          return { stopReason: text === 'hold to completion' ? 'end_turn' : 'cancelled' };
        }
        if (text.startsWith('retained ')) say(text);
        else if (text === 'continue' && cancellations === 1) say('continued in the same adapter session');
        else if (text === 'recover after disconnect' && cancellations === 0) say('continued after adapter recovery');
        else say('unexpected prompt or cancellation');
        return { stopReason: 'end_turn' };
      },
    } });`;
  const t = await world({ adapters: {
    'fake-lead': { command: [process.execPath, '--input-type=module', '-e', adapter] },
    'fake-specialist': fake(),
  } });
  const child = t.run('run');
  const exited = once(child, 'exit');
  try {
    let entered;
    const waitForActive = () => new Promise((resolve) => { entered = resolve; });
    const updates = [];
    const client = rpcPeer({ input: child.stdout, output: child.stdin, onNotify: (_method, params) => {
      const text = params?.update?.content?.text;
      updates.push([params.sessionId, text]);
      if (text === 'turn in progress') entered();
    } });
    await client.request('initialize', { protocolVersion: 1 });
    const createSession = () => client.request('session/new', { cwd: t.root, mcpServers: [] });
    const { sessionId: first } = await createSession();
    const { sessionId: second } = await createSession();
    const prompt = (sessionId, text) => client.request('session/prompt', { sessionId, prompt: [{ type: 'text', text }] });
    const cancel = (sessionId) => client.notify('session/cancel', { sessionId });
    const active = waitForActive();
    const lead = prompt(first, 'hold');
    lead.catch(() => {}); // The fixture can fail before it releases the lead.
    await active;
    let timeout;
    const deadline = new Promise((_, reject) => {
      timeout = setTimeout(() => reject(new Error('queued cancellation waited for the lead')), 3000);
    });
    try {
      for (let i = 0; i < 32; i++) {
        const queued = prompt(second, 'queued prompt must not run');
        cancel('unknown_session');
        cancel(second);
        assert.deepEqual(await Promise.race([queued, deadline]), { stopReason: 'cancelled' });
      }
    } finally { clearTimeout(timeout); }
    const remaining = Promise.all([lead, prompt(second, 'retained first'), prompt(first, 'retained second')]);
    cancel(first);
    assert.deepEqual(await remaining, [{ stopReason: 'cancelled' }, { stopReason: 'end_turn' }, { stopReason: 'end_turn' }]);
    assert.deepEqual(await prompt(first, 'continue'), { stopReason: 'end_turn' });
    assert.deepEqual(updates, [[first, 'turn in progress'], [second, 'retained first'], [first, 'retained second'], [first, 'continued in the same adapter session']]);
    for (const [text, stopReason] of [['hold with request cancelled', 'cancelled'], ['hold to completion', 'end_turn']]) {
      const running = waitForActive();
      const turn = prompt(first, text);
      await running;
      cancel(first);
      assert.deepEqual(await turn, { stopReason });
    }
    const failing = waitForActive();
    const refusal = assert.rejects(prompt(first, 'hold with provider failure'), { code: -32603, message: 'fixture provider failed' });
    await failing;
    cancel(first);
    await refusal;
    const admittedBeforeCrash = t.hq.core.receipts.filter((row) => row.kind === 'hq.admission').length;
    const disconnecting = waitForActive();
    const disconnected = assert.rejects(prompt(first, 'hold until disconnect'), { code: -32603, message: /connection closed/ });
    await disconnecting;
    cancel(first);
    await disconnected;
    assert.equal(t.hq.core.receipts.filter((row) => row.kind === 'hq.admission').length, admittedBeforeCrash, 'the cancelled turn was not retried');
    assert.deepEqual(await prompt(first, 'recover after disconnect'), { stopReason: 'end_turn' });
    assert.deepEqual(updates.at(-1), [first, 'continued after adapter recovery']);
    assert.equal(t.hq.core.receipts.filter((row) => row.kind === 'hq.admission').length, admittedBeforeCrash + 1, 'the later turn readmitted the member');
    child.stdin.end();
    assert.deepEqual(await exited, [0, null]);
  } finally { child.kill('SIGKILL'); await exited; await t.done(); }
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

for (const mode of ['run', 'chat']) test(`the ${mode} executable refuses a protected profile before startup`, async () => {
  const t = await world();
  try {
    await assert.rejects(promisify(execFile)(process.execPath, [BIN, mode, '--soul', t.root, '--hq-home', t.home, '--profile', 'managed-protected'], { timeout: 5000 }), (error) => {
      assert.equal(error.code, 1);
      const lines = error.stderr.trim().split('\n');
      const event = JSON.parse(lines[0]);
      assert.deepEqual(event, { event: 'profile-refused', code: 'profile_insufficient', source: 'local', requested_profile: 'managed-protected' });
      assert.match(lines[1], /agent-bot-souls: the Soul is unavailable: profile_insufficient: Machine-authenticated protected Soul launch inputs are unavailable/);
      return true;
    });
    assert.equal(existsSync(join(t.root, 'Contents/host/installation.json')), false);
  } finally { await t.done(); }
});

test('run and chat reject an option missing its value before HQ admission', async () => {
  const t = await world();
  const execute = promisify(execFile);
  try {
    for (const cmd of ['run', 'chat']) {
      for (const [option, tail] of [
        ['--profile', ['--profile']],
        ['--hq-home', ['--hq-home']],
        ['--soul', ['--soul', '--profile', 'managed-protected']],
      ]) {
        await assert.rejects(execute(process.execPath, [BIN, cmd, '--soul', t.root, '--hq-home', t.home, ...tail],
          { timeout: 5000, env: { ...process.env, AGENT_BOT_HQ_HOME: t.home } }), (error) => {
          assert.equal(error.code, 1);
          assert.equal(error.stderr.trim(), `agent-bot-souls: ${option} requires a value`);
          return true;
        });
      }
    }
    assert.equal(t.hq.core.receipts.some(receipt => receipt.kind === 'hq.admission'), false);
  } finally { await t.done(); }
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
