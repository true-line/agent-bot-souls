// The Soul entry point (agent-bot-hq plan §9 row 14; 0.4 §3, §5, §9). It:
//
// - clocks the Soul in with HQ on admission.sock: Hello, Equip, Ready, and
//   Lease renewals;
// - starts each member's adapter as its own process and drives it over the
//   Agent Client Protocol (ACP) on stdio, one turn at a time per member;
// - gives the owner one conversation, which is the lead's;
// - routes work by role when the lead asks;
// - keeps typed notes, and gives a returning lead its handoff notes before
//   it continues;
// - runs the recovery ladder when a member fails.
//
// It holds no authority. It has no keys and decides no grant. A member
// commits to a task itself, over its own connection to HQ's broker, and HQ
// decides. The entry point only passes each member the runtime HQ admitted
// it as. In the cooperative profile that binding is a bearer secret inside
// the Soul, which HQ reports as `managed-cooperative`.
//
// A restarted member is a new runtime, so a restart is a new admission. The
// new lease generation fences the old lead: nothing it still holds can
// finalize a task. Members that kept running pick up their new runtime the
// next time HQ refuses the old one.
import { spawn } from 'node:child_process';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, unlinkSync } from 'node:fs';
import { connect, createServer } from 'node:net';
import { join } from 'node:path';
import { connectHq, HqRefusal } from './hq-client.mjs';
import { rpcPeer, RpcError } from './jsonrpc.mjs';
import { readLines, writeLine } from './ndjson.mjs';
import { handoffs, NoteError, restrictions, writeNote } from './notes.mjs';
import { classify, createLadder } from './recovery.mjs';
import { LEAD, readSoul } from './soul.mjs';

export const ACP_PROTOCOL_VERSION = 1;
const MAX_PROMPT = 65536;
// sun_path with its NUL: 104 bytes on macOS and the BSDs, 108 on Linux.
const MAX_SOCKET_PATH = (process.platform === 'linux' ? 108 : 104) - 1;

// The Soul cannot take the turn. `state` says why: quarantined, waiting,
// needs-owner, unavailable or stopped.
export class SoulUnavailable extends Error {
  constructor(state, reason) {
    super(`the Soul is ${state}: ${reason}`);
    this.name = 'SoulUnavailable';
    this.state = state;
    this.reason = reason;
  }
}

class MemberRefusal extends Error {
  constructor(code, message) { super(message); this.code = code; }
}
const refuse = (code, message) => { throw new MemberRefusal(code, message); };

// Is something listening on `path`? Tells a stale socket file from another
// entry point that is running this Soul.
const live = (path) => new Promise((resolve) => {
  const s = connect(path);
  s.once('connect', () => { s.destroy(); resolve(true); });
  s.once('error', () => resolve(false));
});

const sleep = (ms) => new Promise((r) => { setTimeout(r, ms); });
const hex = (n) => randomBytes(n).toString('hex');
const sameToken = (a, b) => a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));

// A member's environment: the entry point's own, without anything that
// names another agent-bot identity, plus the adapter's and the member's.
function memberEnv(base, adapterEnv, own) {
  const env = {};
  for (const [k, v] of Object.entries(base)) if (v !== undefined && !/^(AGENT_BOT_|QWTS_AGENT_)/.test(k)) env[k] = v;
  return { ...env, ...adapterEnv, ...own };
}

export async function startSoul({ root, hqHome, delay = sleep, clock = { now: () => Date.now() }, log = () => {}, renewEveryMs = 20_000, env = process.env } = {}) {
  const soul = readSoul(root);
  const socketPath = join(soul.host, 'members.sock');
  if (Buffer.byteLength(socketPath) > MAX_SOCKET_PATH) throw new Error(`socket path ${socketPath} is longer than ${MAX_SOCKET_PATH} bytes; move the Soul to a shorter path`);
  if (existsSync(socketPath)) {
    if (await live(socketPath)) throw new Error(`another entry point is running this Soul (${socketPath})`);
    unlinkSync(socketPath);
  }
  const hq = await connectHq(join(hqHome, 'admission.sock'));
  const brokerPath = join(hqHome, 'broker.sock');
  const ladder = createLadder({ clock });
  const members = new Map(soul.members.map((spec) => [spec.member_id, {
    spec, route: 0, proc: null, rpc: null, sessionId: null, token: null, runtime: null,
    queue: Promise.resolve(), briefed: false, turn: null, idleCrash: false, connections: new Set(),
  }]));
  const lead = [...members.values()].find((m) => m.spec.role === LEAD);
  const events = [];
  let state = 'starting';
  let reason;
  let admission;
  let stopped = false;
  let timer;
  const current = (m) => m.spec.routes[m.route];
  const record = (event) => { events.push({ at: new Date(clock.now()).toISOString(), ...event }); log(event); };
  const unavailable = (next, why) => { state = next; reason = why; return new SoulUnavailable(next, why); };

  // --- Admission (hq/v1) --------------------------------------------------

  let admitting = Promise.resolve();
  // One admission at a time; a second caller waits for the first.
  function admit() {
    const run = admitting.then(async () => {
      const decision = await hq.request('Hello', {
        contract: 'hq/v1',
        request_id: `req_${hex(8)}`,
        soul_id: soul.soul_id,
        definition_digest: soul.definition_digest,
        installation_id: soul.installation_id,
        supported_versions: { hq: [1], wire: [1] },
        supported_capabilities: [],
        requested_profile: 'managed-cooperative',
        requested_roles: [...members.values()].map((m) => ({ role: m.spec.role, member_id: m.spec.member_id, adapter_id: current(m).adapter_id, adapter_version: current(m).adapter_version })),
      });
      for (const a of decision.admitted_runtimes) {
        const m = members.get(a.member_id);
        if (!m) throw new Error(`HQ admitted an unknown member ${a.member_id}`);
        m.runtime = { runtime_id: a.runtime_id, channel_binding: a.channel_binding, installation_epoch: decision.installation_epoch, lease_generation: decision.lease_generation, sequence: 0, ready: false };
        await hq.request('Equip', { runtime_id: a.runtime_id });
      }
      admission = decision;
      record({ event: 'admitted', installation_epoch: decision.installation_epoch, lease_generation: decision.lease_generation, profile: decision.profile });
      // Members that are running are ready under their new runtime at once.
      for (const m of members.values()) if (m.proc) await ready(m);
    });
    admitting = run.catch(() => {});
    return run;
  }
  const renewal = (m, readiness) => ({
    contract: 'hq/v1',
    runtime_id: m.runtime.runtime_id,
    installation_epoch: m.runtime.installation_epoch,
    readiness_state: readiness,
    auth_state: 'authenticated',
    adapter_versions: { [current(m).adapter_id]: current(m).adapter_version },
    lease_generation: m.runtime.lease_generation,
    renewal_sequence: ++m.runtime.sequence,
    observed_health: m.proc ? 'healthy' : 'unreachable',
  });
  async function ready(m) {
    await hq.request('Ready', renewal(m, 'cold'));
    m.runtime.ready = true;
  }
  // Renew every ready runtime's lease. A lease HQ no longer honours is
  // stale, not stopped: the Soul is admitted again.
  async function renew() {
    try {
      for (const m of members.values()) if (m.runtime?.ready) await hq.request('Lease', renewal(m, 'warm'));
    } catch (e) {
      if (!(e instanceof HqRefusal) || !['lease_expired', 'stale_epoch'].includes(e.code)) throw e;
      record({ event: 'lease-stale', code: e.code });
      await admit();
    }
  }

  // --- Members (ACP client) -----------------------------------------------

  async function startMember(m) {
    const adapter = current(m);
    const home = join(soul.contents, 'home', m.spec.member_id);
    mkdirSync(home, { recursive: true, mode: 0o700 });
    m.token = hex(24);
    m.briefed = false;
    const proc = spawn(adapter.command[0], adapter.command.slice(1), {
      cwd: home,
      stdio: ['pipe', 'pipe', 'pipe'],
      env: memberEnv(env, adapter.env, {
        AGENT_BOT_SOULS_SOCKET: socketPath,
        AGENT_BOT_SOULS_MEMBER_TOKEN: m.token,
        AGENT_BOT_SOULS_MEMBER_ID: m.spec.member_id,
        AGENT_BOT_SOULS_ROLE: m.spec.role,
      }),
    });
    const rpc = rpcPeer({
      input: proc.stdout,
      output: proc.stdin,
      // The entry point decides no grant, so it never approves a permission
      // request on the owner's behalf.
      methods: { 'session/request_permission': async () => ({ outcome: { outcome: 'cancelled' } }) },
      onNotify: (method, params) => { if (method === 'session/update' && params?.sessionId === m.sessionId) m.turn?.update(params.update); },
    });
    m.proc = proc;
    m.rpc = rpc;
    m.exited = new Promise((resolve) => {
      const gone = (why) => {
        if (m.proc === proc) { m.proc = null; if (!m.turn && !stopped) m.idleCrash = true; }
        rpc.close(why);
        resolve();
      };
      proc.once('exit', (code, signal) => gone(`member exited (${signal ?? code})`));
      proc.once('error', (e) => gone(`member did not start: ${e.message}`));
    });
    proc.stderr.setEncoding('utf8');
    proc.stderr.on('data', (text) => log({ event: 'member-stderr', member_id: m.spec.member_id, text }));
    const init = await rpc.request('initialize', { protocolVersion: ACP_PROTOCOL_VERSION, clientCapabilities: { fs: { readTextFile: false, writeTextFile: false }, terminal: false } });
    if (init?.protocolVersion !== ACP_PROTOCOL_VERSION) throw new RpcError(-32603, `adapter speaks ACP ${init?.protocolVersion}, not ${ACP_PROTOCOL_VERSION}`, { closed: true });
    const session = await rpc.request('session/new', { cwd: home, mcpServers: [] });
    m.sessionId = session.sessionId;
    m.idleCrash = false;
    await ready(m);
    record({ event: 'member-started', member_id: m.spec.member_id, adapter_id: adapter.adapter_id });
  }

  async function stopMember(m) {
    for (const c of m.connections) c.destroy();
    m.connections.clear();
    const proc = m.proc;
    m.proc = null;
    m.token = null;
    if (!proc) return;
    proc.kill('SIGTERM');
    const killer = setTimeout(() => proc.kill('SIGKILL'), 2000);
    await m.exited;
    clearTimeout(killer);
  }

  // What a returning lead reads before it continues (0.4 §9).
  function brief(m) {
    const notes = handoffs(soul.contents);
    return {
      type: 'text',
      text: [
        `Brief from the entry point. You are ${m.spec.member_id}, the lead of ${soul.soul_id}.`,
        'Before continuing, read your waiting directives and your open tasks from HQ, and reconcile anything whose outcome you do not know.',
        notes.length ? `Handoff notes, oldest first:\n${JSON.stringify(notes, null, 2)}` : 'There are no handoff notes.',
      ].join('\n'),
    };
  }

  // Take the rung of the recovery ladder for this failure. Returns when the
  // turn may be tried again and throws when it may not.
  async function recover(m, failureClass) {
    const action = ladder.next(failureClass, { memberId: m.spec.member_id, routes: m.spec.routes, route: m.route, restrictions: restrictions(soul.contents) });
    record({ event: 'recovery', member_id: m.spec.member_id, failure: failureClass, ...action });
    switch (action.action) {
      case 'restart':
        await stopMember(m);
        await delay(action.delayMs);
        if (stopped) throw new SoulUnavailable('stopped', 'the entry point stopped');
        await admit();
        return;
      case 're-equip':
        try {
          await hq.request('Equip', { runtime_id: m.runtime.runtime_id });
        } catch (e) {
          if (e instanceof HqRefusal) throw unavailable('needs-owner', `HQ did not re-equip ${m.spec.member_id}: ${e.code}`);
          throw e;
        }
        return;
      case 'fail-over':
        await stopMember(m);
        m.route = action.route;
        await admit();
        return;
      case 'quarantine':
        for (const other of members.values()) await stopMember(other);
        throw unavailable('quarantined', `five member crashes within an hour; the owner reviews and releases the Soul`);
      case 'wait':
        throw unavailable('waiting', action.reason);
      case 'owner-decision':
        throw unavailable('needs-owner', action.reason);
      case 'pause':
      case 'unavailable':
        throw unavailable('unavailable', action.reason);
      default:
        throw new Error(`no recovery for ${failureClass}`);
    }
  }

  const failureOf = (e) => {
    if (e instanceof RpcError) return e.data?.closed ? { kind: 'exit' } : { kind: 'rpc', code: e.code, data: e.data };
    return undefined;
  };

  async function attempt(m, blocks, onChunk) {
    for (;;) {
      if (stopped) throw new SoulUnavailable('stopped', 'the entry point stopped');
      if (ladder.quarantined) throw new SoulUnavailable('quarantined', reason ?? 'quarantined');
      let failed;
      try {
        if (m.idleCrash) { m.idleCrash = false; failed = 'crash'; throw new RpcError(-32603, 'member exited between turns', { closed: true }); }
        if (!m.proc) await startMember(m);
        let text = '';
        m.turn = { update(u) { if (u?.sessionUpdate === 'agent_message_chunk' && u.content?.type === 'text') { text += u.content.text; onChunk?.(u.content.text); } } };
        const prompt = m === lead && !m.briefed ? [brief(m), ...blocks] : blocks;
        const result = await m.rpc.request('session/prompt', { sessionId: m.sessionId, prompt });
        m.briefed = true;
        ladder.healthy(m.spec.member_id);
        if (state !== 'ready') { state = 'ready'; reason = undefined; }
        return { member_id: m.spec.member_id, stop_reason: result?.stopReason ?? 'end_turn', text };
      } catch (e) {
        failed = failed ?? classify(failureOf(e));
        if (!failed) throw e;
      } finally {
        m.turn = null;
      }
      await recover(m, failed);
    }
  }
  // One turn at a time per member.
  function turn(m, blocks, onChunk) {
    const run = m.queue.then(() => attempt(m, blocks, onChunk));
    m.queue = run.catch(() => {});
    return run;
  }

  // --- The member socket ----------------------------------------------------

  const memberOps = {
    runtime: (m) => ({
      broker: brokerPath, soul_id: soul.soul_id, member_id: m.spec.member_id, role: m.spec.role,
      runtime_id: m.runtime.runtime_id, channel_binding: m.runtime.channel_binding,
      installation_epoch: m.runtime.installation_epoch, lease_generation: m.runtime.lease_generation,
    }),
    // Role routing: the lead hands work to the member with a role.
    async route(m, payload) {
      if (m !== lead) refuse('souls.not_lead', 'only the lead routes work');
      if (!payload || typeof payload.role !== 'string' || typeof payload.prompt !== 'string' || payload.prompt.length < 1 || payload.prompt.length > MAX_PROMPT) refuse('souls.invalid_request', 'route takes { role, prompt, task_id? }');
      const target = [...members.values()].find((x) => x.spec.role === payload.role && x !== m);
      if (!target) refuse('souls.unknown_role', `no other member has the role ${payload.role}`);
      record({ event: 'routed', from: m.spec.member_id, to: target.spec.member_id, role: payload.role, ...(typeof payload.task_id === 'string' ? { task_id: payload.task_id } : {}) });
      try {
        return await turn(target, [{ type: 'text', text: payload.prompt }]);
      } catch (e) {
        if (e instanceof SoulUnavailable) refuse('souls.member_unavailable', e.message);
        refuse('souls.turn_failed', String(e?.message ?? e));
      }
      return undefined;
    },
    note(m, payload) {
      try {
        const note = writeNote(soul.contents, payload, { note_id: `note_${hex(8)}`, member_id: m.spec.member_id, runtime_id: m.runtime.runtime_id, timestamp: new Date(clock.now()).toISOString() });
        return { note_id: note.note_id };
      } catch (e) {
        if (e instanceof NoteError) refuse('souls.invalid_request', e.message);
        throw e;
      }
    },
    handoffs: () => ({ notes: handoffs(soul.contents) }),
  };

  const server = createServer((socket) => {
    let member;
    const reply = (id, fn) => Promise.resolve().then(fn).then(
      (result) => writeLine(socket, { id, ok: true, result: result === undefined ? null : result }),
      (e) => writeLine(socket, { id, ok: false, host_refusal: { code: e instanceof MemberRefusal ? e.code : 'souls.internal', explanation: String(e?.message ?? e) } }),
    );
    readLines(socket, (line) => {
      let req;
      try { req = JSON.parse(line); } catch { socket.destroy(); return; }
      if (!req || typeof req !== 'object' || typeof req.op !== 'string') { socket.destroy(); return; }
      reply(req.id, () => {
        if (req.op === 'hello') {
          const token = req.payload?.token;
          const found = typeof token === 'string' ? [...members.values()].find((x) => x.token && sameToken(x.token, token)) : undefined;
          if (!found) refuse('souls.unknown_member', 'the token is not a running member\'s');
          member = found;
          found.connections.add(socket);
          return { soul_id: soul.soul_id, member_id: found.spec.member_id, role: found.spec.role };
        }
        if (!member) refuse('souls.unknown_member', 'a member says hello with its token first');
        if (!Object.hasOwn(memberOps, req.op)) refuse('souls.unknown_op', `no operation ${req.op}`);
        return memberOps[req.op](member, req.payload);
      });
    }, () => socket.destroy());
    socket.on('error', () => {});
    socket.on('close', () => member?.connections.delete(socket));
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(socketPath, () => { server.off('error', reject); resolve(); });
  });
  chmodSync(socketPath, 0o600);

  // --- Start ----------------------------------------------------------------

  async function stop() {
    if (stopped) return;
    stopped = true;
    state = 'stopped';
    clearInterval(timer);
    for (const m of members.values()) await stopMember(m);
    await new Promise((resolve) => { server.close(() => resolve()); });
    try { unlinkSync(socketPath); } catch { /* already gone */ }
    await hq.close().catch(() => {});
  }

  try {
    await admit();
  } catch (e) {
    await stop();
    throw e;
  }
  if (renewEveryMs > 0) {
    timer = setInterval(() => { renew().catch((e) => record({ event: 'renew-failed', error: String(e?.message ?? e) })); }, renewEveryMs);
    timer.unref();
  }
  state = 'ready';

  return {
    soul_id: soul.soul_id,
    // The owner's conversation: one turn of the lead. `onChunk(text)`
    // receives the lead's reply as it arrives.
    async prompt(text, onChunk) {
      if (typeof text !== 'string' || text.length < 1 || text.length > MAX_PROMPT) throw new RangeError(`a prompt is 1 to ${MAX_PROMPT} characters`);
      return turn(lead, [{ type: 'text', text }], onChunk);
    },
    cancel() { if (lead.proc && lead.sessionId) lead.rpc.notify('session/cancel', { sessionId: lead.sessionId }); },
    renew,
    // The owner reviewed a quarantined Soul and releases it.
    release() { ladder.release(); state = 'ready'; reason = undefined; record({ event: 'released' }); },
    status: () => ({
      state,
      ...(reason ? { reason } : {}),
      soul_id: soul.soul_id,
      installation_id: soul.installation_id,
      installation_epoch: admission.installation_epoch,
      lease_generation: admission.lease_generation,
      profile: admission.profile,
      warnings: admission.warnings ?? [],
      members: [...members.values()].map((m) => ({ member_id: m.spec.member_id, role: m.spec.role, adapter_id: current(m).adapter_id, running: Boolean(m.proc), runtime_id: m.runtime?.runtime_id })),
    }),
    events: () => [...events],
    stop,
  };
}
