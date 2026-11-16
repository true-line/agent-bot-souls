// The member's side: what a lead or specialist uses from inside its own
// process to reach the entry point and HQ's broker. An adapter that is a
// program imports this; a harness that only runs commands uses
// `agent-bot-souls member <op>`, which wraps it.
//
// The entry point starts a member with two variables:
//   AGENT_BOT_SOULS_SOCKET        the entry point's member socket
//   AGENT_BOT_SOULS_MEMBER_TOKEN  this member process's token for it
// Over that socket the member learns its current runtime and binding, asks
// the entry point to route work by role, and writes typed notes. With the
// runtime it binds its own connection to HQ's broker and reads directives
// and tasks and sends task/v1 commitments there. HQ decides every one of
// them; nothing here is authority.
//
// The bind (agent-bot-hq plan §9 row 16a). The member asks HQ for a
// challenge and answers with a proof keyed by its channel binding. The
// binding itself is never sent to the broker, and there is no fallback that
// sends it. A member that runs in its own OS account has its own broker
// endpoint, which only that account can open; whoever starts the member
// there names it in
//   AGENT_BOT_SOULS_BROKER        this member's own broker endpoint
// Without it the member uses the broker the entry point reports. The path
// is not authority: HQ knows which account each endpoint belongs to.
//
// Recovery (0.4 §7 and §9):
// - A runtime that a newer admission superseded is refused with
//   `lease_expired`. The member asks the entry point for its current
//   runtime, binds again and repeats the request.
// - A commitment whose reply was lost has an unknown outcome. It is
//   reconciled, never replayed under a new key: the identical request is
//   sent again while the runtime is the same, which returns the stored
//   receipt if it committed (T05). Otherwise the task is read back and its
//   record says whether the commitment landed.
import { createHmac, randomBytes } from 'node:crypto';
import { loadContracts } from './contracts.mjs';
import { connectHq, HqRefusal, isRetryableMemberReadFailure } from './hq-client.mjs';
import { createMemberQueryPort } from './vendor/agent-bot-sdk/member-query.mjs';

export class NotCommitted extends Error {
  constructor(request, task) {
    super(`operation ${request.operation_id} did not commit; task ${request.task_id} is ${task.status} at revision ${task.revision}`);
    this.name = 'NotCommitted';
    this.code = 'not_committed';
    this.task = task;
  }
}

// HQ's bind proof: HMAC-SHA256 keyed by the channel binding, over the
// context, the challenge's nonce and the runtime ID (hq/admission.mjs).
export const BIND_CONTEXT = 'agent-bot-hq/bind/v1';
const NONCE = /^[0-9a-f]{64}$(?![\s\S])/;
const RUNTIME_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$(?![\s\S])/;
const CHANNEL_BINDING = /^[A-Za-z0-9_-]{16,128}$(?![\s\S])/;
export function bindProof(channelBinding, nonce, runtimeId) {
  return createHmac('sha256', Buffer.from(channelBinding, 'utf8')).update(`${BIND_CONTEXT}\n${nonce}\n${runtimeId}`).digest('hex');
}

export async function connectMember(env = process.env) {
  const path = env.AGENT_BOT_SOULS_SOCKET;
  const token = env.AGENT_BOT_SOULS_MEMBER_TOKEN;
  if (!path || !token) throw new Error('this process was not started by agent-bot-souls: AGENT_BOT_SOULS_SOCKET and AGENT_BOT_SOULS_MEMBER_TOKEN are not set');
  const contracts = loadContracts({ directory: env.AGENT_BOT_SOUL_CONTRACTS });
  const entry = await connectHq(path, { contracts });
  let me;
  try {
    me = await entry.request('hello', { token });
  } catch (e) { await entry.close().catch(() => {}); throw e; }
  let bound;
  let pending;
  let closed = false;
  let closing;
  const candidates = new Set();
  const retiring = new Set();
  const captures = new WeakMap();
  const invalidated = new WeakSet();
  const open = () => { if (closed) throw new HqRefusal('member', { transport: 'member client is closed' }); };

  async function establish() {
    const runtime = await entry.request('runtime');
    open();
    if (!runtime || typeof runtime.runtime_id !== 'string' || !RUNTIME_ID.test(runtime.runtime_id)
      || typeof runtime.channel_binding !== 'string' || !CHANNEL_BINDING.test(runtime.channel_binding)
      || !Number.isSafeInteger(runtime.installation_epoch) || runtime.installation_epoch < 1
      || !Number.isSafeInteger(runtime.lease_generation) || runtime.lease_generation < 1) throw new Error('entry point returned invalid runtime binding metadata');
    const next = await connectHq(env.AGENT_BOT_SOULS_BROKER || runtime.broker, { contracts });
    candidates.add(next);
    try {
      open();
      const challenge = await next.request('bind.challenge', { runtime_id: runtime.runtime_id });
      if (challenge?.algorithm !== 'hmac-sha256' || challenge.context !== BIND_CONTEXT || challenge.runtime_id !== runtime.runtime_id || typeof challenge.nonce !== 'string' || !NONCE.test(challenge.nonce)) {
        throw new Error('HQ offered a bind challenge this member cannot answer');
      }
      const confirmed = await next.request('bind', { runtime_id: runtime.runtime_id, proof: bindProof(runtime.channel_binding, challenge.nonce, runtime.runtime_id) });
      if (confirmed?.runtime_id !== runtime.runtime_id) throw new Error('HQ bind did not confirm this runtime');
      open();
      // Publish only the completed pair. Every capture sends on this socket,
      // even if another operation later replaces the current binding.
      let pair;
      const captured = Object.freeze({
        freshness: Object.freeze({ installation_epoch: runtime.installation_epoch, lease_generation: runtime.lease_generation }),
        async request(kind, payload) {
          open();
          try { return await next.request(kind, payload); }
          catch (error) {
            // This never resends or reconnects the failing operation. A later
            // explicit capture may repair this exact stale/failed pair.
            if (isRetryableMemberReadFailure(error)) invalidated.add(pair);
            throw error;
          }
        },
      });
      pair = Object.freeze({ runtime: Object.freeze(runtime), broker: next, captured });
      captures.set(captured, pair);
      bound = pair;
      return pair;
    } catch (error) { next.destroy(); throw error; }
    finally { candidates.delete(next); }
  }

  function binding() {
    open();
    if (pending) return pending;
    if (bound && !bound.broker.closed) return invalidated.has(bound) ? reconnect(bound) : Promise.resolve(bound);
    const attempt = establish();
    pending = attempt;
    const clear = () => { if (pending === attempt) pending = undefined; };
    attempt.then(clear, clear);
    return attempt;
  }

  function reconnect(previous) {
    open();
    if (pending) return pending;
    // Another operation already recovered this attempt. Never destroy its
    // replacement while recovering a late refusal from the older socket.
    if (bound && bound !== previous && !bound.broker.closed) return binding();
    const previousBroker = bound?.broker;
    bound = undefined;
    if (previousBroker) retiring.add(previousBroker);
    const replacement = binding();
    const retire = () => { previousBroker?.destroy(); retiring.delete(previousBroker); };
    replacement.then(retire, retire);
    return replacement;
  }

  const queries = createMemberQueryPort({
    capture: async () => (await binding()).captured,
    reconnect: async (captured) => {
      const previous = captures.get(captured);
      if (!previous) throw new TypeError('unknown member query capture');
      return (await reconnect(previous)).captured;
    },
    isRetryableReadFailure: (error, captured) => captures.has(captured) && isRetryableMemberReadFailure(error),
  });
  const stale = (e) => e instanceof HqRefusal && (e.transport || e.code === 'lease_expired');
  const read = (kind, message) => queries.request(kind, () => message, { replay: 'read-once' });
  const get = (taskId) => read('task.get', { task_id: taskId });

  const build = (input, runtime) => ({
    contract: 'task/v1',
    request_id: `req_${randomBytes(8).toString('hex')}`,
    task_id: input.task_id,
    expected_revision: input.expected_revision,
    installation_epoch: runtime.installation_epoch,
    runtime_id: runtime.runtime_id,
    lease_generation: runtime.lease_generation,
    operation_id: input.operation_id,
    transition: input.transition,
    ...(input.result_ref !== undefined ? { result_ref: input.result_ref } : {}),
    ...(input.evidence_refs !== undefined ? { evidence_refs: input.evidence_refs } : {}),
  });

  // Did this operation land? Read the record back; never send it again
  // under another key.
  async function lookup(request) {
    const { task, proposals } = await get(request.task_id);
    const proposal = proposals.find((p) => p.operation_id === request.operation_id);
    if (proposal) return { contract: 'task/v1', operation_id: request.operation_id, task_id: task.task_id, outcome: 'proposal', proposal_id: proposal.proposal_id, status: task.status, revision: task.revision, reconciled: true };
    if (task.revision === request.expected_revision + 1 && task.status === request.transition) {
      return { contract: 'task/v1', operation_id: request.operation_id, task_id: task.task_id, outcome: 'committed', status: task.status, revision: task.revision, reconciled: true };
    }
    throw new NotCommitted(request, task);
  }

  // input: { task_id, expected_revision, operation_id, transition, result_ref?, evidence_refs? }
  async function commit(input) {
    let pair = await binding();
    const request = build(input, pair.runtime);
    try {
      return await pair.broker.request('task.commit', request);
    } catch (e) {
      if (!stale(e)) throw e;
      const unknown = e.transport;
      pair = await reconnect(pair);
      const sameRuntime = pair.runtime.runtime_id === request.runtime_id && pair.runtime.lease_generation === request.lease_generation;
      if (sameRuntime) {
        // Lost reply, same runtime: the identical request is idempotent.
        try { return await pair.broker.request('task.commit', request); } catch (again) { if (!stale(again)) throw again; }
        return lookup(request);
      }
      // A refusal is a known outcome: nothing committed, so the new runtime
      // may send the operation. After a lost reply only the record can say.
      if (unknown) return lookup(request);
      try {
        return await pair.broker.request('task.commit', build(input, pair.runtime));
      } catch (again) {
        if (again instanceof HqRefusal && (again.transport || ['caller_mismatch', 'host.invalid_request'].includes(again.code))) return lookup(request);
        throw again;
      }
    }
  }

  return {
    member_id: me.member_id,
    role: me.role,
    soul_id: me.soul_id,
    queries,
    runtime: async () => { const { channel_binding: _binding, ...rest } = (await binding()).runtime; return rest; },
    directives: async () => (await read('task.directives', {})).directives,
    get,
    commit,
    // Lead only: hand a prompt to the member with this role and wait for
    // its turn to end.
    route: (role, prompt, { task_id: taskId } = {}) => entry.request('route', { role, prompt, ...(taskId ? { task_id: taskId } : {}) }),
    note: (note) => entry.request('note', note),
    handoffs: async () => (await entry.request('handoffs')).notes,
    close() {
      if (closing) return closing;
      closed = true;
      // Abort pending entry/bind requests too. A late candidate can neither
      // publish itself nor resurrect this closed member client.
      entry.destroy();
      bound?.broker.destroy();
      for (const candidate of candidates) candidate.destroy();
      for (const old of retiring) old.destroy();
      closing = Promise.all([entry.close().catch(() => {}), pending?.catch(() => {})]).then(() => undefined);
      return closing;
    },
    // Test hook: lose the broker connection as a crash of the link would.
    dropBroker() { const old = bound; bound = undefined; old?.broker.destroy(); },
  };
}
