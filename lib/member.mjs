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
import { connectHq, HqRefusal } from './hq-client.mjs';

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
const NONCE = /^[0-9a-f]{64}$/;
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
  let rt;
  let broker;

  async function bind(fresh) {
    if (broker && !broker.closed && !fresh) return;
    if (broker) { broker.destroy(); broker = undefined; }
    rt = await entry.request('runtime');
    const next = await connectHq(env.AGENT_BOT_SOULS_BROKER || rt.broker, { contracts });
    try {
      const challenge = await next.request('bind.challenge', { runtime_id: rt.runtime_id });
      // Only the proof this member knows how to make; anything else is not
      // answered, least of all with the binding.
      if (challenge?.algorithm !== 'hmac-sha256' || challenge.context !== BIND_CONTEXT || challenge.runtime_id !== rt.runtime_id || typeof challenge.nonce !== 'string' || !NONCE.test(challenge.nonce)) {
        throw new Error('HQ offered a bind challenge this member cannot answer');
      }
      await next.request('bind', { runtime_id: rt.runtime_id, proof: bindProof(rt.channel_binding, challenge.nonce, rt.runtime_id) });
    } catch (e) { next.destroy(); throw e; }
    broker = next;
  }
  const stale = (e) => e instanceof HqRefusal && (e.transport || e.code === 'lease_expired');

  // A read: safe to repeat once on a fresh binding.
  async function read(kind, message) {
    await bind(false);
    try {
      return await broker.request(kind, message);
    } catch (e) {
      if (!stale(e)) throw e;
      await bind(true);
      return broker.request(kind, message);
    }
  }
  const get = (taskId) => read('task.get', { task_id: taskId });

  const build = (input) => ({
    contract: 'task/v1',
    request_id: `req_${randomBytes(8).toString('hex')}`,
    task_id: input.task_id,
    expected_revision: input.expected_revision,
    installation_epoch: rt.installation_epoch,
    runtime_id: rt.runtime_id,
    lease_generation: rt.lease_generation,
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
    await bind(false);
    const request = build(input);
    try {
      return await broker.request('task.commit', request);
    } catch (e) {
      if (!stale(e)) throw e;
      const unknown = e.transport;
      await bind(true);
      const sameRuntime = rt.runtime_id === request.runtime_id && rt.lease_generation === request.lease_generation;
      if (sameRuntime) {
        // Lost reply, same runtime: the identical request is idempotent.
        try { return await broker.request('task.commit', request); } catch (again) { if (!stale(again)) throw again; }
        return lookup(request);
      }
      // A refusal is a known outcome: nothing committed, so the new runtime
      // may send the operation. After a lost reply only the record can say.
      if (unknown) return lookup(request);
      try {
        return await broker.request('task.commit', build(input));
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
    runtime: async () => { await bind(false); const { channel_binding: _binding, ...rest } = rt; return rest; },
    directives: async () => (await read('task.directives', {})).directives,
    get,
    commit,
    // Lead only: hand a prompt to the member with this role and wait for
    // its turn to end.
    route: (role, prompt, { task_id: taskId } = {}) => entry.request('route', { role, prompt, ...(taskId ? { task_id: taskId } : {}) }),
    note: (note) => entry.request('note', note),
    handoffs: async () => (await entry.request('handoffs')).notes,
    async close() {
      if (broker) await broker.close().catch(() => {});
      await entry.close().catch(() => {});
    },
    // Test hook: lose the broker connection as a crash of the link would.
    dropBroker() { broker?.destroy(); },
  };
}
