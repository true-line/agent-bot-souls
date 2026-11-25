// Mechanical member-side session extracted from true-line/agent-bot-souls
// lib/member.mjs at 2097b8dc129737df23ae1fb1f8dc30eb4f7d8033.
// No host authority lives here.
import { createHmac } from 'node:crypto';
import { connectHq, HqRefusal, isRetryableMemberReadFailure } from './local-socket-client.mjs';

// HQ's bind proof: HMAC-SHA256 keyed by the channel binding, over the
// context, the challenge's nonce and the runtime ID (hq/admission.mjs).
export const BIND_CONTEXT = 'agent-bot-hq/bind/v1';
const NONCE = /^[0-9a-f]{64}$(?![\s\S])/;
const RUNTIME_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$(?![\s\S])/;
const CHANNEL_BINDING = /^[A-Za-z0-9_-]{16,128}$(?![\s\S])/;
const SOUL_ID = /^agent_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$(?![\s\S])/;
const MEMBER_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$(?![\s\S])/;
const ROLE = /^[a-z][a-z0-9-]{0,31}$(?![\s\S])/;
export function bindProof(channelBinding, nonce, runtimeId) {
  return createHmac('sha256', Buffer.from(channelBinding, 'utf8')).update(`${BIND_CONTEXT}\n${nonce}\n${runtimeId}`).digest('hex');
}


// Transport-owner integration only. Member surfaces receive the narrower
// connectMemberQueries result, never this facade.
export async function openMemberSession({ memberSocket, memberToken, brokerSocket, contracts, signal } = {}) {
  if (typeof memberSocket !== 'string' || !memberSocket || typeof memberToken !== 'string' || !memberToken
    || (brokerSocket !== undefined && (typeof brokerSocket !== 'string' || !brokerSocket))) throw new TypeError('member bootstrap needs its existing socket and member token');
  signal?.throwIfAborted();
  const entry = await connectHq(memberSocket, { contracts, signal });
  let me;
  try {
    me = await entry.request('hello', { token: memberToken });
    if (!me || typeof me !== 'object' || Array.isArray(me)
      || !Object.hasOwn(me, 'soul_id') || typeof me.soul_id !== 'string' || !SOUL_ID.test(me.soul_id)
      || !Object.hasOwn(me, 'member_id') || typeof me.member_id !== 'string' || !MEMBER_ID.test(me.member_id)
      || !Object.hasOwn(me, 'role') || typeof me.role !== 'string' || !ROLE.test(me.role)) throw new Error('entry point returned invalid member identity');
    signal?.throwIfAborted();
  } catch (error) {
    entry.destroy();
    await entry.close().catch(() => {});
    throw error;
  }
  let bound;
  let pending;
  let closed = false;
  let closing;
  const candidates = new Set();
  const retiring = new Set();
  const captures = new WeakMap();
  const invalidated = new WeakSet();
  const open = () => { signal?.throwIfAborted(); if (closed) throw new HqRefusal('member', { transport: 'member client is closed' }); };

  async function establish() {
    const runtime = await entry.request('runtime');
    open();
    if (!runtime || typeof runtime.runtime_id !== 'string' || !RUNTIME_ID.test(runtime.runtime_id)
      || typeof runtime.channel_binding !== 'string' || !CHANNEL_BINDING.test(runtime.channel_binding)
      || !Number.isSafeInteger(runtime.installation_epoch) || runtime.installation_epoch < 1
      || !Number.isSafeInteger(runtime.lease_generation) || runtime.lease_generation < 1) throw new Error('entry point returned invalid runtime binding metadata');
    const next = await connectHq(brokerSocket || runtime.broker, { contracts, signal });
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
            if (!signal?.aborted && isRetryableMemberReadFailure(error)) invalidated.add(pair);
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

  const pairOf = (captured) => {
    const pair = captures.get(captured);
    if (!pair) throw new TypeError('unknown member query capture');
    return pair;
  };
  return Object.freeze({
    member: Object.freeze({ member_id: me.member_id, role: me.role, soul_id: me.soul_id }),
    capture: async () => (await binding()).captured,
    reconnect: async (captured) => (await reconnect(pairOf(captured))).captured,
    isRetryableReadFailure: (error, captured) => !signal?.aborted && captures.has(captured) && isRetryableMemberReadFailure(error),
    runtimeFor(captured) {
      const { channel_binding: _binding, ...metadata } = pairOf(captured).runtime;
      return Object.freeze(metadata);
    },
    // Preserve the owner's task.commit-specific recovery path: it uses the
    // captured raw connection, not the generic query wrapper's invalidation.
    requestOnce: (captured, kind, payload) => pairOf(captured).broker.request(kind, payload),
    entryRequest(operation, payload) {
      if (!['route', 'note', 'handoffs'].includes(operation)) throw new TypeError('owner entry request is route, note or handoffs');
      return entry.request(operation, payload);
    },
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
    // Existing owner/test hook, never on the member-facing query capability.
    dropBroker() { const old = bound; bound = undefined; old?.broker.destroy(); },
  });
}
