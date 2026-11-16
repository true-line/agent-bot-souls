// Transport/provider integration, not notice-consumer or MCP acceptance:
// the reviewed SDK port runs against real pinned HQ admission, broker and
// durable store; a test-only kind handler isolates connection/replay effects.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createConnection, createServer } from 'node:net';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { connectMember } from '../lib/member.mjs';
import { readLines, writeLine } from '../lib/ndjson.mjs';
import { checkout } from './pinned.mjs';
import { hello, SOUL, startHQ } from './harness.mjs';

const { definePlugin } = await import(pathToFileURL(join(checkout('agent-bot-hq'), 'sdk/plugin.mjs')));
const { fail } = await import(pathToFileURL(join(checkout('agent-bot-hq'), 'sdk/errors.mjs')));
const { brokerPlugin } = await import(pathToFileURL(join(checkout('agent-bot-comms'), 'lib/hq-plugin/broker.mjs')));
const deferred = () => { let resolve; const promise = new Promise((r) => { resolve = r; }); return { promise, resolve }; };

async function listening(path, accept) {
  const sockets = new Set();
  const server = createServer((socket) => {
    sockets.add(socket); socket.on('error', () => {}); socket.on('close', () => sockets.delete(socket)); accept(socket);
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(path, resolve); });
  return { path, close: () => new Promise((resolve) => { for (const socket of sockets) socket.destroy(); server.close(resolve); }) };
}

async function world(t, { beforeBind, beforeQuery, reply } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'mq-'));
  const members = [];
  const upstream = new Set();
  const frames = [];
  const state = { runtime: null, asked: 0, received: [], binds: 0, dropped: 0 };
  let hq, entry, proxy;
  t.after(async () => { for (const member of members) await member.close(); for (const socket of upstream) socket.destroy(); await proxy?.close(); await entry?.close(); await hq?.done(); rmSync(dir, { recursive: true, force: true }); });
  const handler = definePlugin({
    name: 'query-transport-fixture', version: '0.1.0', hostApi: 1, requires: { 'hq-admission': '^0.1.0' }, services: ['store'],
    async init(ctx) {
      for (const kind of ['notices.peek', 'notices.consume-one']) ctx.broker.registerKind({ kind, async consume(message, meta) {
        state.received.push({ kind, message, runtime_id: meta.runtime_id });
        if (beforeQuery) await beforeQuery({ kind, message, meta, state });
        return ctx.deps['hq-admission'].withBoundRuntime(meta.runtime_id, async (rt) => {
          if (message.installation_epoch !== rt.epoch) fail('stale_epoch', 'test query epoch differs');
          if (message.lease_generation !== rt.lease_generation) fail('lease_expired', 'test query generation differs');
          let effect;
          if (kind === 'notices.consume-one') effect = await ctx.services.store.tx((tx) => {
            const n = (tx.get('effects', 'count') ?? 0) + 1; tx.put('effects', 'count', n); return n;
          });
          return { installation_epoch: rt.epoch, lease_generation: rt.lease_generation, runtime_id: meta.runtime_id, ...(effect ? { effect } : {}) };
        });
      } });
    },
  });
  hq = await startHQ({ plugins: [brokerPlugin({ beforeBind: async () => { state.binds++; if (beforeBind) await beforeBind(state); } }), handler] });
  const admission = await hq.entry();
  let sequence = 0;
  const admit = async () => {
    const response = await admission.request('Hello', hello({ request_id: `provider_${++sequence}` }));
    assert.equal(response.ok, true, JSON.stringify(response));
    const value = response.result;
    const runtime = value.admitted_runtimes[0];
    state.runtime = { runtime_id: runtime.runtime_id, channel_binding: runtime.channel_binding, installation_epoch: value.installation_epoch, lease_generation: value.lease_generation };
    return state.runtime;
  };
  await admit();
  entry = await listening(join(dir, 'member.sock'), (socket) => readLines(socket, (line) => {
    const request = JSON.parse(line);
    if (request.op === 'hello') {
      assert.equal(request.payload.token, 'MEMBER_TOKEN_CANARY');
      writeLine(socket, { id: request.id, ok: true, result: { soul_id: SOUL, member_id: 'm_lead', role: 'lead' } });
    } else if (request.op === 'runtime') {
      state.asked++;
      writeLine(socket, { id: request.id, ok: true, result: { broker: proxy.path, ...state.runtime } });
    } else throw new Error('unexpected member request');
  }));
  proxy = await listening(join(dir, 'proxy.sock'), (client) => {
    const server = createConnection(hq.hq.paths.broker);
    upstream.add(server); server.on('error', () => client.destroy()); server.on('close', () => { upstream.delete(server); client.destroy(); }); client.on('close', () => server.destroy());
    const pending = new Map();
    readLines(client, (line) => { const request = JSON.parse(line); frames.push(request); pending.set(request.id, request); writeLine(server, request); });
    readLines(server, (line) => {
      const result = JSON.parse(line); const request = pending.get(result.id); const kind = request?.op; pending.delete(result.id);
      const output = reply ? reply({ kind, result, request, state }) : result;
      if (output === null) { state.dropped++; client.destroy(); server.destroy(); }
      else if (output !== undefined) writeLine(client, output);
    });
  });
  const connect = async (overrides = {}) => {
    const member = await connectMember({ AGENT_BOT_SOULS_SOCKET: entry.path, AGENT_BOT_SOULS_MEMBER_TOKEN: 'MEMBER_TOKEN_CANARY', ...overrides });
    members.push(member); return member;
  };
  return { hq, state, frames, connect, admit };
}

const build = (freshness) => ({ ...freshness });

test('real HQ: an empty optional broker override uses the authenticated runtime endpoint', async (t) => {
  const w = await world(t);
  const member = await w.connect({ AGENT_BOT_SOULS_BROKER: '' });
  const result = await member.queries.request('notices.peek', build);
  assert.equal(result.runtime_id, w.state.runtime.runtime_id);
  assert.equal(w.state.binds, 1);
  assert.equal(w.state.asked, 1);
  assert.equal(w.state.received.length, 1);
  assert.equal(w.state.received[0].runtime_id, w.state.runtime.runtime_id);
});

test('real HQ: concurrent first captures share one completed bind and expose only the SDK capability', async (t) => {
  const entered = deferred(), release = deferred();
  t.after(() => release.resolve());
  const w = await world(t, { beforeBind: async () => { entered.resolve(); await release.promise; } });
  const member = await w.connect();
  assert.equal(Object.isFrozen(member.queries), true);
  assert.deepEqual(Object.keys(member.queries), ['request']);
  const fresh = [];
  const pending = Array.from({ length: 12 }, () => member.queries.request('notices.peek', (value) => {
    assert.equal(Object.isFrozen(value), true); assert.deepEqual(Object.keys(value).sort(), ['installation_epoch', 'lease_generation']); fresh.push(value); return build(value);
  }, { replay: 'read-once' }));
  await entered.promise;
  assert.equal(w.state.asked, 1); assert.equal(w.state.binds, 1); assert.equal(w.state.received.length, 0);
  release.resolve();
  const results = await Promise.all(pending);
  assert.ok(results.every((result) => result.runtime_id === w.state.runtime.runtime_id));
  assert.equal(fresh.length, 12); assert.equal(w.state.binds, 1);
  assert.equal(JSON.stringify(fresh).includes('MEMBER_TOKEN_CANARY'), false);
  assert.equal(JSON.stringify(fresh).includes(w.state.runtime.channel_binding), false);
  assert.equal(JSON.stringify(w.frames).includes(w.state.runtime.channel_binding), false);
});

test('real HQ: read recovery rebuilds freshness on the replacement binding', async (t) => {
  const w = await world(t); const member = await w.connect();
  const old = await member.runtime(); await w.admit();
  const attempts = [];
  const result = await member.queries.request('notices.peek', (value) => { attempts.push(value); return build(value); }, { replay: 'read-once' });
  assert.deepEqual(attempts.map((x) => x.lease_generation), [old.lease_generation, w.state.runtime.lease_generation]);
  assert.equal(result.runtime_id, w.state.runtime.runtime_id); assert.equal(w.state.binds, 2);
});

test('real HQ: a late failure from an old capture reuses the newer pair instead of destroying it', async (t) => {
  const held = deferred(), replacing = deferred(), bindRelease = deferred();
  t.after(() => bindRelease.resolve());
  let holdOnce = true;
  const w = await world(t, {
    // Hold only the old socket's reply, not HQ's request handler: HQ serializes
    // requests on one connection. Retirement will cut this pending response
    // after the new pair is published, producing the deliberately late error.
    reply: ({ kind, result, request }) => {
      if (kind === 'notices.peek' && request.payload.slow && holdOnce) { holdOnce = false; held.resolve(); return undefined; }
      return result;
    },
    beforeBind: async (state) => { if (state.binds === 2) { replacing.resolve(); await bindRelease.promise; } },
  });
  const member = await w.connect(); await member.runtime(); await w.admit();
  const slow = member.queries.request('notices.peek', (value) => ({ ...value, slow: true }), { replay: 'read-once' });
  await held.promise;
  const trigger = member.queries.request('notices.peek', build, { replay: 'read-once' });
  await replacing.promise; bindRelease.resolve();
  const [a, b] = await Promise.all([slow, trigger]);
  assert.equal(a.runtime_id, w.state.runtime.runtime_id); assert.equal(b.runtime_id, a.runtime_id);
  assert.equal(w.state.binds, 2); assert.equal(w.state.asked, 2);
});

test('real HQ: committed consume with a lost socket reply sends exactly once even when read replay is requested', async (t) => {
  const w = await world(t, { reply: ({ kind, result }) => kind === 'notices.consume-one' && result.ok ? null : result });
  const member = await w.connect();
  await assert.rejects(member.queries.request('notices.consume-one', build, { replay: 'read-once' }), (error) => error.transport === true);
  assert.equal(w.state.received.filter((x) => x.kind === 'notices.consume-one').length, 1);
  assert.equal(w.hq.hq.core.tables.get('query-transport-fixture\0effects').get('count'), 1, 'effect durably committed before the reply was cut');
  assert.equal(w.state.binds, 1); assert.equal(w.state.dropped, 1);
  const result = await member.queries.request('notices.peek', build, { replay: 'read-once' });
  assert.equal(result.runtime_id, w.state.runtime.runtime_id); assert.equal(w.state.binds, 2);
});

test('real HQ: a host code imitating a shared freshness refusal does not authorize replay', async (t) => {
  const w = await world(t, {
    beforeQuery: () => fail('lease_expired', 'test shared refusal'),
    reply: ({ kind, result }) => kind === 'notices.peek' ? { id: result.id, ok: false, host_refusal: { code: 'lease_expired', explanation: 'host string is not a validated shared refusal' } } : result,
  });
  const member = await w.connect();
  await assert.rejects(member.queries.request('notices.peek', build, { replay: 'read-once' }), (error) => error.code === 'lease_expired');
  assert.equal(w.state.received.length, 1); assert.equal(w.state.binds, 1);
});

test('real HQ: shared nonfreshness refusals and local contract failures are not retried', async (t) => {
  const w = await world(t, {
    beforeQuery: () => fail('caller_mismatch', 'test scope refusal'),
    reply: ({ kind, result }) => kind === 'task.get' ? { id: result.id, ok: true, result: { task: {} } } : result,
  });
  const member = await w.connect();
  await assert.rejects(member.queries.request('notices.peek', build, { replay: 'read-once' }), (error) => error.code === 'caller_mismatch');
  await assert.rejects(member.queries.request('task.get', () => ({ task_id: 'missing' }), { replay: 'read-once' }), (error) => error.code === 'souls.invalid_contract');
  assert.equal(w.state.binds, 1); assert.equal(w.frames.filter((x) => x.op === 'task.get').length, 1);
});

test('real HQ: an invalid challenge publishes no capture and the next explicit query can bind afresh', async (t) => {
  let corrupt = true;
  const w = await world(t, { reply: ({ kind, result }) => {
    if (kind === 'bind.challenge' && corrupt) { corrupt = false; return { ...result, result: { ...result.result, nonce: 'ab'.repeat(32) + '\n' } }; }
    return result;
  } });
  const member = await w.connect(); let builds = 0;
  await assert.rejects(member.queries.request('notices.peek', (value) => { builds++; return build(value); }, { replay: 'read-once' }), /cannot answer/);
  assert.equal(builds, 0); assert.equal(w.state.binds, 0); assert.equal(w.state.received.length, 0);
  await w.admit();
  const result = await member.queries.request('notices.peek', build);
  assert.equal(result.runtime_id, w.state.runtime.runtime_id); assert.equal(w.state.binds, 1); assert.equal(w.state.asked, 2);
});

test('real HQ: close aborts an in-flight bind, is idempotent, and a new member can start independently', async (t) => {
  const entered = deferred(), release = deferred(); t.after(() => release.resolve());
  const w = await world(t, { beforeBind: async (state) => { if (state.binds === 1) { entered.resolve(); await release.promise; } } });
  const member = await w.connect(); let builds = 0;
  const failure = assert.rejects(member.queries.request('notices.peek', (value) => { builds++; return build(value); }), (error) => error.transport === true);
  await entered.promise;
  await member.close(); await member.close(); await failure;
  release.resolve();
  await assert.rejects(member.queries.request('notices.peek', build), (error) => error.transport === true);
  assert.equal(builds, 0);
  const replacement = await w.connect();
  assert.equal((await replacement.queries.request('notices.peek', build)).runtime_id, w.state.runtime.runtime_id);
  assert.equal(w.state.received.length, 1);
});

test('real HQ: failed replacement is not published or replayed again; a later explicit request repairs it', async (t) => {
  let challenges = 0;
  const w = await world(t, { reply: ({ kind, result }) => {
    if (kind === 'bind.challenge' && ++challenges === 2) return { ...result, result: { ...result.result, context: 'unsupported-context' } };
    return result;
  } });
  const member = await w.connect(); const old = await member.runtime(); await w.admit();
  const built = [];
  await assert.rejects(member.queries.request('notices.peek', (freshness) => { built.push(freshness); return build(freshness); }, { replay: 'read-once' }), /cannot answer/);
  assert.deepEqual(built.map((value) => value.lease_generation), [old.lease_generation]);
  assert.equal(w.state.received.length, 1, 'failed reconnect is not an implicit third request');
  const next = await member.queries.request('notices.peek', build);
  assert.equal(next.runtime_id, w.state.runtime.runtime_id); assert.equal(w.state.asked, 3); assert.equal(w.state.binds, 2);
});

test('real HQ: malformed entry runtime freshness fails capture before challenge or payload building', async (t) => {
  const w = await world(t); const member = await w.connect();
  const valid = w.state.runtime; w.state.runtime = { ...valid, lease_generation: 0 };
  let built = 0;
  await assert.rejects(member.queries.request('notices.peek', (freshness) => { built++; return build(freshness); }, { replay: 'read-once' }), /invalid runtime binding metadata/);
  assert.equal(built, 0); assert.equal(w.frames.length, 0);
  w.state.runtime = valid;
  const result = await member.queries.request('notices.peek', build);
  assert.equal(result.runtime_id, valid.runtime_id); assert.equal(w.state.binds, 1);
});

test('real HQ: never-replay freshness refusal marks only that pair for the next explicit capture', async (t) => {
  const w = await world(t); const member = await w.connect();
  await member.runtime(); await w.admit();
  await assert.rejects(member.queries.request('notices.consume-one', build), (error) => error.code === 'lease_expired');
  assert.equal(w.state.binds, 1, 'no reconnect inside the refused destructive call');
  assert.equal(w.state.received.length, 1);
  assert.equal(w.hq.hq.core.tables.has('query-transport-fixture\0effects'), false);
  const fresh = await member.queries.request('notices.consume-one', build);
  assert.equal(fresh.runtime_id, w.state.runtime.runtime_id);
  assert.equal(w.state.binds, 2); assert.equal(w.state.received.length, 2);
  assert.equal(w.hq.hq.core.tables.get('query-transport-fixture\0effects').get('count'), 1);
});
