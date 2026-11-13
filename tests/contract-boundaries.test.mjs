// A transport fault in front of the real pinned HQ. These are not canned
// successful replies: the proxy only corrupts what HQ actually produced.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { connect, createServer } from 'node:net';
import { join } from 'node:path';
import { ContractError } from '../lib/contracts.mjs';
import { connectHq } from '../lib/hq-client.mjs';
import { readNotes, restrictions, writeNote } from '../lib/notes.mjs';
import { readLines } from '../lib/ndjson.mjs';
import { fixture, startHQ } from './harness.mjs';

async function corruptReplies(t, hq, alter) {
  const path = join(hq.home, 'fault.sock');
  const sockets = new Set();
  const proxy = createServer((downstream) => {
    const upstream = connect(join(hq.home, 'admission.sock'));
    sockets.add(upstream); sockets.add(downstream);
    downstream.pipe(upstream);
    readLines(upstream, (line) => {
      const text = alter(JSON.parse(line));
      if (text !== undefined) downstream.write(Buffer.isBuffer(text) ? Buffer.concat([text, Buffer.from('\n')]) : `${text}\n`);
    }, () => downstream.destroy());
    downstream.on('error', () => upstream.destroy());
    upstream.on('error', () => downstream.destroy());
    downstream.on('close', () => { sockets.delete(downstream); upstream.destroy(); });
    upstream.on('close', () => { sockets.delete(upstream); downstream.destroy(); });
  });
  await new Promise((resolve, reject) => { proxy.once('error', reject); proxy.listen(path, resolve); });
  t.after(async () => { for (const socket of sockets) socket.destroy(); await new Promise((resolve) => proxy.close(resolve)); });
  return connectHq(path);
}

test('the real runtime rejects corrupted HQ admission before exposing it to a member', async (t) => {
  const hq = await startHQ();
  t.after(() => hq.done());
  const hello = fixture('positive/hello.first-start.json').input;
  for (const [name, corrupt, refuses] of [
    ['unknown record field', (reply) => JSON.stringify({ ...reply, result: { ...reply.result, unexpected: true } }), (e) => e instanceof ContractError],
    ['unnegotiated version', (reply) => JSON.stringify({ ...reply, result: { ...reply.result, negotiated_versions: { hq: 3, wire: 1 } } }), (e) => e.code === 'unsupported_version'],
    ['wrong request echo', (reply) => JSON.stringify({ ...reply, result: { ...reply.result, request_id: 'req_someone_else' } }), (e) => e instanceof ContractError],
    ['duplicate reply key', (reply) => `{"ok":false,${JSON.stringify(reply).slice(1)}`, (e) => e.transport === true],
    ['unknown reply ID', (reply) => JSON.stringify({ ...reply, id: 'not_pending' }), (e) => e.transport === true],
    ['missing reply result', (reply) => JSON.stringify({ id: reply.id, ok: true }), (e) => e.transport === true],
  ]) {
    await t.test(name, async (sub) => {
      const client = await corruptReplies(sub, hq, corrupt);
      sub.after(() => client.close());
      let timeout;
      try {
        await assert.rejects(Promise.race([
          client.request('Hello', { ...hello, request_id: `req_${name.replaceAll(' ', '_')}`, requested_profile: 'managed-cooperative' }),
          new Promise((_, reject) => { timeout = setTimeout(() => reject(new Error('malformed reply left its request hanging')), 2000); }),
        ]), refuses);
      } finally { clearTimeout(timeout); }
    });
  }
});

test('a poisoned HQ reply fails parallel waiters, ignores later same-packet replies and refuses reuse', async (t) => {
  const hq = await startHQ();
  t.after(() => hq.done());
  for (const [name, corrupt, original] of [
    ['invalid contract', (reply) => JSON.stringify({ ...reply, result: { ...reply.result, unexpected: true } }), (e) => e instanceof ContractError],
    ['invalid envelope', (reply) => JSON.stringify({ id: reply.id, ok: true }), (e) => e.transport === true],
    ['invalid JSON', (reply) => `{"ok":false,${JSON.stringify(reply).slice(1)}`, (e) => e.transport === true],
    ['invalid UTF-8', (reply) => {
      const [before, after] = JSON.stringify({ ...reply, result: { ...reply.result, warnings: ['BAD_BYTE'] } }).split('BAD_BYTE');
      return Buffer.concat([Buffer.from(before), Buffer.from([0x80]), Buffer.from(after)]);
    }, (e) => e.transport === true],
  ]) {
    await t.test(name, async (sub) => {
      const replies = [];
      const client = await corruptReplies(sub, hq, (reply) => {
        replies.push(reply);
        if (replies.length < 2) return undefined;
        return Buffer.concat([Buffer.from(corrupt(replies[0])), Buffer.from(`\n${JSON.stringify(replies[1])}`)]);
      });
      sub.after(() => client.close());
      const hello = fixture('positive/hello.first-start.json').input;
      let timeout;
      try {
        const results = await Promise.race([
          Promise.allSettled([
            client.request('Hello', { ...hello, request_id: `req_first_${name.replaceAll(' ', '_')}`, requested_profile: 'managed-cooperative' }),
            client.request('Hello', { ...hello, request_id: `req_second_${name.replaceAll(' ', '_')}`, requested_profile: 'managed-cooperative' }),
          ]),
          new Promise((_, reject) => { timeout = setTimeout(() => reject(new Error('poisoned connection left a waiter hanging')), 2000); }),
        ]);
        assert.equal(results[0].status, 'rejected');
        assert.ok(original(results[0].reason), 'the first failure keeps its original reason');
        assert.equal(results[1].status, 'rejected', 'the valid second frame in the same packet is unusable');
        assert.equal(results[1].reason.transport, true);
        assert.equal(client.closed, true);
        await assert.rejects(client.request('status'), (error) => error.transport === true);
      } finally { clearTimeout(timeout); }
    });
  }
});

test('invalid typed-note stamps never write outside the notes directory; malformed restricted notes fail closed', (t) => {
  const root = mkdtempSync(join(tmpdir(), 'souls-notes-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const directory = join(root, 'Contents');
  const stamp = { note_id: 'note_good', member_id: 'm_lead', runtime_id: 'rt_lead', timestamp: '2026-11-09T00:00:00Z' };
  assert.throws(() => writeNote(directory, { type: 'finding', body: 'valid body' }, { ...stamp, note_id: '../outside' }), /pattern/);
  assert.throws(() => writeNote(directory, { type: 'finding', body: 'valid body' }, { ...stamp, timestamp: 'not-a-time' }), /format/);
  const notes = join(directory, 'comms', 'notes');
  mkdirSync(notes, { recursive: true });
  const note = { ...fixture('positive/typed-note.handoff-before-lead-yields.json').input };
  writeFileSync(join(notes, 'valid.json'), JSON.stringify(note));
  assert.deepEqual(readNotes(directory), [note]);
  writeFileSync(join(notes, 'bad-schema.json'), JSON.stringify({ ...note, provenance: ['invented'] }));
  assert.throws(() => readNotes(directory), /handoff restrictions are unavailable/);
  assert.throws(() => restrictions(directory), /handoff restrictions are unavailable/);
  rmSync(join(notes, 'bad-schema.json'));
  writeFileSync(join(notes, 'duplicate.json'), `{"type":"handoff",${JSON.stringify(note).slice(1)}`);
  assert.throws(() => restrictions(directory), /handoff restrictions are unavailable/);
});
