// What the entry point reads from a Soul package, and the typed notes it
// keeps in comms/ (soul-contracts records/v1 typed-note).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, rmSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { handoffs, readNotes, restrictions, writeNote } from '../lib/notes.mjs';
import { readSoul, SoulError } from '../lib/soul.mjs';
import { DIGEST, FAKE, fake, fixture, makeSoul, schema, SOUL, validate } from './harness.mjs';

const withSoul = (options, fn) => {
  const root = makeSoul(options);
  try { return fn(root); } finally { rmSync(root, { recursive: true, force: true }); }
};
const refuses = (options, pattern) => withSoul(options, (root) => assert.throws(() => readSoul(root), (e) => e instanceof SoulError && pattern.test(e.message), String(pattern)));

test('a Soul package gives the Soul, its definition digest, its members and their routes', () => withSoul({}, (root) => {
  const soul = readSoul(root);
  assert.equal(soul.soul_id, SOUL);
  assert.equal(soul.definition_digest, DIGEST);
  assert.deepEqual(soul.members.map((m) => [m.member_id, m.role, m.routes.length]), [['m_lead', 'lead', 1], ['m_spec', 'specialist', 1]]);
  assert.deepEqual(soul.members[0].routes[0], { adapter_id: 'fake-lead', adapter_version: '0.1.0', command: FAKE, env: {}, accepts: [] });
  // The installation ID is this host's, created once and kept.
  assert.match(soul.installation_id, /^inst_[0-9a-f]{16}$/);
  assert.equal(readSoul(root).installation_id, soul.installation_id);
  assert.equal(statSync(join(root, 'Contents/host')).mode & 0o777, 0o700);
  assert.equal(statSync(join(root, 'Contents/host/installation.json')).mode & 0o777, 0o600);
}));

test('fallbacks become the member\'s fail-over order, each with this host\'s command', () => {
  const info = { soul_id: SOUL, members: [{ member_id: 'm_lead', role: 'lead', adapter_id: 'a', adapter_version: '1.0.0', fallbacks: [{ adapter_id: 'b', adapter_version: '2.0.0' }] }] };
  withSoul({ info, adapters: { a: fake(), b: fake(undefined, { accepts: ['confidential'] }) } }, (root) => {
    assert.deepEqual(readSoul(root).members[0].routes.map((r) => [r.adapter_id, r.adapter_version, r.accepts]), [['a', '1.0.0', []], ['b', '2.0.0', ['confidential']]]);
  });
});

test('a package the entry point cannot run is refused with the reason', () => {
  const member = (over) => ({ member_id: 'm_lead', role: 'lead', adapter_id: 'fake-lead', adapter_version: '0.1.0', ...over });
  refuses({ info: { soul_id: 'bob', members: [member()] } }, /soul_id/);
  refuses({ lock: { definition_digest: 'latest' } }, /definition_digest/);
  refuses({ info: { soul_id: SOUL, members: [] } }, /members/);
  refuses({ info: { soul_id: SOUL, members: [member({ role: 'specialist' })] } }, /exactly one member has the role lead/);
  refuses({ info: { soul_id: SOUL, members: [member(), member({ member_id: 'm_2' })] } }, /exactly one member has the role lead/);
  refuses({ info: { soul_id: SOUL, members: [member(), member({ role: 'specialist' })] } }, /used twice/);
  refuses({ info: { soul_id: SOUL, members: [member({ adapter_version: 'latest' })] } }, /exact adapter_version/);
  refuses({ info: { soul_id: SOUL, members: [member({ adapter_id: 'missing' })] } }, /no command for missing/);
  refuses({ info: { soul_id: SOUL, members: [member({ fallbacks: [{ adapter_id: 'missing', adapter_version: '1.0.0' }] })] } }, /no command for missing/);
  refuses({ adapters: { 'fake-lead': { command: [] }, 'fake-specialist': fake() } }, /no command for fake-lead/);
});

test('a note is stamped by the entry point and is a valid typed-note record', () => withSoul({}, (root) => {
  const contents = join(root, 'Contents');
  const typedNote = schema('records/v1/typed-note.schema.json');
  const stamp = (n, t) => ({ note_id: `note_${n}`, member_id: 'm_lead', runtime_id: 'rt_1', timestamp: t });
  const first = writeNote(contents, { type: 'handoff', task_id: 'task_17', body: 'Task 17 is running.', disclosure_restrictions: ['confidential'], sources: ['receipt_56'] }, stamp(1, '2026-11-09T09:00:00.000Z'));
  assert.deepEqual(validate(typedNote, first), []);
  assert.deepEqual(first.provenance, ['member'], 'a member cannot claim owner or HQ provenance');
  assert.deepEqual(validate(typedNote, fixture('positive/typed-note.handoff-before-lead-yields.json').input), [], 'the same schema the fixture satisfies');
  assert.equal(statSync(join(contents, 'comms/notes/note_1.json')).mode & 0o777, 0o600);
  assert.deepEqual(JSON.parse(readFileSync(join(contents, 'comms/notes/note_1.json'), 'utf8')), first);

  writeNote(contents, { type: 'finding', task_id: 'task_17', body: 'A finding.' }, stamp(2, '2026-11-09T09:01:00.000Z'));
  writeNote(contents, { type: 'handoff', task_id: 'task_18', body: 'Task 18 waits on the owner.', disclosure_restrictions: ['internal'] }, stamp(3, '2026-11-09T09:02:00.000Z'));
  assert.deepEqual(handoffs(contents).map((n) => n.note_id), ['note_1', 'note_3'], 'handoffs only, oldest first');
  assert.deepEqual(restrictions(contents), ['confidential', 'internal']);

  // A later note supersedes the handoff it names.
  const done = writeNote(contents, { type: 'commitment', task_id: 'task_17', body: 'Completed.', superseded_note_references: ['note_1'] }, stamp(4, '2026-11-09T09:03:00.000Z'));
  assert.deepEqual(validate(typedNote, done), []);
  assert.deepEqual(handoffs(contents).map((n) => n.note_id), ['note_3']);
  assert.deepEqual(restrictions(contents), ['internal']);
  assert.equal(readNotes(contents).length, 4);
}));

test('a note a member may not write is refused and leaves no file', () => withSoul({}, (root) => {
  const contents = join(root, 'Contents');
  const stamp = { note_id: 'note_x', member_id: 'm_spec', runtime_id: 'rt_2', timestamp: '2026-11-09T09:00:00.000Z' };
  for (const input of [
    null,
    { type: 'rumour', body: 'x' },
    { type: 'handoff', body: '' },
    { type: 'handoff', body: 'x', provenance: ['owner'] },
    { type: 'handoff', body: 'x', member_id: 'm_lead' },
    { type: 'handoff', body: 'x', task_id: 'not an id' },
    { type: 'handoff', body: 'x', disclosure_restrictions: 'confidential' },
    { type: 'handoff', body: 'x', superseded_note_references: ['../escape'] },
  ]) assert.throws(() => writeNote(contents, input, stamp), { name: 'NoteError' }, JSON.stringify(input));
  assert.equal(existsSync(join(contents, 'comms/notes/note_x.json')), false);
  assert.deepEqual(readNotes(contents), []);
}));
