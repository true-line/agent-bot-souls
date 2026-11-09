// Typed notes in the Soul's comms/ area (soul-contracts records/v1
// typed-note; 0.4 §7 and §10). A handoff note is what lets a returning lead
// resume: the lead writes one before it yields, and the entry point gives
// the unsuperseded ones to the next lead before it continues.
//
// The entry point stamps the fields a member must not choose for itself:
// the note ID, the member and runtime that wrote it, the time, and
// `member` provenance. Notes are files, one per note, written atomically.
import { mkdirSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { writeAtomic } from './soul.mjs';

export const NOTE_TYPES = Object.freeze(['decision', 'finding', 'commitment', 'open_question', 'handoff']);
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const FIELDS = new Set(['type', 'task_id', 'body', 'sources', 'disclosure_restrictions', 'superseded_note_references']);

export class NoteError extends Error {
  constructor(message) { super(message); this.name = 'NoteError'; }
}
const bad = (message) => { throw new NoteError(message); };
const strings = (v, max) => Array.isArray(v) && v.every((s) => typeof s === 'string' && s.length >= 1 && s.length <= max);

const dir = (contents) => join(contents, 'comms', 'notes');

// input: what the member wrote. stamp: { note_id, member_id, runtime_id, timestamp }.
export function writeNote(contents, input, stamp) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) bad('a note is an object');
  for (const k of Object.keys(input)) if (!FIELDS.has(k)) bad(`a note has no field ${k}`);
  if (!NOTE_TYPES.includes(input.type)) bad(`a note's type is one of ${NOTE_TYPES.join(', ')}`);
  if (typeof input.body !== 'string' || input.body.length < 1 || input.body.length > 65536) bad('a note needs a body of 1 to 65536 characters');
  if (input.task_id !== undefined && (typeof input.task_id !== 'string' || !ID.test(input.task_id))) bad('task_id is not an ID');
  if (input.sources !== undefined && !strings(input.sources, 256)) bad('sources is a list of strings');
  if (input.disclosure_restrictions !== undefined && !strings(input.disclosure_restrictions, 64)) bad('disclosure_restrictions is a list of labels');
  if (input.superseded_note_references !== undefined && !(Array.isArray(input.superseded_note_references) && input.superseded_note_references.every((s) => typeof s === 'string' && ID.test(s)))) bad('superseded_note_references is a list of note IDs');
  const note = {
    note_id: stamp.note_id,
    type: input.type,
    ...(input.task_id !== undefined ? { task_id: input.task_id } : {}),
    member_id: stamp.member_id,
    runtime_id: stamp.runtime_id,
    timestamp: stamp.timestamp,
    ...(input.sources !== undefined ? { sources: input.sources } : {}),
    provenance: ['member'],
    ...(input.disclosure_restrictions !== undefined ? { disclosure_restrictions: input.disclosure_restrictions } : {}),
    body: input.body,
    ...(input.superseded_note_references !== undefined ? { superseded_note_references: input.superseded_note_references } : {}),
  };
  mkdirSync(dir(contents), { recursive: true, mode: 0o700 });
  writeAtomic(join(dir(contents), `${note.note_id}.json`), `${JSON.stringify(note, null, 2)}\n`);
  return note;
}

export function readNotes(contents) {
  let names;
  try { names = readdirSync(dir(contents)); } catch { return []; }
  const notes = [];
  for (const name of names.filter((n) => n.endsWith('.json')).sort()) {
    try { notes.push(JSON.parse(readFileSync(join(dir(contents), name), 'utf8'))); } catch { /* an unreadable note is skipped, never guessed */ }
  }
  return notes.sort((a, b) => (a.timestamp < b.timestamp ? -1 : a.timestamp > b.timestamp ? 1 : a.note_id.localeCompare(b.note_id)));
}

// The handoff notes no later note supersedes, oldest first.
export function handoffs(contents) {
  const notes = readNotes(contents);
  const superseded = new Set(notes.flatMap((n) => n.superseded_note_references ?? []));
  return notes.filter((n) => n.type === 'handoff' && !superseded.has(n.note_id));
}

// The data-restriction labels live handoffs carry: what a fail-over route
// must be allowed to receive before any context is sent to it (0.4 §9).
export const restrictions = (contents) => [...new Set(handoffs(contents).flatMap((n) => n.disclosure_restrictions ?? []))].sort();
