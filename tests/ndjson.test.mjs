// Byte-level transport checks. The pinned strict parser cannot detect
// malformed UTF-8 if an earlier decoder has already replaced the bytes.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { PassThrough } from 'node:stream';
import { parseStrict } from '../lib/contracts.mjs';
import { MAX_LINE_BYTES, readLines } from '../lib/ndjson.mjs';

async function receive(chunks, onLine) {
  const stream = new PassThrough();
  const lines = [];
  const errors = [];
  const ended = once(stream, 'end');
  readLines(stream, (line) => { lines.push(line); return onLine?.(line); }, (error) => errors.push(error));
  for (const chunk of chunks) stream.write(chunk);
  stream.end();
  await ended;
  return { lines, errors };
}

test('UTF-8 characters split across chunks and literal U+FFFD keep their exact meaning', async () => {
  const text = JSON.stringify({ text: 'é 😀 �' });
  const bytes = Buffer.from(`${text}\n`);
  const result = await receive([...bytes].map((byte) => Buffer.from([byte])));
  assert.deepEqual(result.errors, []);
  assert.deepEqual(result.lines, [text]);
  assert.deepEqual(parseStrict(result.lines[0]), { text: 'é 😀 �' });
});

test('malformed UTF-8 poisons a packet before either its bad frame or a later frame is delivered', async () => {
  const result = await receive([Buffer.concat([
    Buffer.from('{"text":"'), Buffer.from([0xc0, 0xaf]), Buffer.from('"}\n{"accepted":true}\n'),
  ])]);
  assert.equal(result.errors.length, 1);
  assert.deepEqual(result.lines, []);
});

test('an incomplete UTF-8 character at end refuses once and never emits a replacement character', async () => {
  const result = await receive([Buffer.from('{"text":"'), Buffer.from([0xf0, 0x9f, 0x98])]);
  assert.equal(result.errors.length, 1);
  assert.deepEqual(result.lines, []);
});

test('a line-reader error latches even if its callback does not destroy the stream', async () => {
  const result = await receive([
    Buffer.from(`${'x'.repeat(MAX_LINE_BYTES + 1)}\n{"same_chunk":true}\n`),
    Buffer.from('{"next_chunk":true}\n'),
  ]);
  assert.equal(result.errors.length, 1);
  assert.deepEqual(result.lines, []);
});

test('a consumer can poison a line reader before a later same-chunk frame', async () => {
  const result = await receive([Buffer.from('{"bad":true}\n{"later":true}\n')], () => false);
  assert.deepEqual(result.lines, ['{"bad":true}']);
  assert.deepEqual(result.errors, []);
});

test('a throwing consumer fails once and stops later same-chunk and next-chunk frames', async () => {
  const result = await receive([
    Buffer.from('{"first":true}\n{"same_chunk":true}\n'),
    Buffer.from('{"next_chunk":true}\n'),
  ], () => { throw new Error('consumer could not process the frame'); });
  assert.deepEqual(result.lines, ['{"first":true}']);
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0].message, /consumer could not process/);
});

test('whole and split UTF-8 BOMs remain visible for strict JSON refusal', async () => {
  for (const chunks of [
    [Buffer.from('\ufeff{"ok":true}\n')],
    [Buffer.from([0xef]), Buffer.from([0xbb]), Buffer.from([0xbf]), Buffer.from('{"ok":true}\n')],
  ]) {
    const result = await receive(chunks);
    assert.deepEqual(result.errors, []);
    assert.equal(result.lines[0].charCodeAt(0), 0xfeff);
    assert.throws(() => parseStrict(result.lines[0]), (error) => error.code === 'host.invalid_json');
  }
});
