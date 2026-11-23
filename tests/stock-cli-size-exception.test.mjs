import test from 'node:test';
import assert from 'node:assert/strict';
import { checkMeasuredStockCliQualificationInput,
  qualifiesStockCliQualificationInput } from '../lib/soul.mjs';

const path = 'runtime/bin/claude';
const size = 354_630_016;
const digest = 'e85547190ef8cd983033ba61b17194045a6fea00035da349efeabed86badacc9';
const entry = { path, stat: { isFile: () => true, size, mode: 0o100550 } };
const record = { path, kind: 'regular', mode: '0550', size, sha256: digest };
const measured = { ...record };

test('the stock CLI size allowance is default-off and exact to path, bytes, mode and reviewed digest', () => {
  assert.equal(qualifiesStockCliQualificationInput(entry, record), false);
  assert.equal(qualifiesStockCliQualificationInput(entry, record, true), true);
  for (const changed of [
    [{ ...entry, path: 'runtime/bin/other' }, record],
    [entry, { ...record, path: 'runtime/bin/other' }],
    [{ ...entry, stat: { ...entry.stat, size: size + 1 } }, record],
    [{ ...entry, stat: { ...entry.stat, mode: 0o100555 } }, record],
    [entry, { ...record, sha256: '0'.repeat(64) }],
  ]) {
    assert.equal(qualifiesStockCliQualificationInput(...changed, true), false);
  }
});

test('the measured stock CLI must match the exact bytes after the bounded read', () => {
  checkMeasuredStockCliQualificationInput(measured, true);
  assert.throws(() => checkMeasuredStockCliQualificationInput({ ...measured,
    sha256: '0'.repeat(64) }, true), /exact reviewed bytes/);
  assert.throws(() => checkMeasuredStockCliQualificationInput({ ...measured,
    path: 'runtime/bin/other' }, true), /exact reviewed bytes/);
});
