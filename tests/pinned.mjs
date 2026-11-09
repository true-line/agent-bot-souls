// Checkouts of the repositories the tests run against, at the commits in
// governance/pins.json: agent-bot-hq (the real HQ, and through its own pin
// the soul-contracts schemas) and agent-bot-comms (the broker plugin). They
// are cached under node_modules/.cache. With no cache and no network the
// tests fail; they never skip.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const PINS = JSON.parse(readFileSync(new URL('../governance/pins.json', import.meta.url), 'utf8'));

export function checkout(name) {
  const pin = PINS[name];
  assert.ok(pin, `governance/pins.json has no pin for ${name}`);
  const parent = fileURLToPath(new URL('../node_modules/.cache/', import.meta.url));
  const cache = join(parent, `${name}-${pin.commit}`);
  if (existsSync(join(cache, 'package.json'))) return cache;
  mkdirSync(parent, { recursive: true });
  const work = mkdtempSync(join(parent, `${name}-fetch-`));
  try {
    const git = (...args) => execFileSync('git', ['-C', work, ...args], { stdio: ['ignore', 'pipe', 'pipe'], encoding: 'utf8' });
    git('init', '-q');
    git('fetch', '-q', '--depth', '1', pin.repository, pin.commit);
    git('checkout', '-q', 'FETCH_HEAD');
    assert.equal(git('rev-parse', 'HEAD').trim(), pin.commit, `fetched ${name} revision`);
    rmSync(join(work, '.git'), { recursive: true, force: true });
    try {
      renameSync(work, cache);
    } catch (error) {
      // Another test file fetched it first; keep that tree.
      if (!existsSync(join(cache, 'package.json'))) throw error;
      rmSync(work, { recursive: true, force: true });
    }
  } catch (error) {
    rmSync(work, { recursive: true, force: true });
    throw new Error(`cannot fetch ${name} ${pin.commit}: ${error.stderr?.toString().trim() || error.message}`);
  }
  return cache;
}
