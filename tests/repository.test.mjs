// The repository's own contract: MIT-licensed, with the platform block in
// AGENTS.md that points agents at the platform (registry/repos.yaml).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');

test('the license is MIT, held by True Line AI LLC', () => {
  const license = read('LICENSE');
  assert.match(license, /^MIT License\n/);
  assert.match(license, /Copyright \(c\) 2026 True Line AI LLC/);
  assert.equal(JSON.parse(read('package.json')).license, 'MIT');
});

test('AGENTS.md carries the platform block for agent-bot-souls', () => {
  const agents = read('AGENTS.md');
  const block = agents.slice(agents.indexOf('<!-- platform:agent-bot-platform:start -->'), agents.indexOf('<!-- platform:agent-bot-platform:end -->'));
  assert.match(block, /Platform: true-line\/agent-bot-platform, read at main\./);
  assert.match(block, /registry\/repos\.yaml entry for agent-bot-souls/);
});
