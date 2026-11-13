#!/usr/bin/env node
// Explicit dependency preparation. Runtime use never fetches or falls back.
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { CONTRACT_PIN as pin, DEFAULT_CONTRACTS_DIRECTORY, verifyContractTree } from '../lib/contracts.mjs';

export function prepareContracts({ directory = process.env.AGENT_BOT_SOUL_CONTRACTS || DEFAULT_CONTRACTS_DIRECTORY } = {}) {
  if (existsSync(directory)) { verifyContractTree(directory); return directory; }
  mkdirSync(dirname(directory), { recursive: true });
  const work = mkdtempSync(join(dirname(directory), 'soul-contracts-prepare-'));
  const repo = join(work, 'repo');
  const tree = join(work, 'tree');
  mkdirSync(repo); mkdirSync(tree);
  // Ignore installed helpers, interactive prompts and user git aliases. No
  // credential is used for the public URL. Each command is bounded.
  const env = { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' };
  for (const key of Object.keys(env)) if (/^GIT_CONFIG_(?:COUNT|KEY_\d+|VALUE_\d+)$/.test(key) || ['GIT_ASKPASS', 'SSH_ASKPASS', 'GH_TOKEN', 'GITHUB_TOKEN'].includes(key)) delete env[key];
  const git = (...args) => execFileSync('git', ['-c', 'credential.helper=', '-c', 'core.askPass=', '-c', 'http.extraHeader=', '-c', 'core.hooksPath=/dev/null', '-C', repo, ...args], { env, timeout: 30_000, maxBuffer: 8 << 20, stdio: ['ignore', 'pipe', 'pipe'] });
  try {
    git('init', '-q');
    git('fetch', '-q', '--depth', '1', '--no-tags', pin.repository, `refs/tags/${pin.tag}`);
    if (git('rev-parse', 'FETCH_HEAD^{commit}').toString().trim() !== pin.commit) throw new Error(`tag ${pin.tag} moved from the pinned commit`);
    const listing = git('ls-tree', '-r', '-z', pin.commit, '--', ...pin.paths).toString().split('\0').filter(Boolean);
    for (const row of listing) {
      const [meta, path] = row.split('\t');
      const [mode, type, oid] = meta.split(' ');
      if (type !== 'blob' || !['100644', '100755'].includes(mode) || path.split('/').some((s) => !s || s === '.' || s === '..') || path.startsWith('/')) throw new Error('release contains a non-regular or non-canonical path');
      mkdirSync(dirname(join(tree, path)), { recursive: true });
      writeFileSync(join(tree, path), git('cat-file', 'blob', oid), { mode: mode === '100755' ? 0o755 : 0o644 });
    }
    verifyContractTree(tree);
    try { renameSync(tree, directory); } catch (error) {
      // Another prepare may have won. Its bytes still have to verify.
      if (!existsSync(directory)) throw error;
      verifyContractTree(directory);
    }
    return directory;
  } finally { rmSync(work, { recursive: true, force: true }); }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { console.log(`verified soul-contracts ${pin.tag}: ${prepareContracts()}`); }
  catch (error) { console.error(error.message); process.exitCode = 1; }
}
