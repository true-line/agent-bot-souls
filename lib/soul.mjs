// What the entry point reads from a Soul package (soul-package
// spec/LAYOUT.md): everything is under <root>/Contents/.
//
//   SoulInfo.json            accepted definition: the Soul ID and its members
//   SoulLock.json            the definition digest HQ accepted
//   host/adapters.json       this host's adapter commands (recreated per host)
//   host/installation.json   this host's installation ID (recreated per host)
//
// soul-package does not yet specify the fields of SoulInfo.json or
// SoulLock.json. The entry point reads only the ones below and ignores the
// rest, so the format can grow without a change here.
//
//   SoulInfo.json   { "soul_id": "agent_<uuid>",
//                     "members": [ { "member_id", "role", "adapter_id", "adapter_version",
//                                    "fallbacks": [ { "adapter_id", "adapter_version" } ] } ] }
//   SoulLock.json   { "definition_digest": "sha256:<64 hex>" }
//   adapters.json   { "<adapter_id>": { "command": ["exe", "arg", ...], "env": { }, "accepts": ["label"] } }
//
// `fallbacks` is the owner's fail-over order for a member (0.4 §9).
// `accepts` lists the data-restriction labels a route may receive; a route
// with no list may receive unrestricted work only.
import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { closeSync, constants, fchmodSync, fstatSync, lstatSync, mkdirSync, openSync, readFileSync, realpathSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join, parse } from 'node:path';

const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SOUL_ID = /^agent_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const ROLE = /^[a-z][a-z0-9-]{0,31}$/;
const VERSION = /^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$/;
export const LEAD = 'lead';

export class SoulError extends Error {
  constructor(message) { super(message); this.name = 'SoulError'; }
}
const bad = (message) => { throw new SoulError(message); };

// Node's stat mode omits macOS ACL grants. Reject every allow ACL entry on a
// custody path; deny-only entries (such as the default home deny-delete ACL)
// cannot give another account rename or write authority. Fail closed if the
// native ACL listing cannot be read or parsed.
function checkedDarwinAcl(path, label) {
  if (process.platform !== 'darwin') return;
  const result = spawnSync('/bin/ls', ['-lde', path], { encoding: 'utf8', maxBuffer: 16384 });
  if (result.error || result.status !== 0) bad(`${label}: cannot inspect ACL`);
  const lines = result.stdout.trimEnd().split('\n');
  if (!/^[-bcdlps][rwxStTs-]{9}[+@ ]/.test(lines[0] ?? '')) bad(`${label}: cannot parse ACL listing`);
  if (lines.length === 1 && lines[0][10] !== '+') return;
  if (lines.length < 2 || lines.slice(1).some((line) => !/^\s*\d+:\s+.+\sdeny\s+/.test(line))) bad(`${label}: ACL may grant another account write access`);
}

function checked(path, label, kind, missing = false) {
  let stat;
  try { stat = lstatSync(path); } catch (e) {
    if (missing && e.code === 'ENOENT') return null;
    return bad(`${label}: cannot inspect path: ${e.code ?? e.message}`);
  }
  if ((kind === 'directory' && !stat.isDirectory()) || (kind === 'file' && !stat.isFile())) bad(`${label}: must be a real ${kind}, not a link`);
  if (stat.uid !== process.getuid()) bad(`${label}: owner differs from the runtime account`);
  if (stat.mode & 0o022) bad(`${label}: group or other may write this path`);
  checkedDarwinAcl(path, label);
  return stat;
}

// Every pathname operation below traverses the root's parents. A no-follow
// open of the final component cannot stop another account replacing a parent
// directory between validation and use. Walk from the filesystem root down:
// once a parent is protected, its child cannot be swapped by another account.
// A sticky shared directory is safe only for a child owned by this account or
// root; the parent must itself be owned by this account or root.
function checkedAncestry(root) {
  const ancestors = [];
  for (let path = dirname(root); ; path = dirname(path)) {
    ancestors.push(path);
    if (path === parse(path).root) break;
  }
  ancestors.reverse();
  for (let i = 0; i < ancestors.length; i++) {
    const parent = ancestors[i];
    const child = ancestors[i + 1] ?? root;
    let stat, childStat;
    try {
      stat = lstatSync(parent);
      childStat = lstatSync(child);
    } catch (e) { bad(`Soul ancestry: cannot inspect path: ${e.code ?? e.message}`); }
    if (!stat.isDirectory() || (stat.uid !== 0 && stat.uid !== process.getuid())) bad(`Soul ancestry: unsafe parent ${parent}`);
    checkedDarwinAcl(parent, 'Soul ancestry');
    if (stat.mode & 0o022) {
      if (!(stat.mode & 0o1000) || (childStat.uid !== 0 && childStat.uid !== process.getuid())) bad(`Soul ancestry: writable parent ${parent}`);
    }
  }
}

function openChecked(path, label, kind, expected) {
  let fd;
  try {
    fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (kind === 'directory' ? (constants.O_DIRECTORY ?? 0) : 0));
    const stat = fstatSync(fd);
    if ((kind === 'directory' && !stat.isDirectory()) || (kind === 'file' && !stat.isFile()) ||
        stat.dev !== expected.dev || stat.ino !== expected.ino) bad(`${label}: path changed or is not a real ${kind}`);
    if (stat.uid !== process.getuid()) bad(`${label}: owner differs from the runtime account`);
    if (stat.mode & 0o022) bad(`${label}: group or other may write this path`);
    return fd;
  } catch (e) {
    if (fd !== undefined) closeSync(fd);
    if (e instanceof SoulError) throw e;
    return bad(`${label}: cannot open without following links: ${e.code ?? e.message}`);
  }
}

function readJson(path, label) {
  let text;
  const stat = checked(path, label, 'file');
  const fd = openChecked(path, label, 'file', stat);
  try { text = readFileSync(fd, 'utf8'); } catch (e) { return bad(`cannot read ${label}: ${e.code ?? e.message}`); }
  finally { closeSync(fd); }
  try { return JSON.parse(text); } catch (e) { return bad(`${path} is not JSON: ${e.message}`); }
}
const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

// Write a file so a reader never sees half of it.
export function writeAtomic(path, text, mode = 0o600) {
  const tmp = `${path}.${randomBytes(6).toString('hex')}.tmp`;
  writeFileSync(tmp, text, { mode, flag: 'wx' });
  renameSync(tmp, path);
}

function route(where, r) {
  if (!isObject(r) || typeof r.adapter_id !== 'string' || !ID.test(r.adapter_id)) bad(`${where}: needs an adapter_id`);
  if (typeof r.adapter_version !== 'string' || !VERSION.test(r.adapter_version)) bad(`${where}: needs an exact adapter_version`);
  return { adapter_id: r.adapter_id, adapter_version: r.adapter_version };
}

export function readSoul(root) {
  if (typeof process.getuid !== 'function' || constants.O_NOFOLLOW === undefined || constants.O_DIRECTORY === undefined) bad('Soul host custody: ownership and no-follow checks unavailable');
  checked(root, 'Soul root', 'directory');
  // Anchor every later path below the resolved root, not a replaceable parent link.
  root = realpathSync(root);
  checkedAncestry(root);
  const contents = join(root, 'Contents');
  checked(root, 'Soul root', 'directory');
  checked(contents, 'Contents', 'directory');
  const info = readJson(join(contents, 'SoulInfo.json'), 'SoulInfo.json');
  const lock = readJson(join(contents, 'SoulLock.json'), 'SoulLock.json');
  if (!isObject(info) || typeof info.soul_id !== 'string' || !SOUL_ID.test(info.soul_id)) bad('SoulInfo.json: soul_id is agent_<uuid>');
  if (!isObject(lock) || typeof lock.definition_digest !== 'string' || !DIGEST.test(lock.definition_digest)) bad('SoulLock.json: definition_digest is sha256:<64 hex>');
  if (!Array.isArray(info.members) || info.members.length === 0) bad('SoulInfo.json: members is a list with at least the lead');

  const host = join(contents, 'host');
  if (!checked(host, 'host', 'directory', true)) mkdirSync(host, { mode: 0o700 });
  checked(host, 'host', 'directory');
  const adapters = readJson(join(host, 'adapters.json'), 'host/adapters.json');
  if (!isObject(adapters)) bad('host/adapters.json: an object keyed by adapter_id');
  const adapter = (where, id) => {
    const a = adapters[id];
    if (!isObject(a) || !Array.isArray(a.command) || a.command.length === 0 || !a.command.every((s) => typeof s === 'string' && s !== '')) bad(`${where}: host/adapters.json has no command for ${id}`);
    if (a.env !== undefined && (!isObject(a.env) || !Object.values(a.env).every((v) => typeof v === 'string'))) bad(`host/adapters.json: ${id}.env maps names to strings`);
    if (a.accepts !== undefined && (!Array.isArray(a.accepts) || !a.accepts.every((s) => typeof s === 'string'))) bad(`host/adapters.json: ${id}.accepts is a list of labels`);
    return { command: [...a.command], env: { ...a.env }, accepts: [...(a.accepts ?? [])] };
  };

  const seen = new Set();
  const members = info.members.map((m, i) => {
    const where = `SoulInfo.json: members[${i}]`;
    if (!isObject(m) || typeof m.member_id !== 'string' || !ID.test(m.member_id)) bad(`${where}: needs a member_id`);
    if (seen.has(m.member_id)) bad(`${where}: member_id ${m.member_id} is used twice`);
    seen.add(m.member_id);
    if (typeof m.role !== 'string' || !ROLE.test(m.role)) bad(`${where}: needs a role`);
    if (m.fallbacks !== undefined && !Array.isArray(m.fallbacks)) bad(`${where}: fallbacks is a list`);
    const routes = [route(where, m), ...(m.fallbacks ?? []).map((f, j) => route(`${where}.fallbacks[${j}]`, f))]
      .map((r) => ({ ...r, ...adapter(where, r.adapter_id) }));
    return { member_id: m.member_id, role: m.role, routes };
  });
  if (members.filter((m) => m.role === LEAD).length !== 1) bad('SoulInfo.json: exactly one member has the role lead');

  const installationPath = join(host, 'installation.json');
  let installation;
  if (checked(installationPath, 'host/installation.json', 'file', true)) {
    installation = readJson(installationPath, 'host/installation.json');
    if (!isObject(installation) || typeof installation.installation_id !== 'string' || !ID.test(installation.installation_id)) bad('host/installation.json: needs an installation_id');
  } else {
    installation = { installation_id: `inst_${randomBytes(8).toString('hex')}` };
    writeAtomic(installationPath, `${JSON.stringify(installation, null, 2)}\n`);
    checked(installationPath, 'host/installation.json', 'file');
  }

  // Mutate the directory only after every existing host state file is checked.
  const hostStat = checked(host, 'host', 'directory');
  const hostFd = openChecked(host, 'host', 'directory', hostStat);
  try { fchmodSync(hostFd, 0o700); } finally { closeSync(hostFd); }

  return Object.freeze({
    root,
    contents,
    host,
    soul_id: info.soul_id,
    definition_digest: lock.definition_digest,
    installation_id: installation.installation_id,
    members,
  });
}
