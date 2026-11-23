// What the entry point reads from a Soul package (soul-package
// spec/LAYOUT.md). Cooperative runtime state lives under <root>/Contents/.
//
//   SoulInfo.json            accepted definition: the Soul ID and its members
//   SoulLock.json            the package's claimed definition digest
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
import { createHash, randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { closeSync, constants, fchmodSync, fstatSync, lstatSync, mkdirSync, openSync, readdirSync, readFileSync, readSync, realpathSync, renameSync, writeFileSync } from 'node:fs';
import { basename, dirname, isAbsolute, join, parse, relative, resolve, sep } from 'node:path';
import { canonicalize } from './vendor/agent-bot-sdk/wire/canonical-json.mjs';
import { parseStrict } from './vendor/agent-bot-sdk/wire/strict-json.mjs';
import { verifyMemberSetAssignment } from './member-set-assignment.mjs';

const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SOUL_ID = /^agent_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const ROLE = /^[a-z][a-z0-9-]{0,31}$/;
const VERSION = /^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$/;
const DEFINITION_FILES = ['Contents/SoulInfo.json', 'Contents/SoulLock.json'];
const DEFINITION_TREES = ['Contents/primitives', 'Contents/opt'];
const HOST_PROJECTION_FILES = ['host/adapters.json', 'host/installation.json'];
const LAUNCH_INPUT_FIELDS = ['files', 'host_projection', 'selected_command', 'argv', 'system_images', 'sandbox_policy_digest', 'component_digests', 'environment', 'effective_config'];
const PROTECTED_COMPONENT_DIGESTS = ['machine', 'hq', 'souls', 'bridge', 'comms_broker', 'adapter', 'harness', 'test_provider'];
const COOPERATIVE_COMPONENT_DIGESTS = ['machine', 'hq', 'souls', 'comms_broker', 'adapter'];
const MAX_FROZEN_ENTRIES = 512;
const MAX_EXTERNAL_INPUTS = 64;
const MAX_INPUT_BYTES = 256 * 1024 ** 2;
const MAX_QUALIFICATION_STOCK_CLI_BYTES = 384 * 1024 ** 2;
const STOCK_CLI_PATH = 'runtime/bin/claude';
const STOCK_CLI_BYTES = 354_630_016;
const STOCK_CLI_SHA256 = 'e85547190ef8cd983033ba61b17194045a6fea00035da349efeabed86badacc9';
const MAX_CLOSURE_BYTES = 1024 ** 3;
const MAX_CONFIG_BYTES = 64 * 1024;
const MAX_SYSTEM_IMAGES_BYTES = 512 * 1024;
const MAX_LAUNCH_OBJECT_BYTES = 1024 * 1024;
const MAX_R_SIDECAR_BYTES = 2 * 1024 * 1024;
const PROTECTED_CHILD_ENV_FIELDS = ['schema', 'provider', 'base_url', 'http_host', 'client_key_sha256', 'model', 'messages_query', 'disable_nonessential_traffic'];
const PROTECTED_PLACEHOLDER_SHA256 = 'sha256:da4fec28d868ca5cf8f00f43869f703f138bd4211683b8637a751b904860ddf0';
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

function checked(path, label, kind, missing = false, owner = process.getuid()) {
  let stat;
  try { stat = lstatSync(path); } catch (e) {
    if (missing && e.code === 'ENOENT') return null;
    return bad(`${label}: cannot inspect path: ${e.code ?? e.message}`);
  }
  if ((kind === 'directory' && !stat.isDirectory()) || (kind === 'file' && !stat.isFile())) bad(`${label}: must be a real ${kind}, not a link`);
  if (kind === 'entry' && !stat.isDirectory() && !stat.isFile()) bad(`${label}: must be a real directory or regular file`);
  if (stat.uid !== owner) bad(`${label}: owner differs from ${owner === 0 ? 'root' : 'the runtime account'}`);
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
    if (stat.uid !== expected.uid) bad(`${label}: owner changed after inspection`);
    if (stat.mode & 0o022) bad(`${label}: group or other may write this path`);
    return fd;
  } catch (e) {
    if (fd !== undefined) closeSync(fd);
    if (e instanceof SoulError) throw e;
    return bad(`${label}: cannot open without following links: ${e.code ?? e.message}`);
  }
}

function readBytes(path, label) {
  const stat = checked(path, label, 'file');
  const fd = openChecked(path, label, 'file', stat);
  try { return readFileSync(fd); } catch (e) { return bad(`cannot read ${label}: ${e.code ?? e.message}`); }
  finally { closeSync(fd); }
}

function readJson(path, label) {
  const bytes = readBytes(path, label);
  try { return JSON.parse(bytes.toString('utf8')); } catch (e) { return bad(`${path} is not JSON: ${e.message}`); }
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

function requireCustodyChecks() {
  if (typeof process.getuid !== 'function' || constants.O_NOFOLLOW === undefined || constants.O_DIRECTORY === undefined) bad('Soul host custody: ownership and no-follow checks unavailable');
}

function checkDefinition(info, lock) {
  if (!isObject(info) || typeof info.soul_id !== 'string' || !SOUL_ID.test(info.soul_id)) bad('SoulInfo.json: soul_id is agent_<uuid>');
  if (!isObject(lock) || typeof lock.definition_digest !== 'string' || !DIGEST.test(lock.definition_digest)) bad('SoulLock.json: definition_digest is sha256:<64 hex>');
  if (!Array.isArray(info.members) || info.members.length === 0) bad('SoulInfo.json: members is a list with at least the lead');
}

function readMembers(info, adapters) {
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
  return members;
}

function checkInstallation(installation) {
  if (!isObject(installation) || typeof installation.installation_id !== 'string' || !ID.test(installation.installation_id)) bad('host/installation.json: needs an installation_id');
}

export function readSoul(root) {
  requireCustodyChecks();
  checked(root, 'Soul root', 'directory');
  // Anchor every later path below the resolved root, not a replaceable parent link.
  root = realpathSync(root);
  checkedAncestry(root);
  const contents = join(root, 'Contents');
  checked(root, 'Soul root', 'directory');
  checked(contents, 'Contents', 'directory');
  const info = readJson(join(contents, 'SoulInfo.json'), 'SoulInfo.json');
  const lock = readJson(join(contents, 'SoulLock.json'), 'SoulLock.json');
  checkDefinition(info, lock);

  const host = join(contents, 'host');
  if (!checked(host, 'host', 'directory', true)) mkdirSync(host, { mode: 0o700 });
  checked(host, 'host', 'directory');
  const members = readMembers(info, readJson(join(host, 'adapters.json'), 'host/adapters.json'));

  const installationPath = join(host, 'installation.json');
  let installation;
  if (checked(installationPath, 'host/installation.json', 'file', true)) {
    installation = readJson(installationPath, 'host/installation.json');
    checkInstallation(installation);
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
    stateRoot: contents,
    soul_id: info.soul_id,
    definition_digest: lock.definition_digest,
    installation_id: installation.installation_id,
    members,
  });
}

function checkAbsolutePath(path, label) {
  if (typeof path !== 'string' || path.includes('\0') || !isAbsolute(path) || resolve(path) !== path || path === parse(path).root) {
    bad(`${label}: needs a normalized absolute path below the filesystem root`);
  }
}

// Each parent must be root-owned and non-writable by the runner. Checking
// only the leaf would permit replacement from a runner-owned parent.
function checkRootTree(path, label) {
  const { root } = parse(path);
  checked(root, `${label} ancestry ${root}`, 'directory', false, 0);
  if (path === root) return;
  let parent = root;
  for (const component of path.slice(root.length).split(sep)) {
    parent = join(parent, component);
    checked(parent, `${label} ancestry ${parent}`, 'directory', false, 0);
  }
}

const SNAPSHOT_PARENT = '/private/var/db/managed-machine/soul-snapshots';
function checkAdminSnapshotRoot(path, label, installationId, ownerUid, runnerGid, identity) {
  const slot = createHash('sha256').update('agent-bot-soul-endpoint-installation/v1\0')
    .update(installationId).digest('hex').slice(0, 20);
  const namespace = join(SNAPSHOT_PARENT, slot);
  if (dirname(path) !== namespace || !/^snap_[0-9a-f]{24}$/.test(basename(path))
    || identity?.root_path !== path || identity.owner_uid !== ownerUid || identity.owner_gid !== runnerGid) {
    bad(label + ': not the signed installation snapshot');
  }
  checkRootTree(SNAPSHOT_PARENT, label);
  const parent = checked(namespace, label + ' namespace', 'directory', false, ownerUid);
  if (parent.gid !== runnerGid || (parent.mode & 0o7777) !== 0o750) bad(label + ': snapshot namespace has wrong runner group or mode');
  const root = checked(path, label, 'directory', false, ownerUid);
  const actual = lstatSync(path, { bigint: true });
  if (root.gid !== runnerGid || (root.mode & 0o7777).toString(8).padStart(4, '0') !== identity.mode
    || BigInt.asUintN(32, actual.dev).toString() !== identity.device || actual.ino.toString() !== identity.inode
    || actual.birthtimeNs?.toString() !== identity.birthtime_ns) {
    bad(label + ': snapshot identity differs from the signed Machine reservation');
  }
}

function checkSignedRRuntime(plan, installationId, ownerUid, runnerUid, runnerGid, stockCommand) {
  const root = plan.runtimeRoot;
  const ref = plan.rInventory;
  checkAbsolutePath(root, 'Frozen R runtime');
  if (!isObject(ref) || ref.contract !== 'machine/v3' || ref.kind !== 'stage2a-inventory-ref'
    || ref.schema_version !== 3 || ref.domain !== 'R-runtime'
    || ref.installation_id !== installationId || ref.machine_uid !== ownerUid
    || ref.reader_uid !== runnerUid || ref.reader_gid !== runnerGid
    || ref.snapshot?.path !== root || ref.snapshot?.owner_uid !== ownerUid
    || ref.snapshot?.owner_gid !== runnerGid || ref.snapshot?.mode !== '0555'
    || ref.sidecar?.owner_uid !== ownerUid || ref.sidecar?.owner_gid !== runnerGid
    || ref.sidecar?.mode !== '0440' || !isDigest(ref.sidecar?.sha256)
    || !isDigest(ref.inventory_digest) || !isDigest(ref.owner_plan_digest)
    || ref.owner_plan_digest !== `sha256:${plan.planDigest}`) {
    bad('Frozen R runtime: signed inventory reference differs from this start');
  }
  const slot = createHash('sha256').update('agent-bot/stage2a-domain-slot/v3\0R-runtime\0')
    .update(installationId).digest('hex').slice(0, 20);
  const stem = createHash('sha256').update('agent-bot/stage2a-domain-snapshot/v3\0R-runtime\0')
    .update(installationId).digest('hex').slice(0, 24);
  const namespace = join(SNAPSHOT_PARENT, `r_${slot}`);
  if (plan.snapshotCustody === 'machine-admin') {
    if (root !== join(namespace, `snap_${stem}`)
      || ref.sidecar.path !== join(namespace, `inventory_${stem}.jcs`)) {
      bad('Frozen R runtime: not the signed installation namespace');
    }
    checkRootTree(SNAPSHOT_PARENT, 'Frozen R runtime');
    const parent = checked(namespace, 'Frozen R runtime namespace', 'directory', false, ownerUid);
    if (parent.gid !== runnerGid || (parent.mode & 0o7777) !== 0o750) {
      bad('Frozen R runtime: namespace has wrong reader group or mode');
    }
  } else {
    checkRootTree(dirname(root), 'Frozen R runtime');
  }
  const snapshot = checked(root, 'Frozen R runtime root', 'directory', false, ownerUid);
  const actualRoot = lstatSync(root, { bigint: true });
  if (snapshot.gid !== runnerGid || (snapshot.mode & 0o7777) !== 0o555
    || BigInt.asUintN(32, actualRoot.dev).toString() !== ref.snapshot.device
    || actualRoot.ino.toString() !== ref.snapshot.inode
    || actualRoot.birthtimeNs?.toString() !== ref.snapshot.birthtime_ns) {
    bad('Frozen R runtime: root identity differs from the signed inventory');
  }
  if (dirname(ref.sidecar.path) !== dirname(root)) bad('Frozen R runtime: sidecar is outside the snapshot namespace');
  const sidecar = checked(ref.sidecar.path, 'Frozen R runtime sidecar', 'file', false, ownerUid);
  const actualSidecar = lstatSync(ref.sidecar.path, { bigint: true });
  if (sidecar.gid !== runnerGid || (sidecar.mode & 0o7777) !== 0o440
    || sidecar.nlink !== 1 || sidecar.size < 1 || sidecar.size > MAX_R_SIDECAR_BYTES
    || sidecar.size !== ref.sidecar.size_bytes
    || BigInt.asUintN(32, actualSidecar.dev).toString() !== ref.sidecar.device
    || actualSidecar.ino.toString() !== ref.sidecar.inode
    || actualSidecar.birthtimeNs?.toString() !== ref.sidecar.birthtime_ns) {
    bad('Frozen R runtime: sidecar identity differs from the signed inventory');
  }
  const fd = openChecked(ref.sidecar.path, 'Frozen R runtime sidecar', 'file', sidecar);
  let bytes;
  try { bytes = readFileSync(fd); } finally { closeSync(fd); }
  if (bytes.length !== sidecar.size || `sha256:${createHash('sha256').update(bytes).digest('hex')}` !== ref.sidecar.sha256) {
    bad('Frozen R runtime: sidecar bytes differ from the signed inventory');
  }
  let inventory;
  try { inventory = parseStrict(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
  catch (error) { bad(`Frozen R runtime: invalid sidecar JSON: ${error.message}`); }
  if (canonicalize(inventory) !== bytes.toString('utf8')
    || !hasFields(inventory, ['contract', 'kind', 'schema_version', 'domain', 'installation_id', 'limits', 'directories', 'files', 'total_bytes'])
    || inventory.contract !== 'machine/v3' || inventory.kind !== 'stage2a-domain-inventory'
    || inventory.schema_version !== 3 || inventory.domain !== 'R-runtime'
    || inventory.installation_id !== installationId || !Array.isArray(inventory.files)
    || inventory.files.length !== ref.file_count || !Array.isArray(inventory.directories)
    || inventory.directories.length !== ref.directory_count || inventory.total_bytes !== ref.total_bytes
    || measurement('agent-bot/stage2a-r-runtime-inventory/v3', bytes.toString('utf8')) !== ref.inventory_digest) {
    bad('Frozen R runtime: sidecar inventory differs from the signed reference');
  }
  const components = plan.rComponents;
  if (!Array.isArray(components) || !components.some((row) => row?.source_repository === 'true-line/agent-bot-souls')) {
    bad('Frozen R runtime: Souls release component is absent');
  }
  const stockRelative = stockCommand && relative(root, stockCommand);
  if (stockCommand && (!/^adapter\/[A-Za-z0-9._-]+$/.test(stockRelative)
    || basename(stockCommand) !== 'claude-agent-acp')) {
    bad('Frozen R runtime: stock ACP path is outside the reviewed adapter directory');
  }
  const stockCli = stockCommand && join(dirname(stockCommand), 'claude');
  const selected = new Map();
  const verifiedFiles = new Map();
  const selectedRelatives = stockCommand
    ? [stockRelative, relative(root, stockCli), 'bin/node', 'bin/agent-bot-souls.mjs', 'package.json']
    : ['adapter/cli', 'adapter/library.mjs', 'bin/node', 'bin/agent-bot-souls.mjs', 'package.json'];
  for (const relative of selectedRelatives) {
    const rows = inventory.files.filter((row) => row?.path === relative);
    if (rows.length !== 1 || rows[0].kind !== 'regular' || !isDigest(rows[0].sha256)
      || !components.some((component) => component.component_id === rows[0].component_id)
      || !components.some((component) => component.component_id === rows[0].component_id
        && component.source_repository === (relative.startsWith('adapter/')
          ? 'true-line/soul-adapters' : 'true-line/agent-bot-souls'))) {
      bad(`Frozen R runtime: ${relative} has no reviewed component row`);
    }
    const file = join(root, relative);
    const stat = checked(file, `Frozen R runtime ${relative}`, 'file', false, ownerUid);
    const mode = (stat.mode & 0o7777).toString(8).padStart(4, '0');
    if (stat.gid !== runnerGid || stat.nlink !== 1 || mode !== rows[0].mode
      || stat.size !== rows[0].size_bytes) bad(`Frozen R runtime: ${relative} identity differs from the signed row`);
    const hash = createHash('sha256');
    const input = openChecked(file, `Frozen R runtime ${relative}`, 'file', stat);
    try {
      const buffer = Buffer.alloc(65_536);
      for (let offset = 0; offset < stat.size;) {
        const count = readSync(input, buffer, 0, Math.min(buffer.length, stat.size - offset), offset);
        if (count <= 0) bad(`Frozen R runtime: ${relative} truncated during measurement`);
        hash.update(buffer.subarray(0, count));
        offset += count;
      }
      const after = fstatSync(input);
      if (!sameInput(after, stat)) bad(`Frozen R runtime: ${relative} changed during measurement`);
    } finally { closeSync(input); }
    if (`sha256:${hash.digest('hex')}` !== rows[0].sha256) bad(`Frozen R runtime: ${relative} bytes differ from the signed row`);
    selected.set(relative, file);
    verifiedFiles.set(file, rows[0].sha256);
  }
  return { node: selected.get('bin/node'), entry: selected.get('bin/agent-bot-souls.mjs'),
    adapter: selected.get(stockRelative ?? 'adapter/cli'), files: inventory.files, verifiedFiles };
}

function checkEntries(path, label, expected) {
  const entries = readdirSync(path);
  if (entries.length !== expected.length || expected.some(name => !entries.includes(name))) bad(`${label}: unexpected projection entries`);
}

const nestedIn = (path, root) => path === root || path.startsWith(`${root}${sep}`);
const overlaps = (left, right) => nestedIn(left, right) || nestedIn(right, left);
const byteOrder = (left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right));
const validEntryName = (name) => /^[\x20-\x7e]+$/.test(name) && name !== '.' && name !== '..' && !/[/\\]/.test(name);
const measurement = (purpose, canonical) => `sha256:${createHash('sha256').update(purpose).update('\0').update(canonical).digest('hex')}`;
const isDigest = (value) => typeof value === 'string' && DIGEST.test(value);
const hasFields = (value, fields) => isObject(value) && Object.keys(value).length === fields.length && fields.every(field => Object.hasOwn(value, field));

function boundedText(value, limit) {
  return typeof value === 'string' && value.length <= 2 * limit && !value.includes('\0')
    && (value.length <= limit || [...value].length <= limit);
}

function checkLaunchPath(path, label) {
  checkAbsolutePath(path, label);
  if (path.length > 4096 || !path.slice(1).split('/').every(validEntryName)) bad(`${label}: needs a canonical ASCII path of at most 4096 characters`);
}

function boundedCanonicalJson(value, label, maxBytes) {
  // Bound traversal and unescaped bytes before invoking recursive JCS.
  const pending = [[value, 0]];
  let nodes = 0;
  let textBytes = 0;
  while (pending.length) {
    const [item, depth] = pending.pop();
    if (++nodes > 4096 || depth > 16) bad(`${label}: exceeds the JSON depth or node limit`);
    if (typeof item === 'string') textBytes += Buffer.byteLength(item);
    if (item && typeof item === 'object') {
      const keys = Object.keys(item);
      if (keys.length + pending.length + nodes > 4096) bad(`${label}: exceeds the JSON node limit`);
      for (const key of keys) {
        if (!Array.isArray(item)) textBytes += Buffer.byteLength(key);
        pending.push([item[key], depth + 1]);
      }
    }
    if (textBytes > maxBytes) bad(`${label}: exceeds the ${maxBytes}-byte canonical JSON limit`);
  }
  let canonical;
  try { canonical = canonicalize(value); }
  catch (error) { return bad(`${label}: invalid canonical JSON: ${error.message}`); }
  if (Buffer.byteLength(canonical) > maxBytes) bad(`${label}: exceeds the ${maxBytes}-byte canonical JSON limit`);
  return canonical;
}

export function qualifiesStockCliQualificationInput(entry, record, enabled = false) {
  const { path, stat } = entry ?? {};
  return enabled === true && path === STOCK_CLI_PATH
    && stat?.isFile?.() === true && stat.size === STOCK_CLI_BYTES
    && stat.size <= MAX_QUALIFICATION_STOCK_CLI_BYTES
    && (stat.mode & 0o7777) === 0o550
    && record?.path === STOCK_CLI_PATH && record.kind === 'regular'
    && record.mode === '0550' && record.size === STOCK_CLI_BYTES
    && record.sha256 === STOCK_CLI_SHA256;
}

export function checkMeasuredStockCliQualificationInput(entry, enabled = false) {
  if (enabled !== true) return;
  if (entry?.path !== STOCK_CLI_PATH || entry.kind !== 'regular'
    || entry.mode !== '0550' || entry.size !== STOCK_CLI_BYTES
    || entry.sha256 !== STOCK_CLI_SHA256) {
    bad('stock CLI qualification input differs from the exact reviewed bytes');
  }
}

function checkInputLimits(entries, countLimit, { stockCliException = false, records = [] } = {}) {
  if (entries.length > countLimit) bad(`Protected Soul input: closure exceeds ${countLimit} entries`);
  let total = 0;
  for (const { path, stat } of entries) {
    if (!stat.isFile()) continue;
    const record = records.find((row) => row.path === path);
    if (!Number.isSafeInteger(stat.size) || stat.size < 0
      || (stat.size > MAX_INPUT_BYTES && !qualifiesStockCliQualificationInput(
        { path, stat }, record, stockCliException))) {
      bad(`${path}: input exceeds the per-file size limit`);
    }
    if (stat.nlink !== 1) bad(`${path}: regular file must have a single link`);
    total += stat.size;
    if (total > MAX_CLOSURE_BYTES) bad('Protected Soul input: closure exceeds the aggregate size limit');
  }
}

function definitionEntries(root, ownerUid = 0) {
  const entries = [];
  const folded = new Set();
  function visit(path, kind) {
    const file = join(root, path);
    const key = path.toLowerCase();
    if (folded.has(key)) bad(`${path}: case-fold duplicate in the installed definition`);
    folded.add(key);
    if (entries.length === MAX_FROZEN_ENTRIES) bad(`Protected Soul definition: closure exceeds ${MAX_FROZEN_ENTRIES} entries`);
    const stat = checked(file, path, kind, false, ownerUid);
    entries.push({ path, file, stat });
    if (stat.isDirectory()) {
      for (const entry of readdirSync(file, { encoding: 'buffer' })) {
        const name = entry.toString('latin1');
        if (!validEntryName(name)) bad(`${path}: invalid ASCII entry name`);
        const child = `${path}/${name}`;
        const kind = DEFINITION_FILES.includes(child) ? 'file' : DEFINITION_TREES.includes(child) ? 'directory' : 'entry';
        visit(child, kind);
      }
    }
  }
  visit('Contents', 'directory');
  return entries;
}

function launchInputEntries(root, records, ownerUid = 0) {
  const directories = new Map([['', new Map()]]);
  const files = new Set();
  let previous;
  for (const record of records) {
    const path = record?.path;
    if (typeof path !== 'string' || path.length > 4096 || !path.split('/').every(validEntryName)) bad('Protected Soul launch input: invalid root-relative record path');
    if (previous !== undefined && byteOrder(previous, path) >= 0) bad('Protected Soul launch input: records must be in strict path order');
    previous = path;
    files.add(path);

    let parent = '';
    for (const name of path.split('/')) {
      const children = directories.get(parent);
      const folded = name.toLowerCase();
      if (children.has(folded) && children.get(folded) !== name) bad(`${path}: case-fold duplicate in the launch input projection`);
      children.set(folded, name);
      parent = parent ? `${parent}/${name}` : name;
      if (parent !== path && !directories.has(parent)) directories.set(parent, new Map());
    }
  }
  if (HOST_PROJECTION_FILES.some(path => !files.has(path))) bad('Protected Soul launch input: host projection records are required');
  for (const [path, children] of directories) {
    if (files.has(path)) bad(`${path}: launch input path names both a file and a directory`);
    const directory = join(root, path);
    if (path) checked(directory, path, 'directory', false, ownerUid);
    checkEntries(directory, 'Protected Soul launch input projection', [...children.values()]);
  }
  return records.map(({ path }) => {
    const file = join(root, path);
    return { path, file, stat: checked(file, path, 'file', false, ownerUid) };
  });
}

function checkSystemImages(images) {
  if (!hasFields(images, ['product_version', 'build_version', 'darwin_kernel', 'selected'])
      || ![images.product_version, images.build_version, images.darwin_kernel].every(value => value && boundedText(value, 128))
      || !Array.isArray(images.selected) || images.selected.length < 1 || images.selected.length > 256) {
    bad('Protected Soul system images: requires bounded product version, build, kernel and 1–256 selected images');
  }
  const seen = new Set();
  let previous;
  for (const image of images.selected) {
    if (!hasFields(image, ['path', 'signing_requirement', 'cdhash'])
        || !image.signing_requirement || !boundedText(image.signing_requirement, 4096)
        || typeof image.cdhash !== 'string' || !/^[0-9a-f]{40}$/.test(image.cdhash)) {
      bad('Protected Soul system image: requires a bounded signing requirement and a lowercase CDHash');
    }
    checkLaunchPath(image.path, 'Protected Soul system image');
    const folded = image.path.toLowerCase();
    if (seen.has(folded)) bad('Protected Soul system images: duplicate or case-fold alias');
    if (previous !== undefined && byteOrder(previous, image.path) >= 0) bad('Protected Soul system images: selected paths must be in strict path order');
    seen.add(folded);
    previous = image.path;
  }
}

function checkLaunchInputRecords(records, expectedProfile) {
  if (!hasFields(records, LAUNCH_INPUT_FIELDS) || !Array.isArray(records.files)
      || !hasFields(records.host_projection, ['adapters', 'installation'])
      || !Object.values(records.host_projection).every(isObject)
      || !isDigest(records.sandbox_policy_digest) || !isObject(records.component_digests)
      || !isObject(records.environment)
      || !isObject(records.effective_config)) {
    bad('Protected Soul launch input: complete reviewed launch input object is required');
  }
  checkLaunchPath(records.selected_command, 'Protected Soul selected command');
  if (!Array.isArray(records.argv) || records.argv.length < 1 || records.argv.length > 128
      || !records.argv.every(value => boundedText(value, 4096))) bad('Protected Soul launch input: argv exceeds the argument count or length limit');
  if (records.argv[0] !== records.selected_command) bad('Protected Soul launch input: full argv must begin with the selected command');
  const environment = Object.entries(records.environment);
  if (environment.length > 256 || environment.some(([key, value]) => !/^[A-Za-z_][A-Za-z0-9_]*$/.test(key) || !boundedText(value, 8192))) {
    bad('Protected Soul launch input: environment exceeds the property, key or value limits');
  }
  const profile = records.effective_config.profile;
  if ((profile !== 'managed-protected' && profile !== 'managed-cooperative') || profile !== expectedProfile) {
    bad('Protected Soul launch input: effective profile differs from the expected profile');
  }
  const components = profile === 'managed-protected' ? PROTECTED_COMPONENT_DIGESTS : COOPERATIVE_COMPONENT_DIGESTS;
  const actualComponents = Object.keys(records.component_digests);
  const optionalPair = profile === 'managed-cooperative'
    && actualComponents.includes('harness') === actualComponents.includes('test_provider');
  if ((!hasFields(records.component_digests, components)
      && !(profile === 'managed-cooperative' && optionalPair
        && components.every((name) => Object.hasOwn(records.component_digests, name))
        && actualComponents.every((name) => [...components, 'harness', 'test_provider'].includes(name))))
    || !Object.values(records.component_digests).every(isDigest)) {
    bad('Protected Soul launch input: component digests differ from the selected profile');
  }
  if (Object.hasOwn(records.environment, 'B_ONLY_TOKEN')) bad('Protected Soul launch input: bridge-only proof is forbidden in the runner environment');
  if (records.files.length > MAX_EXTERNAL_INPUTS) bad(`Protected Soul launch input: closure exceeds ${MAX_EXTERNAL_INPUTS} entries`);
  checkSystemImages(records.system_images);
  for (const [label, value] of [
    ['host adapters', records.host_projection.adapters], ['host installation', records.host_projection.installation],
    ['effective config', records.effective_config],
  ]) {
    if (Object.keys(value).length > 256) bad(`Protected Soul ${label}: exceeds the property limit`);
    boundedCanonicalJson(value, `Protected Soul ${label}`, MAX_CONFIG_BYTES);
  }
  boundedCanonicalJson(records.argv, 'Protected Soul argv', MAX_CONFIG_BYTES);
  boundedCanonicalJson(records.environment, 'Protected Soul environment', MAX_CONFIG_BYTES);
  boundedCanonicalJson(records.system_images, 'Protected Soul system images', MAX_SYSTEM_IMAGES_BYTES);
  return boundedCanonicalJson(records, 'Protected Soul launch input', MAX_LAUNCH_OBJECT_BYTES);
}

function sameInput(actual, expected) {
  return actual.isFile() && ['dev', 'ino', 'uid', 'gid', 'mode', 'nlink', 'size', 'mtimeMs', 'ctimeMs'].every((key) => actual[key] === expected[key]);
}

function measureInput({ path, file, stat }, captured) {
  const mode = (stat.mode & 0o7777).toString(8).padStart(4, '0');
  if (stat.isDirectory()) return { path, kind: 'directory', mode };
  const hash = createHash('sha256');
  const size = stat.size;
  const buffer = Buffer.alloc(captured ? size : Math.min(size, 65_536));
  const fd = openChecked(file, path, 'file', stat);
  try {
    if (!sameInput(fstatSync(fd), stat)) bad(`${path}: input changed before measurement`);
    for (let position = 0; position < size;) {
      const offset = captured ? position : 0;
      const count = readSync(fd, buffer, offset, Math.min(size - position, 65_536), position);
      if (count === 0) bad(`${path}: input was truncated during measurement`);
      hash.update(buffer.subarray(offset, offset + count));
      position += count;
    }
    if (!sameInput(fstatSync(fd), stat)) bad(`${path}: input changed during measurement`);
  } finally { closeSync(fd); }
  captured?.set(path, buffer);
  return { path, kind: 'regular', mode, size, sha256: hash.digest('hex') };
}

function readMeasuredJson(path, captured) {
  try { return parseStrict(captured.get(path)); }
  catch (error) { return bad(`${path}: ${error.message}`); }
}

// Read-only preflight of a frozen definition and separate runner state against
// reviewed measurements. Machine must authenticate the one-use start and
// independently measure the installed launch before this can authorize it.
export function readProtectedSoulLayout(root, stateRoot, plan = {}, expectedProfile = 'managed-protected',
  { qualificationStockCliException = false } = {}) {
  requireCustodyChecks();
  if (expectedProfile !== 'managed-protected' && expectedProfile !== 'managed-cooperative') {
    bad('frozen Soul layout: unsupported profile');
  }
  const uid = process.getuid();
  if (uid === 0 || process.geteuid?.() !== uid) bad('Protected Soul custody: the runner needs a non-root account');
  if (!isObject(plan)) bad('Protected Soul layout: exact reviewed input measurements are required');
  const { launchInputRoot, definitionMeasurement, launchInputMeasurement, launchInputRecords, installationId, runnerUid } = plan;
  checkAbsolutePath(root, 'Protected Soul projection');
  checkAbsolutePath(stateRoot, 'Protected Soul state');
  checkAbsolutePath(launchInputRoot, 'Protected Soul launch input projection');
  if (overlaps(root, stateRoot) || overlaps(launchInputRoot, stateRoot) || overlaps(root, launchInputRoot)
    || (plan.runtimeRoot !== undefined && [root, stateRoot, launchInputRoot].some((path) => overlaps(plan.runtimeRoot, path)))) {
    bad('Protected Soul layout: definition, state, runtime and launch input projection must be disjoint');
  }
  if (typeof installationId !== 'string' || !ID.test(installationId)) bad('Protected Soul layout: reviewed installation ID is required');
  if (uid !== runnerUid) bad('Protected Soul state: runtime UID differs from the reviewed installation runner UID');
  if (stateRoot !== plan.stateRoot) bad('Protected Soul state: path differs from the reviewed installation state path');
  if (![definitionMeasurement, launchInputMeasurement].every(isDigest)) {
    bad('Protected Soul layout: exact reviewed input measurements are required');
  }
  const approvedCanonical = checkLaunchInputRecords(launchInputRecords, expectedProfile);

  const contents = join(root, 'Contents');
  const snapshotOwnerUid = plan.snapshotCustody === 'machine-admin' ? plan.snapshotOwnerUid : 0;
  if (plan.snapshotCustody === 'machine-admin') {
    checkAdminSnapshotRoot(root, 'Protected Soul projection', installationId,
      snapshotOwnerUid, plan.snapshotGroupGid, plan.definitionSnapshot);
    checked(contents, 'Protected Contents', 'directory', false, snapshotOwnerUid);
  } else {
    checkRootTree(contents, 'Protected Soul projection');
  }
  checkEntries(root, 'Protected Soul projection', ['Contents']);
  checkEntries(contents, 'Protected Contents', [...DEFINITION_FILES, ...DEFINITION_TREES].map(name => basename(name)));
  if (plan.snapshotCustody === 'machine-admin') {
    checkAdminSnapshotRoot(launchInputRoot, 'Protected Soul launch input projection', installationId,
      snapshotOwnerUid, plan.snapshotGroupGid, plan.launchInputSnapshot);
  } else {
    checkRootTree(launchInputRoot, 'Protected Soul launch input projection');
  }

  if (plan.stateCustody === 'runner-home' || plan.stateCustody === 'runner-home-canonical') {
    // macOS /var is the system alias for /private/var. The dedicated R home
    // and its state are runner-owned Life, while their physical parent stays
    // root-owned. Neither location may supply frozen executable inputs.
    const canonical = plan.stateCustody === 'runner-home-canonical';
    const prefix = canonical ? '/private/var/agent-bot-soul-runner-' : '/var/agent-bot-soul-runner-';
    if (!stateRoot.startsWith(prefix) || basename(stateRoot) !== 'state'
      || realpathSync('/var') !== '/private/var'
      || realpathSync(stateRoot) !== (canonical ? stateRoot : '/private' + stateRoot)) {
      bad('Protected Soul state: not the fixed private runner state path');
    }
    const physicalHome = dirname(realpathSync(stateRoot));
    checkRootTree(dirname(physicalHome), 'Protected Soul state');
    const home = checked(physicalHome, 'Protected Soul runner home', 'directory', false, uid);
    if ((home.mode & 0o7777) !== 0o700) bad('Protected Soul runner home: mode must be 0700');
  } else {
    checkRootTree(dirname(stateRoot), 'Protected Soul state');
  }
  const state = checked(stateRoot, 'Protected Soul state', 'directory', false, uid);
  if ((state.mode & 0o7777) !== 0o700) bad('Protected Soul state: mode must be 0700');

  const definition = definitionEntries(root, snapshotOwnerUid);
  const projection = launchInputEntries(launchInputRoot, launchInputRecords.files, snapshotOwnerUid);
  checkInputLimits(definition, MAX_FROZEN_ENTRIES);
  const stockCliException = qualificationStockCliException === true
    && Boolean(plan.memberSetEnvelopeBytes);
  checkInputLimits(projection, MAX_EXTERNAL_INPUTS, {
    stockCliException, records: launchInputRecords.files });
  if (plan.memberSetEnvelopeBytes) {
    const manifest = definition.filter(({ path }) => path === 'Contents/opt/stock-claude.json');
    if (manifest.length !== 1 || !manifest[0].stat.isFile() || manifest[0].stat.size > MAX_CONFIG_BYTES) {
      bad('Protected Soul stock adapter manifest is missing or exceeds the raw JSON limit');
    }
  }
  for (const { path, stat } of projection) {
    if (HOST_PROJECTION_FILES.includes(path) && stat.size > MAX_CONFIG_BYTES) bad(`${path}: exceeds the ${MAX_CONFIG_BYTES}-byte raw host JSON limit`);
  }

  const captured = new Map();
  const byPath = (left, right) => byteOrder(left.path, right.path);
  const definitionRecords = definition.sort(byPath).map(entry => measureInput(entry,
    DEFINITION_FILES.includes(entry.path) || (plan.memberSetEnvelopeBytes
      && entry.path === 'Contents/opt/stock-claude.json') ? captured : undefined));
  const measuredDefinition = measurement('agent-bot/stage2a-definition-opt-closure/v1', canonicalize(definitionRecords));
  if (measuredDefinition !== definitionMeasurement) bad('Protected Soul definition: measurement differs from the reviewed inventory');
  const measuredProjection = projection.map(entry => measureInput(entry, HOST_PROJECTION_FILES.includes(entry.path) ? captured : undefined));
  if (stockCliException) {
    const measuredCli = measuredProjection.find((entry) => entry.path === STOCK_CLI_PATH);
    checkMeasuredStockCliQualificationInput(measuredCli, true);
  }
  const adapters = readMeasuredJson('host/adapters.json', captured);
  const installation = readMeasuredJson('host/installation.json', captured);
  const measuredRecords = Object.freeze({
    ...launchInputRecords,
    files: Object.freeze(measuredProjection.map(Object.freeze)),
    host_projection: { adapters, installation },
  });
  const measuredCanonical = boundedCanonicalJson(measuredRecords, 'Protected Soul launch input', MAX_LAUNCH_OBJECT_BYTES);
  const launchPurpose = expectedProfile === 'managed-cooperative'
    ? 'agent-bot/stage2a-cooperative-launch-inputs/v3' : 'agent-bot/stage2a-launch-inputs/v1';
  const measuredLaunch = measurement(launchPurpose, measuredCanonical);
  if (measuredLaunch !== launchInputMeasurement || measuredCanonical !== approvedCanonical) bad('Protected Soul launch input: measurement differs from the reviewed inventory');
  const launchDigests = new Set(measuredProjection.map(({ sha256 }) => `sha256:${sha256}`));
  if (!launchDigests.has(launchInputRecords.sandbox_policy_digest)) bad('Protected Soul launch input: sandbox policy has no measured file');
  if (expectedProfile === 'managed-protected') {
    for (const [name, digest] of Object.entries(launchInputRecords.component_digests)) {
      if (!launchDigests.has(digest)) bad(`Protected Soul launch input: ${name} has no measured file`);
    }
  }

  const info = readMeasuredJson('Contents/SoulInfo.json', captured);
  const lock = readMeasuredJson('Contents/SoulLock.json', captured);
  checkDefinition(info, lock);
  if (expectedProfile === 'managed-cooperative' && plan.entryLaunch === true) {
    if (!isObject(installation) || installation.id !== installationId) bad('Protected Soul host projection: installation ID differs from the reviewed plan');
  } else checkInstallation(installation);
  if (expectedProfile !== 'managed-cooperative' || plan.entryLaunch !== true) {
    if (installation.installation_id !== installationId) bad('Protected Soul host projection: installation ID differs from the reviewed plan');
  }
  if (plan.stateCustody !== 'runner-home' && plan.stateCustody !== 'runner-home-canonical'
    && basename(stateRoot) !== installationId) bad('Protected Soul state: directory name differs from the installation ID');
  const members = readMembers(info, adapters);
  const code = [...definition.filter(({ path }) => path.startsWith('Contents/opt/')), ...projection.filter(({ path }) => !HOST_PROJECTION_FILES.includes(path))];
  const executablePaths = new Set(code.filter(({ stat }) => stat.isFile() && (stat.mode & 0o111)).map(({ file }) => file));
  const stockCommand = plan.memberSetEnvelopeBytes
    ? members.find((member) => member.role === LEAD)?.routes[0]?.command[0] : undefined;
  const runtime = expectedProfile === 'managed-cooperative' && plan.entryLaunch === true
    ? checkSignedRRuntime(plan, installationId, snapshotOwnerUid, uid, plan.runnerGid, stockCommand)
    : null;
  let memberSetAssignment;
  if (plan.memberSetEnvelopeBytes) {
    const files = new Map(measuredProjection.map(({ path, sha256 }) =>
      [projection.find((entry) => entry.path === path)?.file, `sha256:${sha256}`]));
    if (runtime) for (const [file, digest] of runtime.verifiedFiles) files.set(file, digest);
    const expected = {
      profile_in_force: expectedProfile, host_id: plan.hostId,
      installation_id: installationId, soul_id: plan.soulId,
      start_id: plan.startId, hq_epoch: plan.hqEpoch,
      plan_id: plan.planId, plan_digest: plan.planDigest,
      reservation_sha256: plan.reservationSha256,
      soul_artifact_sha256: plan.soulArtifactSha256,
      definition_measurement: measuredDefinition,
      runner_uid: plan.runnerUid, runner_gid: plan.runnerGid,
      b_authority_sha256: plan.bAuthoritySha256,
      bridge: plan.memberSetBridge,
      bridge_uid: plan.memberEndpoint?.expected_peer_uid,
      bridge_gid: plan.memberEndpoint?.group_gid,
      member_endpoint: plan.memberEndpoint,
      relay_endpoint: plan.relayEndpoint,
    };
    memberSetAssignment = verifyMemberSetAssignment({
      envelopeBytes: plan.memberSetEnvelopeBytes, machinePin: plan.machinePin,
      expected, frozen: {
        soulInfoBytes: captured.get('Contents/SoulInfo.json'),
        adapterManifestBytes: captured.get('Contents/opt/stock-claude.json'),
        hostProjection: { adapters, installation },
        definitionMeasurement: measuredDefinition, files,
      },
    });
    if (members.length !== 2 || memberSetAssignment.payload.members.some((assigned, index) =>
      assigned.member_id !== [...members].sort((a, b) => byteOrder(a.member_id, b.member_id))[index]?.member_id)) {
      bad('Protected Soul member set differs from the signed assignment');
    }
  }
  if (plan.entryLaunch === true) {
    const node = runtime?.node ?? join(launchInputRoot, 'bin', 'node');
    const entry = runtime?.entry ?? join(launchInputRoot, 'bin', 'agent-bot-souls.mjs');
    const startFlag = expectedProfile === 'managed-protected' ? '--protected-start-fd' : '--cooperative-start-fd';
    const expectedArgv = [node, entry, 'run', '--soul', root,
      '--admission-socket', plan.admissionSocket,
      ...(plan.adapterTransport === 'brokered-b'
        ? ['--member-socket', plan.memberSocket, '--relay-socket', plan.relaySocket]
        : ['--broker-socket', plan.brokerSocket]),
      '--profile', expectedProfile, startFlag, '3'];
    if ((!runtime && (!executablePaths.has(node) || !projection.some(({ file }) => file === entry)))
      || canonicalize(launchInputRecords.argv) !== canonicalize(expectedArgv)
      || launchInputRecords.selected_command !== node) {
      bad('Protected Soul launch input: fixed Souls entry argv differs from the signed Machine start');
    }
    const expectedEnv = { PATH: '/usr/bin:/bin', HOME: expectedProfile === 'managed-cooperative' ? stateRoot : dirname(stateRoot),
      AGENT_BOT_SOULS_REQUIRE_HQ_LAUNCH: '1' };
    if (canonicalize(launchInputRecords.environment) !== canonicalize(expectedEnv)) {
      bad('Protected Soul launch input: fixed Souls entry environment differs from the signed Machine start');
    }
    const childEnv = launchInputRecords.effective_config.adapter_child_env;
    if (!hasFields(childEnv, PROTECTED_CHILD_ENV_FIELDS)
      || childEnv.schema !== 'agent-bot-souls/adapter-child-env/v1'
      || childEnv.provider !== 'anthropic-messages'
      || childEnv.base_url !== 'http://fixture.invalid'
      || childEnv.http_host !== 'fixture.invalid'
      || childEnv.client_key_sha256 !== PROTECTED_PLACEHOLDER_SHA256
      || !boundedText(childEnv.model, 128) || childEnv.model.length === 0
      || !boundedText(childEnv.messages_query, 1024)
      || childEnv.disable_nonessential_traffic !== true) {
      bad('Protected Soul launch input: signed stock child environment is invalid');
    }
    const adapterId = launchInputRecords.effective_config.adapter_id;
    if (typeof adapterId !== 'string' || !ID.test(adapterId)
      || (memberSetAssignment && memberSetAssignment.payload.members.some((member) => member.adapter_id !== adapterId))
      || (!memberSetAssignment && (members.length !== 1 || members[0].role !== LEAD
        || members[0].routes.length !== 1 || members[0].routes[0].adapter_id !== adapterId))) {
      bad('Protected Soul launch input: signed stock child route differs from the sole lead');
    }
    const child = members.find((member) => member.role === LEAD)?.routes[0];
    const childPath = expectedProfile === 'managed-cooperative'
      ? (memberSetAssignment ? relative(plan.runtimeRoot, child.command[0]) : 'adapter/cli')
      : projection.find(({ file }) => file === child.command[0])?.path;
    const childFile = expectedProfile === 'managed-cooperative'
      ? runtime?.files.find(({ path }) => path === childPath)
      : measuredProjection.find(({ path }) => path === childPath);
    const childDigest = expectedProfile === 'managed-cooperative' ? childFile?.sha256
      : childFile?.sha256 && `sha256:${childFile.sha256}`;
    if (expectedProfile === 'managed-cooperative'
      && runtime.files.find(({ path }) => path === 'bin/agent-bot-souls.mjs')?.sha256
        !== launchInputRecords.component_digests.souls) {
      bad('Protected Soul launch input: Souls digest differs from frozen R runtime');
    }
    if (child.command.length !== 1 || (expectedProfile === 'managed-protected'
      && basename(child.command[0]) !== 'claude-agent-acp')
      || Object.keys(child.env).length !== 0 || !childFile || !childFile.sha256
      || childDigest !== launchInputRecords.component_digests.adapter
      || (expectedProfile === 'managed-cooperative' ? child.command[0] !== runtime.adapter
        : !executablePaths.has(child.command[0]))) {
      bad('Protected Soul launch input: stock ACP argv, environment or adapter digest differs from frozen inputs');
    }
  }
  if (expectedProfile === 'managed-cooperative' && plan.entryLaunch === true) {
    executablePaths.add(runtime.adapter);
  }
  for (const member of members) {
    for (const { command, env } of member.routes) {
      if (!executablePaths.has(command[0])) bad(`${member.member_id}: adapter executable is outside the reviewed code inventory`);
      if (plan.entryLaunch !== true && canonicalize(command) !== canonicalize(launchInputRecords.argv)) bad(`${member.member_id}: adapter argv differs from the reviewed launch input`);
      if (plan.entryLaunch !== true && Object.entries(env).some(([name, value]) => launchInputRecords.environment[name] !== value)) bad(`${member.member_id}: adapter environment differs from the reviewed launch input`);
    }
  }
  return Object.freeze({
    root, stateRoot, launchInputRoot, members,
    soulId: info.soul_id,
    installationId,
    claimedDefinitionDigest: lock.definition_digest,
    definitionMeasurement: measuredDefinition,
    definitionRecords: Object.freeze(definitionRecords.map(Object.freeze)),
    launchInputMeasurement: measuredLaunch,
    launchInputRecords: measuredRecords,
    ...(memberSetAssignment ? { memberSetAssignment } : {}),
  });
}
