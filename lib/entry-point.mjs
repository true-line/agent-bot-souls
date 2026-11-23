// The Soul entry point (agent-bot-hq plan §9 row 14; 0.4 §3, §5, §9). It:
//
// - clocks the Soul in with HQ on admission.sock: Hello, Equip, Ready, and
//   Lease renewals;
// - starts each member's adapter as its own process and drives it over the
//   Agent Client Protocol (ACP) on stdio, one turn at a time per member;
// - gives the owner one conversation, which is the lead's;
// - routes work by role when the lead asks;
// - keeps typed notes, and gives a returning lead its handoff notes before
//   it continues;
// - runs the recovery ladder when a member fails.
//
// It holds no authority. It has no keys and decides no grant. A member
// commits to a task itself, over its own connection to HQ's broker, and HQ
// decides. The entry point only passes each member the runtime HQ admitted
// it as. In the cooperative profile that binding is a bearer secret inside
// the Soul, which HQ reports as `managed-cooperative`.
//
// A restarted member is a new runtime, so a restart is a new admission. The
// new lease generation fences the old lead: nothing it still holds can
// finalize a task. Members that kept running pick up their new runtime the
// next time HQ refuses the old one.
import { spawn } from 'node:child_process';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { chmodSync, lstatSync, mkdirSync, realpathSync, unlinkSync } from 'node:fs';
import { connect, createServer } from 'node:net';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { canonicalize, loadContracts, parseStrict } from './contracts.mjs';
import { attachHq, connectHq, HqRefusal } from './hq-client.mjs';
import { REQUEST_CANCELLED, rpcPeer, RpcError } from './jsonrpc.mjs';
import { readLines, writeLine } from './ndjson.mjs';
import { handoffs, NoteError, restrictions, writeNote } from './notes.mjs';
import { authenticateMemberPeer, memberPeerSupported } from './member-peer.mjs';
import { classify, createLadder } from './recovery.mjs';
import { LEAD, readProtectedSoulLayout, readSoul } from './soul.mjs';
import { verifyMemberSetAdmission, verifyMemberSetLaunch } from './member-set-assignment.mjs';
import { verifyMemberSetAttach } from './member-set-attach.mjs';
import { checkProtectedStart } from './protected-start.mjs';
import { attachCooperative, checkCooperativeBPublishOutcome, checkCooperativeStart, connectCooperativeAdmission, verifyCooperativeBMemberPath, verifyCooperativeBParents } from './cooperative-start.mjs';
import { openMemberSession } from './vendor/agent-bot-sdk/member-session.mjs';

export const ACP_PROTOCOL_VERSION = 1;
const MAX_PROMPT = 65536;
const PROTECTED_INPUTS_UNAVAILABLE = 'Machine-authenticated protected Soul launch inputs are unavailable';
const MEMBER_HELLO_MS = 5_000;
const MAX_UNAUTHENTICATED = 16;
// HQ retains an unattached reservation for 30 seconds. An unanswered
// reservation cannot be stopped by ID and must not hold shutdown forever.
const RESERVATION_DRAIN_MS = 30_000;
// HQ can spend 35 seconds on normal group lookup, TERM, KILL and pipe closure.
const STOP_CONFIRM_MS = 45_000;
// sun_path with its NUL: 104 bytes on macOS and the BSDs, 108 on Linux.
const MAX_SOCKET_PATH = (process.platform === 'linux' ? 108 : 104) - 1;

function socketPath(value, label) {
  if (typeof value !== 'string' || !value.startsWith('/') || Buffer.byteLength(value) > MAX_SOCKET_PATH) throw new Error(`HQ launch did not return a usable ${label}`);
  return value;
}

// The separate-runner route has a Machine-provisioned per-start directory.
// This checks the HQ assignment before binding; Machine must independently
// authenticate the directory and account in its one-use start record.
export function memberEndpoint(launch, runnerUid = process.geteuid()) {
  const path = socketPath(launch?.member_socket, 'member socket path');
  const assigned = launch?.member_endpoint;
  if (assigned === undefined) return { path, broker: join(dirname(path), 'broker.sock'), mode: 0o660 };
  if (!assigned || typeof assigned !== 'object' || Array.isArray(assigned)) throw new Error('HQ launch returned an invalid member endpoint');
  if (Object.keys(assigned).some((key) => !['directory', 'owner_uid', 'group_gid', 'dir_mode', 'socket_mode', 'peer_uids'].includes(key))) throw new Error('HQ launch member endpoint contains an unsupported field');
  const { directory, owner_uid: ownerUid, group_gid: groupGid, dir_mode: dirMode, socket_mode: mode, peer_uids: peerUids } = assigned;
  if (typeof directory !== 'string' || !directory.startsWith('/') || resolve(directory) !== directory || dirname(path) !== directory) throw new Error('HQ launch member endpoint does not bind its exact directory');
  if (!Number.isSafeInteger(ownerUid) || ownerUid !== runnerUid || !Number.isSafeInteger(groupGid) || groupGid < 0 || dirMode !== 0o2750 || mode !== 0o660) throw new Error('HQ launch member endpoint has an invalid runner, group or mode');
  if (!Array.isArray(peerUids) || peerUids.length !== 2 || !peerUids.includes(ownerUid) || new Set(peerUids).size !== 2 || peerUids.some(uid => !Number.isSafeInteger(uid) || uid < 1 || uid >= 0xffffffff)) throw new Error('HQ launch member endpoint lacks exact runner and bridge peer UIDs');
  if (!memberPeerSupported()) throw new Error('kernel member peer UID verification is unavailable');
  const st = lstatSync(directory);
  if (!st.isDirectory() || realpathSync(directory) !== directory || st.uid !== ownerUid || st.gid !== groupGid || (st.mode & 0o7777) !== dirMode) throw new Error('HQ launch member endpoint directory has an unexpected owner, group or mode');
  return { path, mode, directory, ownerUid, groupGid, peerUids,
    bridgeUid: peerUids.find(uid => uid !== ownerUid), dev: st.dev, ino: st.ino };
}

// The Soul cannot take the turn. `state` says why: quarantined, waiting,
// needs-owner, unavailable or stopped.
export class SoulUnavailable extends Error {
  constructor(state, reason, code) {
    super(`the Soul is ${state}: ${code ? `${code}: ` : ''}${reason}`);
    this.name = 'SoulUnavailable';
    this.state = state;
    this.reason = reason;
    if (code) this.code = code;
  }
}

class MemberRefusal extends Error {
  constructor(code, message) { super(message); this.code = code; }
}
const refuse = (code, message) => { throw new MemberRefusal(code, message); };

// Is something listening on `path`? Tells a stale socket file from another
// entry point that is running this Soul.
const live = (path) => new Promise((resolve, reject) => {
  const s = connect(path);
  s.once('connect', () => { s.destroy(); resolve(true); });
  s.once('error', error => {
    if (error.code === 'ECONNREFUSED' || error.code === 'ENOENT') resolve(false);
    else reject(error);
  });
});

const sleep = (ms) => new Promise((r) => { setTimeout(r, ms); });
const hex = (n) => randomBytes(n).toString('hex');
const sameToken = (a, b) => a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));
const cleanupFailure = (errors) => errors.length === 1 ? errors[0]
  : new AggregateError(errors, errors.map(error => String(error?.message ?? error)).join('\n'));

// Do not retire the socket while a peer helper may still hold its accepted
// stream as fd 3. A missing child close is a cleanup failure, not a join.
export async function closeListener(listener) {
  if (!listener) return;
  listener.closing = true;
  for (const socket of listener.sockets) socket.destroy();
  const checks = [...listener.peerChecks];
  for (const check of checks) check.abort();
  const joined = await Promise.allSettled(checks.map((check) => check.done));
  const failures = [...new Set([...(listener.peerFailures ?? []),
    ...joined.filter((result) => result.status === 'rejected').map((result) => result.reason)])];
  if (failures.length) throw cleanupFailure(failures);
  // Node may unlink the bound pathname during close. The inode check guards
  // only the explicit cleanup below, so the parent must remain trusted.
  await new Promise((resolve) => listener.server.close(() => resolve()));
  if (listener.ino === null) return;
  try {
    const st = lstatSync(listener.path);
    if (st.isSocket() && st.uid === process.geteuid() && st.dev === listener.dev && st.ino === listener.ino) unlinkSync(listener.path);
  } catch { /* already gone or unreadable */ }
}

// A member's environment: the entry point's own, without anything that
// names another agent-bot identity, plus the adapter's and the member's.
function memberEnv(base, adapterEnv, own) {
  const env = {};
  for (const [k, v] of Object.entries(base)) if (v !== undefined && !/^(AGENT_BOT_|QWTS_AGENT_)/.test(k)) env[k] = v;
  return { ...env, ...adapterEnv, ...own };
}

export async function startSoul({ root, hqHome, admissionSocket, brokerSocket, memberSocket, relaySocket, requestedProfile = 'managed-cooperative', protectedStateRoot, protectedInputs, protectedStart, cooperativeStart, signal, delay = sleep, clock = { now: () => Date.now() }, log = () => {}, renewEveryMs = 20_000, env = process.env } = {}) {
  signal?.throwIfAborted();
  if (requestedProfile !== 'managed-cooperative' && requestedProfile !== 'managed-protected') throw new TypeError('requestedProfile is managed-cooperative or managed-protected');
  const requireHqLaunch = env.AGENT_BOT_SOULS_REQUIRE_HQ_LAUNCH === '1'
    || protectedStart !== undefined || cooperativeStart !== undefined;
  const hasProtectedLayout = protectedStateRoot !== undefined || protectedInputs !== undefined;
  let protectedLayout;
  let verifiedStart;
  if (requestedProfile === 'managed-protected' || hasProtectedLayout
    || protectedStart !== undefined || cooperativeStart !== undefined) {
    const refuseStart = (reason) => {
      log({ event: 'profile-refused', code: 'profile_insufficient', source: 'local', requested_profile: requestedProfile });
      throw new SoulUnavailable('unavailable', reason, 'profile_insufficient');
    };
    if (protectedStart !== undefined) {
      if (hasProtectedLayout || cooperativeStart !== undefined || requestedProfile !== 'managed-protected') refuseStart('protected fd 3 cannot be mixed with another profile or layout input');
      try { verifiedStart = checkProtectedStart(protectedStart, root); }
      catch (error) { refuseStart(error.message); }
      protectedLayout = readProtectedSoulLayout(root, verifiedStart.stateRoot, verifiedStart, requestedProfile);
      if (protectedLayout.soulId !== verifiedStart.soulId
        || protectedLayout.claimedDefinitionDigest !== verifiedStart.claimedDefinitionDigest) {
        refuseStart('the signed reservation does not map the measured Soul definition');
      }
    } else if (cooperativeStart !== undefined) {
      if (hasProtectedLayout || requestedProfile !== 'managed-cooperative') {
        refuseStart('cooperative fd 3 cannot be mixed with another profile or layout input');
      }
      try { verifiedStart = checkCooperativeStart(cooperativeStart, root); }
      catch (error) { refuseStart(error.message); }
      if (verifiedStart.adapterTransport === 'brokered-b') {
        try {
          const outcome = checkCooperativeBPublishOutcome(cooperativeStart, verifiedStart);
          if (verifiedStart.memberSetEnvelopeBytes) {
            verifiedStart = Object.freeze({ ...verifiedStart,
              bAuthoritySha256: outcome.bridge_assignment_sha256 });
          }
        }
        catch (error) { refuseStart(error.message); }
      }
      try { verifyCooperativeBParents(verifiedStart); }
      catch (error) { refuseStart(error.message); }
      if (verifiedStart.adapterTransport === 'brokered-b' && !memberPeerSupported()) {
        refuseStart('kernel member peer UID verification is unavailable for B');
      }
      if (verifiedStart.adapterTransport === 'brokered-b') {
        try { verifyCooperativeBMemberPath(verifiedStart); }
        catch (error) { refuseStart(error.message); }
      }
      protectedLayout = readProtectedSoulLayout(root, verifiedStart.stateRoot, verifiedStart, requestedProfile);
      if (protectedLayout.soulId !== verifiedStart.soulId
        || protectedLayout.claimedDefinitionDigest !== verifiedStart.claimedDefinitionDigest) {
        refuseStart('the signed cooperative reservation does not map the measured Soul definition');
      }
    } else if (hasProtectedLayout) {
      if (!requireHqLaunch || requestedProfile !== 'managed-protected') refuseStart('the installed projection requires an HQ-started managed-protected launch');
      if (protectedStateRoot === undefined) refuseStart('the HQ-started protected Soul has no separate runtime state directory');
      readProtectedSoulLayout(root, protectedStateRoot, protectedInputs, requestedProfile);
    }
    // A layout alone cannot authenticate Machine's one-use start. The fd 3
    // handoff is checked against its measured bytes here; HQ's protected
    // listener independently verifies the reservation and live finalization.
    if (!protectedLayout) refuseStart(PROTECTED_INPUTS_UNAVAILABLE);
  }
  const brokeredB = verifiedStart?.adapterTransport === 'brokered-b';
  const explicitEndpoints = admissionSocket !== undefined || brokerSocket !== undefined
    || memberSocket !== undefined || relaySocket !== undefined;
  if (brokeredB ? (hqHome !== undefined || brokerSocket !== undefined
    || [admissionSocket, memberSocket, relaySocket].some((path) => typeof path !== 'string' || !isAbsolute(path))
    || new Set([admissionSocket, memberSocket, relaySocket]).size !== 3)
    : (memberSocket !== undefined || relaySocket !== undefined
      || (explicitEndpoints && (hqHome !== undefined || typeof admissionSocket !== 'string' || !isAbsolute(admissionSocket)
        || typeof brokerSocket !== 'string' || !isAbsolute(brokerSocket) || admissionSocket === brokerSocket)))) {
    throw new TypeError(brokeredB
      ? 'provide distinct absolute admissionSocket, memberSocket and relaySocket without hqHome'
      : 'provide distinct absolute admissionSocket and brokerSocket without hqHome');
  }
  if (!explicitEndpoints && typeof hqHome !== 'string') throw new TypeError('provide hqHome or both explicit HQ sockets');
  if (protectedLayout && !explicitEndpoints) throw new TypeError('protected start requires both assigned HQ sockets');
  if (protectedLayout && (admissionSocket !== verifiedStart.admissionSocket
    || (brokeredB ? (memberSocket !== verifiedStart.memberSocket || relaySocket !== verifiedStart.relaySocket)
      : brokerSocket !== verifiedStart.brokerSocket))) {
    throw new SoulUnavailable('unavailable', 'the HQ sockets differ from the signed Machine assignment', 'profile_insufficient');
  }
  const admissionPath = explicitEndpoints ? admissionSocket : resolve(hqHome, 'admission.sock');
  const brokerPath = brokeredB ? undefined : (explicitEndpoints ? brokerSocket : resolve(hqHome, 'broker.sock'));
  const contracts = loadContracts({ directory: env.AGENT_BOT_SOUL_CONTRACTS });
  const soul = protectedLayout ? Object.freeze({
    root: protectedLayout.root,
    stateRoot: protectedLayout.stateRoot,
    soul_id: protectedLayout.soulId,
    definition_digest: protectedLayout.claimedDefinitionDigest,
    installation_id: protectedLayout.installationId,
    members: protectedLayout.members,
  }) : readSoul(root);
  const socketPath = brokeredB ? verifiedStart.memberSocket : join(soul.stateRoot, 'host', 'members.sock');
  if (Buffer.byteLength(socketPath) > MAX_SOCKET_PATH) throw new Error(`socket path ${socketPath} is longer than ${MAX_SOCKET_PATH} bytes; move the Soul to a shorter path`);
  let hq;
  let cooperativeAttach;
  if (cooperativeStart !== undefined) {
    hq = await connectCooperativeAdmission(verifiedStart,
      (path, attemptSignal) => connectHq(path, { contracts, signal: attemptSignal }), { signal });
    try { cooperativeAttach = await attachCooperative(hq, cooperativeStart, verifiedStart); }
    catch (error) { hq.destroy(); throw error; }
  }
  try {
    const previous = lstatSync(socketPath, { throwIfNoEntry: false });
    if (previous) {
      if (brokeredB) throw new Error(`signed B member socket path is occupied: ${socketPath}`);
      if (!previous.isSocket() || previous.uid !== process.geteuid()) throw new Error(`member socket path is occupied: ${socketPath}`);
      if (await live(socketPath)) throw new Error(`another entry point is running this Soul (${socketPath})`);
      const stale = lstatSync(socketPath, { throwIfNoEntry: false });
      if (stale) {
        if (!stale.isSocket() || stale.uid !== previous.uid || stale.dev !== previous.dev || stale.ino !== previous.ino) {
          throw new Error(`member socket changed before cleanup: ${socketPath}`);
        }
        unlinkSync(socketPath);
      }
    }
  } catch (error) { hq?.destroy(); throw error; }
  hq ??= await connectHq(admissionPath, { contracts, signal });
  const ladder = createLadder({ clock });
  const members = new Map(soul.members.map((spec) => [spec.member_id, {
    spec, route: 0, proc: null, rpc: null, sessionId: null, token: null, runtime: null,
    queue: new Set(), draining: false, briefed: false, turn: null, idleCrash: false, connections: new Set(), memberListener: null, launchId: null,
  }]));
  const lead = [...members.values()].find((m) => m.spec.role === LEAD);
  const events = [];
  let state = 'starting';
  let reason;
  let stateCode;
  let admission;
  let stopped = false;
  let stopping;
  let quarantining = false;
  const previousMemberCleanupFailures = new Set();
  let sharedMemberListener;
  let pendingSharedMemberListener;
  let sharedSignedEndpoint;
  let sharedReadyEnvelopeSha256;
  let timer;
  const current = (m) => m.spec.routes[m.route];
  const record = (event) => { events.push({ at: new Date(clock.now()).toISOString(), ...event }); log(event); };
  const unavailable = (next, why, code) => { state = next; reason = why; stateCode = code; return new SoulUnavailable(next, why, code); };

  const checkAdmissionFence = () => {
    signal?.throwIfAborted();
    if (stopped) throw new SoulUnavailable('stopped', 'the entry point stopped');
    if (stateCode === 'profile_insufficient') throw new SoulUnavailable(state, reason, stateCode);
  };
  const checkTurnLive = () => {
    if (stopped) throw new SoulUnavailable('stopped', 'the entry point stopped');
    if (state !== 'ready') throw new SoulUnavailable(state, reason ?? `the Soul is ${state}`, stateCode);
  };

  // Latch before stopping members so no new turn can begin during cleanup.
  async function refuseProfile(why, details, hqError) {
    const error = unavailable('unavailable', why, 'profile_insufficient');
    record({ event: 'profile-refused', code: error.code, ...details });
    const failures = await stopMembers();
    for (const { memberId, error: cleanupError } of failures) {
      previousMemberCleanupFailures.add(cleanupError);
      record({ event: 'member-stop-failed', member_id: memberId, error: String(cleanupError?.message ?? cleanupError) });
    }
    for (const m of members.values()) m.runtime = null;
    if (failures.length) hq.destroy();
    throw hqError ?? error;
  }

  // --- Admission (hq/v1) --------------------------------------------------

  let admitting = Promise.resolve();
  let protectedHelloSpent = false;
  let protectedHelloSha256;
  // One admission at a time; a second caller waits for the first.
  function admit() {
    const run = admitting.then(async () => {
      checkAdmissionFence();
      if (protectedLayout) {
        if (protectedHelloSpent) return refuseProfile('a protected restart needs a fresh Machine reservation and launcher', {
          source: 'local', requested_profile: requestedProfile,
        });
        // Even an unanswered Hello may have consumed the one-use start.
        protectedHelloSpent = true;
      }
      let decision;
      try {
        const hello = {
          contract: 'hq/v1',
          request_id: `req_${hex(8)}`,
          soul_id: soul.soul_id,
          definition_digest: soul.definition_digest,
          installation_id: soul.installation_id,
          supported_versions: { hq: [1], wire: [1] },
          supported_capabilities: [],
          requested_profile: requestedProfile,
          requested_roles: [...members.values()].map((m) => ({ role: m.spec.role, member_id: m.spec.member_id, adapter_id: current(m).adapter_id, adapter_version: current(m).adapter_version })),
        };
        if (protectedLayout) protectedHelloSha256 = 'sha256:' + createHash('sha256')
          .update(canonicalize(hello)).digest('hex');
        decision = await hq.request('Hello', hello);
      } catch (error) {
        checkAdmissionFence();
        if (!(error instanceof HqRefusal) || error.code !== 'profile_insufficient' || error.transport) throw error;
        admission = undefined;
        return refuseProfile(`HQ refused ${requestedProfile}: ${error.message}`, { source: 'hq', requested_profile: requestedProfile }, error);
      }
      checkAdmissionFence();
      if (decision.profile === 'managed-protected') {
        if (!protectedLayout || requestedProfile !== 'managed-protected') {
          admission = undefined;
          return refuseProfile(PROTECTED_INPUTS_UNAVAILABLE, {
            source: 'local', requested_profile: requestedProfile, granted_profile: decision.profile,
          });
        }
      }
      if (decision.profile !== requestedProfile) {
        admission = decision;
        return refuseProfile(`HQ granted ${decision.profile ?? 'no profile'} when ${requestedProfile} was requested`, {
          source: 'local', requested_profile: requestedProfile, granted_profile: decision.profile ?? null,
        });
      }
      if (protectedLayout?.memberSetAssignment) {
        verifyMemberSetAdmission(protectedLayout.memberSetAssignment, decision.admitted_runtimes);
      }
      for (const a of decision.admitted_runtimes) {
        const m = members.get(a.member_id);
        if (!m) throw new Error(`HQ admitted an unknown member ${a.member_id}`);
        m.runtime = { runtime_id: a.runtime_id, channel_binding: a.channel_binding, installation_epoch: decision.installation_epoch, lease_generation: decision.lease_generation, sequence: 0, ready: false };
        try { await hq.request('Equip', { runtime_id: a.runtime_id }); }
        finally { checkAdmissionFence(); }
      }
      admission = decision;
      record({ event: 'admitted', installation_epoch: decision.installation_epoch, lease_generation: decision.lease_generation, profile: decision.profile });
      // A live process can still be negotiating its first ACP session.
      for (const m of members.values()) if (m.proc && m.sessionId !== null) await ready(m);
    });
    admitting = run.catch(() => {});
    return run;
  }
  const renewal = (m, readiness) => ({
    contract: 'hq/v1',
    runtime_id: m.runtime.runtime_id,
    installation_epoch: m.runtime.installation_epoch,
    readiness_state: readiness,
    auth_state: 'authenticated',
    adapter_versions: { [current(m).adapter_id]: current(m).adapter_version },
    lease_generation: m.runtime.lease_generation,
    renewal_sequence: ++m.runtime.sequence,
    observed_health: m.proc ? 'healthy' : 'unreachable',
  });
  async function ready(m) {
    checkAdmissionFence();
    const runtime = m.runtime;
    try { await hq.request('Ready', renewal(m, 'cold')); }
    finally { checkAdmissionFence(); }
    if (m.runtime === runtime) runtime.ready = true;
  }
  // Renew every ready runtime's lease. A lease HQ no longer honours is
  // stale, not stopped: the Soul is admitted again.
  async function renew() {
    try {
      for (const m of members.values()) if (m.runtime?.ready) await hq.request('Lease', renewal(m, 'warm'));
    } catch (e) {
      if (!(e instanceof HqRefusal) || !['lease_expired', 'stale_epoch'].includes(e.code)) throw e;
      record({ event: 'lease-stale', code: e.code });
      await admit();
    }
  }

  // --- Members (ACP client) -----------------------------------------------

  async function sharedFallbackAllowed(m, signal) {
    const probe = await openMemberSession({ memberSocket: socketPath, memberToken: m.token, brokerSocket: brokerPath, contracts, signal });
    try {
      await probe.capture();
      return true;
    } catch (error) {
      if (error instanceof HqRefusal && error.code === 'caller_mismatch') return false;
      throw error;
    } finally {
      await probe.close().catch(() => {});
    }
  }

  async function prepareMember(m, setup) {
    const { signal } = setup.controller;
    const adapter = current(m);
    const home = join(soul.stateRoot, 'home', m.spec.member_id);
    m.token = hex(24);
    m.bridgeToken = null;
    m.bridgeUid = undefined;
    m.sessionId = null;
    m.briefed = false;
    const launchEnv = { AGENT_BOT_SOULS_MEMBER_TOKEN: m.token };
    const localBootstrap = {
      AGENT_BOT_SOULS_SOCKET: socketPath, AGENT_BOT_SOULS_MEMBER_TOKEN: m.token,
      AGENT_BOT_SOULS_MEMBER_ID: m.spec.member_id, AGENT_BOT_SOULS_ROLE: m.spec.role,
    };
    let proc;
    let sessionCwd = home;
    let launchId;
    let fallbackBroker;
    let isolatedEndpoint = false;
    try {
      // A signed bridge and member handoff are required before R may start
      // the stock adapter. The legacy HQ launch route does not provide B.
      if (cooperativeStart !== undefined) {
        throw new Error('cooperative B sidecar member launch is not yet available');
      }
      const twoMember = protectedLayout?.memberSetAssignment;
      let launch;
      try {
        launch = twoMember
          ? await hq.request('stage2a.member.attach.prepare', { runtime_id: m.runtime.runtime_id })
          : await hq.request('launch', { runtime_id: m.runtime.runtime_id,
            command: adapter.command, env: launchEnv });
      }
      catch (error) {
        if (!setup.cleanupError && error instanceof HqRefusal && error.transport) setup.cleanupError = error;
        throw error;
      } finally { setup.reserving = false; }
      launchId = typeof launch?.launch_id === 'string' && launch.launch_id.length ? launch.launch_id : undefined;
      try {
        if (!launchId) throw new Error('HQ launch did not return a launch ID');
        const assignedMember = protectedLayout?.memberSetAssignment
          && verifyMemberSetLaunch(protectedLayout.memberSetAssignment, m.spec.member_id, launch);
        if (assignedMember) {
          const attested = verifyMemberSetAttach(launch, verifiedStart, twoMember, admission,
            verifiedStart.machinePin, clock.now());
          if (sharedReadyEnvelopeSha256
            && sharedReadyEnvelopeSha256 !== attested.readyEnvelopeSha256) {
            throw new Error('HQ returned different aggregate Ready evidence for the two members');
          }
          sharedReadyEnvelopeSha256 = attested.readyEnvelopeSha256;
        }
        checkTurnLive();
        if (Object.keys(adapter.env).length) throw new Error(`adapter ${adapter.adapter_id} has environment variables that HQ account launch cannot accept`);
        if (typeof launch.cwd !== 'string' || !launch.cwd.startsWith('/')) throw new Error('HQ launch did not return an absolute working directory');
        // Machine's separate R/B start signs the exact member endpoint. A
        // missing fragment cannot turn that start into the legacy HQ-account
        // socket route, even if the rest of the launch reply is incomplete.
        const separateRunner = requestedProfile === 'managed-protected' || admission?.profile === 'managed-protected'
          || (requireHqLaunch && explicitEndpoints) || launch.runner_endpoint !== undefined
          || launch.member_bridge_token !== undefined || launch.bridge_ready_nonce !== undefined;
        if (separateRunner && launch.member_endpoint === undefined) throw new Error('HQ launch lacks its Machine-assigned member endpoint');
        if (protectedLayout && (launch.member_socket !== verifiedStart.memberEndpoint.member_socket
          || canonicalize(launch.member_endpoint) !== canonicalize(verifiedStart.memberEndpoint.member_endpoint))) {
          throw new Error('HQ launch member endpoint differs from the signed Machine reservation');
        }
        const endpoint = memberEndpoint(launch);
        isolatedEndpoint = launch.member_endpoint !== undefined;
        m.bridgeUid = endpoint.bridgeUid;
        if (isolatedEndpoint) {
          if (!/^[0-9a-f]{48}$/.test(launch.member_bridge_token ?? '')) throw new Error('HQ launch lacks a minted bridge member token');
          if (!/^[0-9a-f]{64}$/.test(launch.bridge_ready_nonce ?? '')) throw new Error('HQ launch lacks a bridge readiness nonce');
          if (!explicitEndpoints || launch.runner_endpoint?.socketPath !== admissionPath
            || launch.runner_endpoint?.peerUid !== process.geteuid()
            || launch.runner_endpoint?.directory !== dirname(admissionPath)) throw new Error('HQ launch lacks its assigned runner admission endpoint');
          if (assignedMember && [...members.values()].some((other) => other !== m
            && other.bridgeToken === launch.member_bridge_token)) {
            throw new Error('HQ reused a bridge member token across the signed member set');
          }
          m.bridgeToken = launch.member_bridge_token;
        }
        sessionCwd = launch.cwd;
        fallbackBroker = endpoint.broker;
        if (protectedLayout && members.size === 2) {
          // The signed B assignment has one member endpoint for the whole
          // Soul. The bridge's per-member token selects exactly one member
          // after the kernel peer UID check on that shared socket.
          const signedEndpoint = canonicalize(launch.member_endpoint);
          if (sharedSignedEndpoint && sharedSignedEndpoint !== signedEndpoint) {
            throw new Error('HQ launch changed the shared signed member endpoint');
          }
          if (!pendingSharedMemberListener && !sharedMemberListener) {
            sharedSignedEndpoint = signedEndpoint;
            pendingSharedMemberListener = listenMember(endpoint.path, undefined, endpoint.mode, endpoint)
              .then(async (listener) => {
                if (stopped) {
                  await closeListener(listener);
                  throw new Error('the Soul stopped while binding its shared member endpoint');
                }
                sharedMemberListener = listener;
                return listener;
              }).finally(() => { pendingSharedMemberListener = null; });
          }
          await pendingSharedMemberListener;
        } else {
          m.memberListener = await listenMember(endpoint.path, m, endpoint.mode, endpoint);
        }
        checkTurnLive();
        if (isolatedEndpoint) {
          // A separate control connection has a bounded lifetime. HQ must
          // verify live B-only HMAC bind and Machine start evidence before it
          // answers. The raw attach endpoint must recheck the same state.
          const controller = new AbortController();
          const abort = () => controller.abort(signal.reason);
          signal.addEventListener('abort', abort, { once: true });
          const timer = setTimeout(() => controller.abort(new Error('bridge readiness timed out')), 10_000);
          let readyClient;
          try {
            readyClient = await connectHq(admissionPath, { contracts, signal: controller.signal });
            const ready = await readyClient.request('launch.bridge_ready', {
              launch_id: launchId, attach: launch.attach, bridge_ready_nonce: launch.bridge_ready_nonce,
            });
            if (!ready || typeof ready !== 'object' || Array.isArray(ready)
              || Object.keys(ready).length !== 2 || ready.launch_id !== launchId || ready.bridge_ready !== true) {
              throw new Error('HQ did not verify a live bridge bind for this launch');
            }
          } finally {
            clearTimeout(timer);
            signal.removeEventListener('abort', abort);
            readyClient?.destroy();
          }
          checkTurnLive();
        }
        proc = await attachHq(admissionPath, { launch_id: launch.launch_id, attach: launch.attach },
          { contracts, signal, operation: assignedMember ? 'stage2a.member.attach' : 'launch.attach' });
        checkTurnLive();
      }
      catch (error) {
        const failures = [error];
        try { await closeMemberListener(m); } catch (cleanupError) { failures.push(cleanupError); }
        proc?.destroy();
        const reserved = launchId;
        launchId = undefined;
        if (!reserved) {
          // HQ's reservation has a deadline, but there is no usable ID to
          // confirm cleanup now. Close the connection to fence a retry.
          setup.cleanupError = error;
          if (!signal.aborted) hq.destroy();
        } else {
          try { await stopLaunch(reserved, m.spec.member_id); }
          catch (cleanupError) {
            failures.push(cleanupError);
            if (!signal.aborted) hq.destroy();
          }
          if (failures.length > 1) setup.cleanupError = cleanupFailure(failures.slice(1));
        }
        throw cleanupFailure(failures);
      }
    } catch (error) {
      if (!(error instanceof HqRefusal) || error.code !== 'host.launch_unavailable' || admission?.profile !== 'managed-cooperative' || isolatedEndpoint) {
        m.token = null; m.bridgeToken = null;
        throw error;
      }
      // A runner started by HQ may run in an account that holds HQ state.
      // It must never execute an adapter in that account when account-bound
      // HQ launch is unavailable. The dedicated runner socket itself is a
      // no-fallback marker even if a launcher omitted the environment flag;
      // externally started cooperative Souls retain their existing fallback.
      if (requireHqLaunch) {
        m.token = null;
        m.bridgeToken = null;
        record({ event: 'member-launch-fallback-refused', member_id: m.spec.member_id, code: error.code });
        throw unavailable('unavailable', `HQ launch is unavailable for HQ-started member ${m.spec.member_id}; local fallback is disabled`, error.code);
      }
      // A request-time refusal carries no account endpoint. Prove the
      // runtime is allowed on HQ's shared broker before starting locally;
      // account-bound runtimes must fail closed rather than start a process
      // that can never bind. Attach-time refusal has fallbackBroker from the
      // verified launch result and does not need this probe.
      checkTurnLive();
      if (!fallbackBroker && !(await sharedFallbackAllowed(m, signal))) {
        m.token = null; m.bridgeToken = null;
        record({ event: 'member-launch-fallback-refused', member_id: m.spec.member_id, code: 'caller_mismatch' });
        throw unavailable('unavailable', `HQ launch is unavailable for account-bound member ${m.spec.member_id}; local fallback cannot use its broker endpoint`);
      }
      checkTurnLive();
      mkdirSync(home, { recursive: true, mode: 0o700 });
      proc = spawn(adapter.command[0], adapter.command.slice(1), {
        cwd: home,
        stdio: ['pipe', 'pipe', 'pipe'],
        env: memberEnv(env, adapter.env, {
          ...localBootstrap, AGENT_BOT_SOUL_CONTRACTS: contracts.directory,
          ...(fallbackBroker ? { AGENT_BOT_SOULS_BROKER: fallbackBroker } : {}),
        }),
      });
      record({ event: 'member-launch-fallback', member_id: m.spec.member_id, code: error.code });
    }
    const input = launchId ? proc : proc.stdout;
    const output = launchId ? proc : proc.stdin;
    const rpc = rpcPeer({
      input,
      output,
      // The entry point decides no grant, so it never approves a permission
      // request on the owner's behalf.
      methods: { 'session/request_permission': async () => ({ outcome: { outcome: 'cancelled' } }) },
      onNotify: (method, params) => { if (method === 'session/update' && params?.sessionId === m.sessionId) m.turn?.update(params.update); },
    });
    // attachHq pauses after preserving any bytes that shared the attach reply;
    // resume only after ACP installed its data listener.
    if (launchId) proc.resume();
    m.proc = proc;
    m.launchId = launchId;
    m.rpc = rpc;
    m.exited = new Promise((resolve) => {
      let finished = false;
      const gone = (why) => {
        if (finished) return;
        finished = true;
        if (m.proc === proc) {
          m.proc = null;
          m.token = null; m.bridgeToken = null;
          closeMemberListener(m).catch((error) => record({ event: 'member-listener-close-failed', member_id: m.spec.member_id, error: String(error?.message ?? error) }));
          if ((!m.turn || m.turn.signal?.aborted) && !stopped) m.idleCrash = true;
        }
        rpc.close(why);
        resolve();
      };
      if (launchId) proc.once('close', () => gone('HQ launch connection closed'));
      else proc.once('exit', (code, signal) => gone(`member exited (${signal ?? code})`));
      proc.once('error', (e) => gone(`member did not start: ${e.message}`));
    });
    if (!launchId) {
      proc.stderr.setEncoding('utf8');
      proc.stderr.on('data', (text) => log({ event: 'member-stderr', member_id: m.spec.member_id, text }));
    }
    return { rpc, sessionCwd, adapter, launchId };
  }

  async function startMember(m) {
    const setup = { controller: new AbortController(), reserving: true };
    m.launchSetup = setup;
    let prepared;
    try { prepared = await (setup.done = prepareMember(m, setup)); }
    finally { m.launchSetup = null; }
    const { rpc, sessionCwd, adapter, launchId } = prepared;
    try {
      checkTurnLive();
      const init = await rpc.request('initialize', { protocolVersion: ACP_PROTOCOL_VERSION, clientCapabilities: { fs: { readTextFile: false, writeTextFile: false }, terminal: false } });
      checkTurnLive();
      if (init?.protocolVersion !== ACP_PROTOCOL_VERSION) throw new RpcError(-32603, `adapter speaks ACP ${init?.protocolVersion}, not ${ACP_PROTOCOL_VERSION}`, { closed: true });
      const session = await rpc.request('session/new', { cwd: sessionCwd, mcpServers: [] });
      checkTurnLive();
      if (typeof session?.sessionId !== 'string' || session.sessionId.length === 0) {
        throw new RpcError(-32603, 'adapter did not return a session ID', { closed: true });
      }
      m.sessionId = session.sessionId;
      m.idleCrash = false;
      await ready(m);
      checkTurnLive();
      record({ event: 'member-started', member_id: m.spec.member_id, adapter_id: adapter.adapter_id, launch: launchId ? 'hq' : 'local' });
    } catch (error) {
      try { await stopMember(m); }
      catch (cleanupError) { throw cleanupFailure([error, cleanupError]); }
      throw error;
    }
  }

  async function stopLaunch(launchId, memberId) {
    let timer;
    let result;
    try {
      const deadline = new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`HQ launch ${launchId} of member ${memberId} is unconfirmed: stop reply timed out`)), STOP_CONFIRM_MS);
      });
      result = await Promise.race([hq.request('launch.stop', { launch_id: launchId }), deadline]);
    } finally { clearTimeout(timer); }
    if (result?.launch_id === launchId && result.state === 'exited') return;
    const reason = result?.launch_id === launchId && result.state === 'uncontained' ? 'uncontained' : 'unconfirmed';
    throw new Error(`HQ launch ${launchId} of member ${memberId} is ${reason} after stop`);
  }

  function stopMember(m, keepAdmission = false, setup = m.launchSetup) {
    m.stopping ??= cleanupMember(m, keepAdmission, setup).finally(() => { m.stopping = null; });
    return m.stopping;
  }

  async function cleanupMember(m, keepAdmission, setup) {
    const failures = [];
    if (setup) {
      setup.controller.abort();
      // Setup ends before ACP initialization, which can wait on this
      // transport. A pending attach has its own cancelable socket, but to
      // stop an outstanding reservation we first need HQ to return its ID.
      const deadline = setup.reserving ? setTimeout(() => {
        setup.cleanupError = new Error(`HQ launch reservation for member ${m.spec.member_id} is unconfirmed after the shutdown deadline`);
        hq.destroy();
      }, RESERVATION_DRAIN_MS) : undefined;
      try { await setup.done.catch(() => {}); }
      finally { clearTimeout(deadline); }
      if (setup.cleanupError) failures.push(setup.cleanupError);
    }
    m.token = null; m.bridgeToken = null;
    for (const c of m.connections) c.destroy();
    m.connections.clear();
    const proc = m.proc;
    const exited = m.exited;
    const launchId = m.launchId;
    m.proc = null;
    m.launchId = null;
    try { await closeMemberListener(m); } catch (error) { failures.push(error); }
    if (launchId) {
      try { await stopLaunch(launchId, m.spec.member_id); }
      catch (error) {
        failures.push(error);
        if (!keepAdmission && !stopped && state !== 'quarantined') hq.destroy();
      }
      finally { if (proc) { proc.destroy(); await exited; } }
    } else if (proc) {
      proc.kill('SIGTERM');
      const killer = setTimeout(() => proc.kill('SIGKILL'), 2000);
      await exited;
      clearTimeout(killer);
    }
    if (failures.length) throw cleanupFailure(failures);
  }

  let memberCleanup;
  function stopMembers() {
    memberCleanup ??= (async () => {
      const pending = [];
      const known = [];
      for (const m of members.values()) {
        const setup = m.launchSetup;
        setup?.controller.abort();
        (setup?.reserving ? pending : known).push({ m, setup });
      }
      const failures = [];
      // Stop known launches before a missing reservation reply can force
      // closure of their shared owner connection.
      for (const { m, setup } of [...known, ...pending]) {
        try { await stopMember(m, true, setup); }
        catch (error) { failures.push({ memberId: m.spec.member_id, error }); }
      }
      return failures;
    })().finally(() => { memberCleanup = null; });
    return memberCleanup;
  }

  // What a returning lead reads before it continues (0.4 §9).
  function brief(m) {
    const notes = handoffs(soul.stateRoot, contracts);
    return {
      type: 'text',
      text: [
        `Brief from the entry point. You are ${m.spec.member_id}, the lead of ${soul.soul_id}.`,
        'Before continuing, read your waiting directives and your open tasks from HQ, and reconcile anything whose outcome you do not know.',
        notes.length ? `Handoff notes, oldest first:\n${JSON.stringify(notes, null, 2)}` : 'There are no handoff notes.',
      ].join('\n'),
    };
  }

  // Take the rung of the recovery ladder for this failure. Returns when the
  // turn may be tried again and throws when it may not.
  async function recover(m, failureClass) {
    let labels;
    try { labels = restrictions(soul.stateRoot, contracts); }
    catch (error) {
      if (error instanceof NoteError) throw unavailable('needs-owner', 'handoff restrictions cannot be read; no fail-over route can receive the context');
      throw error;
    }
    const action = ladder.next(failureClass, { memberId: m.spec.member_id, routes: m.spec.routes, route: m.route, restrictions: labels });
    record({ event: 'recovery', member_id: m.spec.member_id, failure: failureClass, ...action });
    switch (action.action) {
      case 'restart':
        await stopMember(m);
        await delay(action.delayMs);
        if (stopped) throw new SoulUnavailable('stopped', 'the entry point stopped');
        await admit();
        return;
      case 're-equip':
        try {
          await hq.request('Equip', { runtime_id: m.runtime.runtime_id });
        } catch (e) {
          if (e instanceof HqRefusal) throw unavailable('needs-owner', `HQ did not re-equip ${m.spec.member_id}: ${e.code}`);
          throw e;
        }
        return;
      case 'fail-over':
        await stopMember(m);
        m.route = action.route;
        await admit();
        return;
      case 'quarantine': {
        const error = unavailable('quarantined', 'five member crashes within an hour; the owner reviews and releases the Soul');
        quarantining = true;
        try {
          const failures = (await stopMembers()).map(({ error }) => error);
          for (const failure of failures) previousMemberCleanupFailures.add(failure);
          if (failures.length) {
            hq.destroy();
            throw cleanupFailure([error, ...failures]);
          }
        } finally { quarantining = false; }
        throw error;
      }
      case 'wait':
        throw unavailable('waiting', action.reason);
      case 'owner-decision':
        throw unavailable('needs-owner', action.reason);
      case 'pause':
      case 'unavailable':
        throw unavailable('unavailable', action.reason);
      default:
        throw new Error(`no recovery for ${failureClass}`);
    }
  }

  const failureOf = (e) => {
    if (e instanceof RpcError) return e.data?.closed ? { kind: 'exit' } : { kind: 'rpc', code: e.code, data: e.data };
    return undefined;
  };

  const cancelledTurn = (m) => ({ member_id: m.spec.member_id, stop_reason: 'cancelled', text: '' });

  async function attempt(m, blocks, onChunk, signal) {
    let priorFailure;
    const cancelled = () => {
      if (priorFailure) throw priorFailure;
      return cancelledTurn(m);
    };
    for (;;) {
      if (stopped) throw new SoulUnavailable('stopped', 'the entry point stopped');
      if (state !== 'ready') throw new SoulUnavailable(state, reason ?? `the Soul is ${state}`, stateCode);
      if (ladder.quarantined) throw new SoulUnavailable('quarantined', reason ?? 'quarantined');
      if (signal?.aborted) return cancelled();
      let failed;
      try {
        if (m.idleCrash) { m.idleCrash = false; failed = 'crash'; throw new RpcError(-32603, 'member exited between turns', { closed: true }); }
        if (!m.proc) await startMember(m);
        checkTurnLive();
        if (signal?.aborted) return cancelled();
        let text = '';
        m.turn = { signal, update(u) { if (!stopped && state === 'ready' && u?.sessionUpdate === 'agent_message_chunk' && u.content?.type === 'text') { text += u.content.text; onChunk?.(u.content.text); } } };
        const prompt = m === lead && !m.briefed ? [brief(m), ...blocks] : blocks;
        const { rpc, sessionId } = m;
        const cancel = () => rpc.notify('session/cancel', { sessionId });
        signal?.addEventListener('abort', cancel, { once: true });
        let result;
        try { result = await rpc.request('session/prompt', { sessionId, prompt }); }
        catch (error) {
          // ACP also permits a typed cancellation error. An unrelated
          // failure or an earlier uncertain attempt still needs reporting.
          if (!signal?.aborted) throw error;
          if (failureOf(error)?.kind === 'exit') m.idleCrash = true;
          if (!(error instanceof RpcError) || error.code !== REQUEST_CANCELLED) throw error;
          if (priorFailure) throw priorFailure;
          result = { stopReason: 'cancelled' };
        }
        finally { signal?.removeEventListener('abort', cancel); }
        checkTurnLive();
        m.briefed = true;
        ladder.healthy(m.spec.member_id);
        return { member_id: m.spec.member_id, stop_reason: result?.stopReason ?? 'end_turn', text };
      } catch (e) {
        if (stopped || stateCode === 'profile_insufficient') checkTurnLive();
        if (signal?.aborted) throw e;
        failed = failed ?? classify(failureOf(e));
        if (!failed) throw e;
        priorFailure = e;
      } finally {
        m.turn = null;
      }
      if (state !== 'ready') throw new SoulUnavailable(state, reason ?? `the Soul is ${state}`, stateCode);
      await recover(m, failed);
    }
  }

  // One turn at a time per member. A queued cancellation removes its entry
  // immediately, even if the adapter is still handling the previous turn.
  async function drainTurns(m) {
    m.draining = true;
    while (m.queue.size) {
      const next = m.queue.values().next().value;
      m.queue.delete(next);
      next.signal?.removeEventListener('abort', next.cancel);
      try { next.resolve(await attempt(m, next.blocks, next.onChunk, next.signal)); }
      catch (error) { next.reject(error); }
    }
    m.draining = false;
  }

  function turn(m, blocks, onChunk, signal) {
    if (signal?.aborted) return Promise.resolve(cancelledTurn(m));
    return new Promise((resolve, reject) => {
      const cancel = () => {
        m.queue.delete(queued);
        signal.removeEventListener('abort', cancel);
        resolve(cancelledTurn(m));
      };
      const queued = { blocks, onChunk, signal, cancel, resolve, reject };
      m.queue.add(queued);
      signal?.addEventListener('abort', cancel, { once: true });
      if (!m.draining) void drainTurns(m);
    });
  }

  // --- The member socket ----------------------------------------------------

  const memberOps = {
    runtime: (m, _payload, peerUid) => {
      if (protectedLayout && members.size === 2 && state !== 'ready') {
        refuse('souls.unknown_member', 'the two-member Soul is not finalized');
      }
      if (m.bridgeUid !== undefined && peerUid !== m.bridgeUid) refuse('souls.unknown_member', 'only the assigned bridge may receive runtime bootstrap');
      return {
        soul_id: soul.soul_id, member_id: m.spec.member_id, role: m.spec.role,
        runtime_id: m.runtime.runtime_id,
        installation_epoch: m.runtime.installation_epoch, lease_generation: m.runtime.lease_generation,
        ...(m.bridgeUid === undefined ? { broker: brokerPath, channel_binding: m.runtime.channel_binding } : {}),
      };
    },
    // Role routing: the lead hands work to the member with a role.
    async route(m, payload) {
      if (m !== lead) refuse('souls.not_lead', 'only the lead routes work');
      if (!payload || typeof payload.role !== 'string' || typeof payload.prompt !== 'string' || payload.prompt.length < 1 || payload.prompt.length > MAX_PROMPT) refuse('souls.invalid_request', 'route takes { role, prompt, task_id? }');
      const target = [...members.values()].find((x) => x.spec.role === payload.role && x !== m);
      if (!target) refuse('souls.unknown_role', `no other member has the role ${payload.role}`);
      record({ event: 'routed', from: m.spec.member_id, to: target.spec.member_id, role: payload.role, ...(typeof payload.task_id === 'string' ? { task_id: payload.task_id } : {}) });
      try {
        return await turn(target, [{ type: 'text', text: payload.prompt }]);
      } catch (e) {
        if (e instanceof SoulUnavailable) refuse('souls.member_unavailable', e.message);
        refuse('souls.turn_failed', String(e?.message ?? e));
      }
      return undefined;
    },
    note(m, payload) {
      try {
        const note = writeNote(soul.stateRoot, payload, { note_id: `note_${hex(8)}`, member_id: m.spec.member_id, runtime_id: m.runtime.runtime_id, timestamp: new Date(clock.now()).toISOString() }, contracts);
        return { note_id: note.note_id };
      } catch (e) {
        if (e instanceof NoteError) refuse('souls.invalid_request', e.message);
        throw e;
      }
    },
    handoffs: () => ({ notes: handoffs(soul.stateRoot, contracts) }),
  };

  function memberConnection(socket, expected, listener, peerUid) {
    let member;
    let unauthenticated = false;
    let helloTimer;
    const authenticated = () => {
      if (!unauthenticated) return;
      unauthenticated = false;
      listener.unauthenticated -= 1;
      clearTimeout(helloTimer);
    };
    socket.on('error', () => {});
    socket.on('close', () => {
      authenticated();
      listener.sockets.delete(socket);
      member?.connections.delete(socket);
    });
    if (listener.unauthenticated >= MAX_UNAUTHENTICATED) { socket.destroy(); return; }
    listener.sockets.add(socket);
    listener.unauthenticated += 1;
    unauthenticated = true;
    helloTimer = setTimeout(() => socket.destroy(), MEMBER_HELLO_MS);
    helloTimer.unref();
    const reply = (id, fn) => Promise.resolve().then(fn).then(
      (result) => writeLine(socket, { id, ok: true, result: result === undefined ? null : result }),
      (e) => writeLine(socket, { id, ok: false, host_refusal: { code: e instanceof MemberRefusal ? e.code : 'souls.internal', explanation: String(e?.message ?? e) } }),
    );
    readLines(socket, (line) => {
      let req;
      try { req = parseStrict(line); } catch { socket.destroy(); return; }
      if (!req || typeof req !== 'object' || typeof req.op !== 'string') { socket.destroy(); return; }
      reply(req.id, () => {
        if (req.op === 'hello') {
          if (protectedLayout && members.size === 2 && state !== 'ready') {
            refuse('souls.unknown_member', 'the two-member Soul is not finalized');
          }
          const token = req.payload?.token;
          const candidates = expected ? [expected] : [...members.values()];
          const found = typeof token === 'string' ? candidates.find((x) => {
            const expectedToken = x.bridgeUid !== undefined && peerUid === x.bridgeUid ? x.bridgeToken : x.token;
            return expectedToken && sameToken(expectedToken, token);
          }) : undefined;
          if (!found) refuse('souls.unknown_member', 'the token is not a running member\'s');
          member = found;
          found.connections.add(socket);
          authenticated();
          return { soul_id: soul.soul_id, member_id: found.spec.member_id, role: found.spec.role };
        }
        if (!member) refuse('souls.unknown_member', 'a member says hello with its token first');
        if (member.bridgeUid !== undefined && peerUid === member.bridgeUid && req.op !== 'runtime') refuse('souls.unknown_op', 'the bridge may request runtime bootstrap only');
        if (!Object.hasOwn(memberOps, req.op)) refuse('souls.unknown_op', `no operation ${req.op}`);
        return memberOps[req.op](member, req.payload, peerUid);
      });
    }, () => socket.destroy());
  }

  async function listenMember(path, expected, mode, endpoint) {
    if (lstatSync(path, { throwIfNoEntry: false })) throw new Error(`member socket ${path} already exists`);
    if (endpoint?.directory) {
      const parent = lstatSync(endpoint.directory);
      if (!parent.isDirectory() || parent.dev !== endpoint.dev || parent.ino !== endpoint.ino || parent.uid !== endpoint.ownerUid || parent.gid !== endpoint.groupGid || (parent.mode & 0o7777) !== 0o2750) throw new Error(`member socket ${path} parent changed before bind`);
    }
    const listener = { path, server: null, sockets: new Set(), peerChecks: new Set(), peerFailures: new Set(),
      unauthenticated: 0, pendingPeers: 0, closing: false, dev: null, ino: null };
    const server = createServer({ pauseOnConnect: Boolean(endpoint?.peerUids) }, (socket) => {
      if (listener.closing) { socket.destroy(); return; }
      if (!endpoint?.peerUids) { memberConnection(socket, expected, listener); return; }
      socket.on('error', () => {});
      if (listener.pendingPeers + listener.unauthenticated >= MAX_UNAUTHENTICATED) { socket.destroy(); return; }
      listener.pendingPeers += 1;
      listener.sockets.add(socket);
      socket.once('close', () => listener.sockets.delete(socket));
      const check = authenticateMemberPeer(socket, endpoint.peerUids);
      listener.peerChecks.add(check);
      void check.done.then((uid) => {
        listener.peerChecks.delete(check);
        listener.pendingPeers -= 1;
        if (uid === null || listener.closing || socket.destroyed || !server.listening) { socket.destroy(); return; }
        memberConnection(socket, expected, listener, uid);
        socket.resume();
      }, (error) => {
        listener.peerFailures.add(error);
        listener.closing = true;
        for (const peerSocket of listener.sockets) peerSocket.destroy();
        listener.peerChecks.delete(check);
        listener.pendingPeers -= 1;
        socket.destroy();
      });
    });
    listener.server = server;
    try {
      await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(path, () => { server.off('error', reject); resolve(); });
      });
      const bound = lstatSync(path);
      if (!bound.isSocket() || bound.uid !== process.geteuid()) throw new Error(`member socket ${path} has an unexpected owner or type`);
      listener.dev = bound.dev;
      listener.ino = bound.ino;
      chmodSync(path, mode);
      const st = lstatSync(path);
      if (!st.isSocket() || (st.mode & 0o777) !== mode) throw new Error(`member socket ${path} was not created with mode ${mode.toString(8)}`);
      if (mode === 0o660 && st.gid !== lstatSync(dirname(path)).gid) throw new Error(`member socket ${path} did not inherit the harness group`);
      if (endpoint?.directory) {
        const parent = lstatSync(endpoint.directory);
        if (!parent.isDirectory() || parent.dev !== endpoint.dev || parent.ino !== endpoint.ino || parent.uid !== endpoint.ownerUid || parent.gid !== endpoint.groupGid || (parent.mode & 0o7777) !== 0o2750) throw new Error(`member socket ${path} parent changed during bind`);
      }
      if (st.dev !== bound.dev || st.ino !== bound.ino) throw new Error(`member socket ${path} changed during setup`);
      return listener;
    } catch (error) {
      await closeListener(listener);
      throw error;
    }
  }

  async function closeMemberListener(m) {
    const listener = m.memberListener;
    m.memberListener = null;
    await closeListener(listener);
  }

  if (!protectedLayout) {
    try { sharedMemberListener = await listenMember(socketPath, undefined, 0o600); }
    catch (error) {
      await hq.close().catch(() => {});
      throw error;
    }
  }

  // --- Start ----------------------------------------------------------------

  function stop() {
    if (stopping) return stopping;
    stopped = true;
    state = 'stopped';
    stateCode = undefined;
    clearInterval(timer);
    for (const m of members.values()) m.runtime = null;
    stopping = (async () => {
      const memberFailures = await stopMembers();
      const failures = [...new Set([...memberFailures.map(({ error }) => error), ...previousMemberCleanupFailures])];
      if (pendingSharedMemberListener) {
        try { await pendingSharedMemberListener; } catch (error) { failures.push(error); }
      }
      try { await closeListener(sharedMemberListener); } catch (error) { failures.push(error); }
      if (failures.length) {
        hq.destroy();
        throw cleanupFailure(failures);
      }
      await hq.close().catch(() => {});
    })();
    return stopping;
  }

  try {
    await admit();
  } catch (error) {
    try { await stop(); }
    catch (cleanupError) { throw cleanupFailure([error, cleanupError]); }
    throw error;
  }
  if (renewEveryMs > 0) {
    timer = setInterval(() => { renew().catch((e) => record({ event: 'renew-failed', error: String(e?.message ?? e) })); }, renewEveryMs);
    timer.unref();
  }
  state = 'ready';

  return {
    soul_id: soul.soul_id,
    ...(cooperativeAttach ? { cooperativeAcp: Object.freeze({
      path: admissionPath, acpTicketBase64url: cooperativeAttach.acp_ticket_base64url,
      reservationSha256: verifiedStart.reservationSha256,
      startId: verifiedStart.startId, launchId: verifiedStart.launchId,
    }) } : {}),
    ...(protectedLayout ? { protectedAdmission: Object.freeze({
      helloPayloadSha256: protectedHelloSha256,
      decisionId: admission.decision_id,
      installationEpoch: admission.installation_epoch,
      admittedRuntimes: Object.freeze(admission.admitted_runtimes.map((runtime) => Object.freeze({
        member_id: runtime.member_id, runtime_id: runtime.runtime_id,
        profile_in_force: admission.profile,
      })).sort((a, b) => a.member_id < b.member_id ? -1 : a.member_id > b.member_id ? 1 : 0)),
    }) } : {}),
    // The owner's conversation: one turn of the lead. `onChunk(text)`
    // receives the lead's reply as it arrives.
    async prompt(text, onChunk, { signal } = {}) {
      if (typeof text !== 'string' || text.length < 1 || text.length > MAX_PROMPT) throw new RangeError(`a prompt is 1 to ${MAX_PROMPT} characters`);
      return turn(lead, [{ type: 'text', text }], onChunk, signal);
    },
    cancel() { if (lead.proc && lead.sessionId) lead.rpc.notify('session/cancel', { sessionId: lead.sessionId }); },
    renew,
    // The owner reviewed a quarantined Soul and releases it.
    release() {
      if (state !== 'quarantined' || !ladder.quarantined) throw new SoulUnavailable(state, 'only a quarantined Soul can be released', stateCode);
      if (quarantining) throw new SoulUnavailable(state, 'quarantine member cleanup is still in progress');
      if (previousMemberCleanupFailures.size) throw cleanupFailure([...previousMemberCleanupFailures]);
      ladder.release(); state = 'ready'; reason = undefined; record({ event: 'released' });
    },
    status: () => ({
      state,
      ...(reason ? { reason } : {}),
      ...(stateCode ? { code: stateCode } : {}),
      soul_id: soul.soul_id,
      installation_id: soul.installation_id,
      ...(admission ? { installation_epoch: admission.installation_epoch, lease_generation: admission.lease_generation,
        profile: admission.profile, warnings: admission.warnings ?? [] } : {}),
      members: [...members.values()].map((m) => ({ member_id: m.spec.member_id, role: m.spec.role, adapter_id: current(m).adapter_id, running: Boolean(m.proc), runtime_id: m.runtime?.runtime_id })),
    }),
    events: () => [...events],
    stop,
  };
}
