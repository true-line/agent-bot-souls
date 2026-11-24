import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter, once } from 'node:events';
import { chmodSync, mkdirSync, mkdtempSync, realpathSync, rmSync, statSync, symlinkSync } from 'node:fs';
import { connect, createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { closeListener, memberEndpoint } from '../lib/entry-point.mjs';
import { authenticateMemberPeer, createMemberPeerAuthenticator, memberPeerSupported } from '../lib/member-peer.mjs';

test('a separately provisioned member socket binds the runner-owned bridge-group directory', () => {
  const root = mkdtempSync(join(tmpdir(), 'soul-member-endpoint-'));
  const directory = join(realpathSync(root), 'start');
  try {
    mkdirSync(directory);
    chmodSync(directory, 0o2750);
    const group = statSync(directory).gid;
    const launch = {
      member_socket: join(directory, 'member.sock'),
      member_endpoint: {
        directory, owner_uid: process.geteuid(), group_gid: group,
        dir_mode: 0o2750, socket_mode: 0o660,
        peer_uids: [process.geteuid(), process.geteuid() + 1],
      },
    };
    assert.equal(memberEndpoint(launch).broker, undefined, 'the runner receives no bridge broker path');
    assert.equal(memberEndpoint(launch).path, join(directory, 'member.sock'));
    assert.equal(memberEndpoint(launch).bridgeUid, process.geteuid() + 1);
    assert.throws(() => memberEndpoint({ ...launch, member_endpoint: { ...launch.member_endpoint, broker_socket: join(root, 'broker.sock') } }), /unsupported field/);
    assert.throws(() => memberEndpoint({ ...launch, member_endpoint: { ...launch.member_endpoint, owner_uid: process.geteuid() + 1 } }), /invalid runner/);
    assert.throws(() => memberEndpoint({ ...launch, member_endpoint: { ...launch.member_endpoint, peer_uids: [process.geteuid(), process.geteuid()] } }), /peer UIDs/);
    assert.throws(() => memberEndpoint({ ...launch, member_endpoint: { ...launch.member_endpoint, group_gid: group + 1 } }), /unexpected owner/);
    assert.throws(() => memberEndpoint({ ...launch, member_endpoint: { ...launch.member_endpoint, directory: root } }), /does not bind/);
    chmodSync(directory, 0o750);
    assert.throws(() => memberEndpoint(launch), /unexpected owner/);
    rmSync(directory, { recursive: true });
    symlinkSync(root, directory);
    assert.throws(() => memberEndpoint(launch), /unexpected owner/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('legacy account endpoint keeps the broker beside its member socket', () => {
  const launch = { member_socket: '/tmp/harness/member-abcd.sock' };
  assert.equal(memberEndpoint(launch).broker, '/tmp/harness/broker.sock');
});

test('cooperative B endpoint retains the signed parent identity and bridge peer', (t) => {
  const root = mkdtempSync(join(tmpdir(), 'scm-'));
  const directory = join(realpathSync(root), 's');
  try {
    mkdirSync(directory);
    chmodSync(directory, 0o2750);
    const st = statSync(directory, { bigint: true });
    if (Number(st.gid) === process.geteuid()) {
      t.skip('the test account has no distinct directory group to model B');
      return;
    }
    const member_socket = join(directory, 'm.sock');
    const member_endpoint = {
      directory, socket_path: member_socket, owner_uid: process.geteuid(),
      group_gid: Number(st.gid), dir_mode: 0o2750, socket_mode: 0o660,
      expected_peer_uid: Number(st.gid), parent_device: st.dev.toString(),
      parent_inode: st.ino.toString(), parent_birthtime_ns: st.birthtimeNs.toString(),
    };
    const launch = { member_socket, member_endpoint };
    assert.equal(memberEndpoint(launch).bridgeUid, Number(st.gid));
    assert.deepEqual(memberEndpoint(launch).peerUids,
      [process.geteuid(), Number(st.gid)]);
    assert.throws(() => memberEndpoint({ ...launch, member_endpoint: {
      ...member_endpoint, parent_inode: String(st.ino + 1n) } }), /parent changed/);
    assert.throws(() => memberEndpoint({ ...launch, member_endpoint: {
      ...member_endpoint, expected_peer_uid: process.geteuid() } }), /differs from signed/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('the member peer helper reads kernel UID from the accepted stream', async () => {
  assert.equal(memberPeerSupported(), true);
  const root = mkdtempSync(join(tmpdir(), 'soul-peer-'));
  const path = join(root, 'member.sock');
  let client;
  let server;
  const result = new Promise((resolve, reject) => {
    server = createServer({ pauseOnConnect: true }, async (socket) => {
      try {
        assert.equal(await authenticateMemberPeer(socket, [process.geteuid() + 1]).done, null);
        assert.equal(await authenticateMemberPeer(socket, [process.geteuid()]).done, process.geteuid());
        const pending = authenticateMemberPeer(socket, [process.geteuid()]);
        pending.abort();
        assert.equal(await pending.done, null, 'abort joins the helper before socket cleanup');
        resolve();
      } catch (error) { reject(error); }
      finally { socket.destroy(); }
    });
  });
  try {
    server.listen(path);
    await once(server, 'listening');
    client = connect(path);
    await result;
  } finally {
    client?.destroy();
    await new Promise((resolve) => server?.close(resolve));
    rmSync(root, { recursive: true, force: true });
  }
});

const fakePeerChild = () => {
  const child = new EventEmitter();
  child.stdout = new EventEmitter();
  child.kill = () => {
    queueMicrotask(() => child.emit('error', new Error('kill failed')));
    return false;
  };
  return child;
};

test('listener cleanup waits for child close after a kill error before retiring its socket', async () => {
  const child = fakePeerChild();
  const uid = process.geteuid();
  const authenticate = createMemberPeerAuthenticator({ spawnChild: () => child, closeTimeoutMs: 1_000 });
  const check = authenticate({}, [uid]);
  child.stdout.emit('data', `${uid}\n`);
  let peerResult = 'pending';
  void check.done.then((value) => { peerResult = value; });
  let socketDestroyed = false;
  let serverClosed = false;
  const listener = {
    sockets: new Set([{ destroy() { socketDestroyed = true; } }]),
    peerChecks: new Set([check]), peerFailures: new Set(), ino: null,
    server: { close(callback) { serverClosed = true; callback(); } },
  };
  const closing = closeListener(listener);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(socketDestroyed, true);
  assert.equal(peerResult, 'pending', 'error is not proof that fd 3 closed');
  assert.equal(serverClosed, false, 'listener is not retired while helper may hold fd 3');
  child.emit('close', 0);
  await closing;
  assert.equal(peerResult, null, 'a failed kill never authenticates a printed UID');
  assert.equal(serverClosed, true);
});

test('listener cleanup fails closed when a peer helper never confirms close', async () => {
  const child = fakePeerChild();
  const authenticate = createMemberPeerAuthenticator({ spawnChild: () => child, closeTimeoutMs: 20 });
  const check = authenticate({}, [process.geteuid()]);
  let serverClosed = false;
  const listener = { sockets: new Set(), peerChecks: new Set([check]), peerFailures: new Set(), ino: null,
    server: { close(callback) { serverClosed = true; callback(); } } };
  await assert.rejects(closeListener(listener), /member peer helper did not close/);
  assert.equal(listener.closing, true);
  assert.equal(serverClosed, false, 'uncertain fd custody must not retire the endpoint');
});

test('listener cleanup remembers an earlier peer close failure after its check leaves the pending set', async () => {
  const error = new Error('peer close unconfirmed');
  let serverClosed = false;
  const listener = { sockets: new Set(), peerChecks: new Set(), peerFailures: new Set([error]), ino: null,
    server: { close(callback) { serverClosed = true; callback(); } } };
  await assert.rejects(closeListener(listener), (caught) => caught === error);
  assert.equal(serverClosed, false);
});

test('a synchronous peer helper spawn refusal has no inherited descriptor', async () => {
  const authenticate = createMemberPeerAuthenticator({ spawnChild() { throw new Error('spawn refused'); } });
  assert.equal(await authenticate({}, [process.geteuid()]).done, null);
});
