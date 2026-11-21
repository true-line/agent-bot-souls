import { test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { chmodSync, mkdirSync, mkdtempSync, realpathSync, rmSync, statSync, symlinkSync } from 'node:fs';
import { connect, createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { memberEndpoint } from '../lib/entry-point.mjs';
import { authenticateMemberPeer, memberPeerSupported } from '../lib/member-peer.mjs';

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
