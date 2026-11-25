import assert from 'node:assert/strict';
import { chmodSync, lstatSync, mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { requestProtectedLive } from '../lib/protected-live-client.mjs';

async function withHqSocket(t, respond, check) {
  const parent = mkdtempSync(join(tmpdir(), 'souls-live-hq-'));
  const directory = join(parent, 'r');
  const socketPath = join(directory, 'live.sock');
  const { mkdirSync } = await import('node:fs');
  mkdirSync(directory, { mode: 0o2750 });
  chmodSync(directory, 0o2750);
  const server = createServer((socket) => {
    let raw = '';
    socket.on('data', (chunk) => {
      raw += chunk.toString('utf8');
      if (!raw.endsWith('\n')) return;
      respond(JSON.parse(raw), socket);
    });
  });
  try {
    await new Promise((resolve) => server.listen(socketPath, resolve));
    chmodSync(socketPath, 0o660);
    const dir = lstatSync(directory);
    const st = lstatSync(socketPath);
    const start = { installationId: 'inst_fixture', startId: 'st_' + '1'.repeat(24),
      launchId: 'ln_' + '2'.repeat(24), reservationSha256: `sha256:${'3'.repeat(64)}`,
      admissionSocket: socketPath,
      admissionEndpoint: { directory, socket_path: socketPath, owner_uid: st.uid,
        group_gid: dir.gid, dir_mode: 0o2750, socket_mode: 0o660, peer_uids: [process.geteuid()] } };
    await check(start);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    rmSync(parent, { recursive: true, force: true });
  }
}

test('R uses only the Machine-assigned HQ socket and exact private Live wire', (t) => withHqSocket(t,
  (request, socket) => {
    assert.deepEqual(Object.keys(request).sort(), ['id', 'op', 'payload']);
    assert.equal(request.id, 1);
    assert.equal(request.op, 'launch.live');
    assert.deepEqual(Object.keys(request.payload).sort(), ['challenge', 'installation_id', 'launch_id', 'reservation_sha256', 'start_id']);
    assert.equal(Buffer.from(request.payload.challenge, 'base64url').length, 32);
    socket.end(JSON.stringify({ id: 1, ok: true, result: {
      lease_envelope_base64url: 'YQ', lease_sha256: `sha256:${'a'.repeat(64)}`, lease_sequence: 1,
    } }) + '\n');
  }, async (start) => {
    const { challenge, reply } = await requestProtectedLive(start);
    assert.equal(challenge.length, 32);
    assert.equal(reply.lease_sequence, 1);
    assert.throws(() => requestProtectedLive({ ...start, admissionSocket: '/wrong' }), /signed R-only HQ endpoint/);
  }));

test('R rejects extra bytes in the private HQ Live response', (t) => withHqSocket(t,
  (_request, socket) => socket.end('{"id":1,"ok":true,"result":{"lease_envelope_base64url":"YQ","lease_sha256":"sha256:' + 'a'.repeat(64) + '","lease_sequence":1}}\nextra'),
  async (start) => assert.rejects(requestProtectedLive(start), /trailing reply bytes/)));
