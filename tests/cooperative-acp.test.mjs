import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { connectCooperativeAcp } from '../lib/cooperative-acp.mjs';

const startId = `st_${'1'.repeat(24)}`;
const launchId = `ln_${'2'.repeat(24)}`;
const reservationSha256 = `sha256:${'3'.repeat(64)}`;
const ticket = Buffer.alloc(32, 0x44).toString('base64url');

async function withServer(t, handle) {
  const directory = mkdtempSync(join(tmpdir(), 'souls-acp-'));
  const path = join(directory, 'c.sock');
  const sockets = new Set();
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
    handle(socket);
  });
  await new Promise((resolve) => server.listen(path, resolve));
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
    rmSync(directory, { recursive: true, force: true });
  });
  return { path, acpTicketBase64url: ticket, reservationSha256, startId, launchId };
}

test('second signed C connection consumes the ticket then carries raw ACP', async (t) => {
  const rawAcp = Buffer.from('{"jsonrpc":"2.0","id":1,"method":"initialize"}\n');
  const start = await withServer(t, (socket) => {
    socket.once('data', (chunk) => {
      assert.deepEqual(JSON.parse(chunk.toString()), { id: 1, op: 'cooperative.acp.v3',
        payload: { acp_ticket_base64url: ticket } });
      socket.write(Buffer.concat([Buffer.from(`${JSON.stringify({ id: 1, ok: true, result: {
        schema: 'hq/cooperative-acp/v3', reservation_sha256: reservationSha256,
        start_id: startId, launch_id: launchId,
      } })}\n`), rawAcp]));
    });
  });
  const socket = await connectCooperativeAcp(start);
  const received = new Promise((resolve) => socket.once('data', resolve));
  socket.resume();
  assert.deepEqual(await received, rawAcp);
  socket.destroy();
});

test('wrong ACP ticket reply refuses before raw stream handoff', async (t) => {
  const start = await withServer(t, (socket) => {
    socket.once('data', () => socket.end(`${JSON.stringify({ id: 1, ok: true, result: {
      schema: 'hq/cooperative-acp/v3', reservation_sha256: `sha256:${'0'.repeat(64)}`,
      start_id: startId, launch_id: launchId,
    } })}\n`));
  });
  await assert.rejects(connectCooperativeAcp(start), /reply differs/);
});
