// The R-only assigned admission socket carries one private Live request per
// connection. This is deliberately separate from the public HQ/Contracts SDK.
import { randomBytes } from 'node:crypto';
import { lstatSync } from 'node:fs';
import { connect } from 'node:net';
import { dirname } from 'node:path';
import { parseStrict } from './contracts.mjs';

const MAX_REPLY = 16 * 1024;
const bad = (reason) => { throw new Error('protected live client: ' + reason); };
const exact = (value, fields) => value !== null && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === fields.length && fields.every((field) => Object.hasOwn(value, field));

function checkEndpoint(start) {
  const endpoint = start?.admissionEndpoint;
  if (!endpoint || start.admissionSocket !== endpoint.socket_path
    || dirname(endpoint.socket_path) !== endpoint.directory
    || endpoint.dir_mode !== 0o2750 || endpoint.socket_mode !== 0o660
    || !Array.isArray(endpoint.peer_uids) || endpoint.peer_uids.length !== 1
    || endpoint.peer_uids[0] !== process.geteuid()) bad('signed R-only HQ endpoint is invalid');
  let dir, socket;
  try { dir = lstatSync(endpoint.directory); socket = lstatSync(endpoint.socket_path); }
  catch { bad('assigned HQ endpoint is unavailable'); }
  if (!dir.isDirectory() || !socket.isSocket()
    || dir.uid !== endpoint.owner_uid || dir.gid !== endpoint.group_gid
    || socket.uid !== endpoint.owner_uid || socket.gid !== endpoint.group_gid
    || (dir.mode & 0o7777) !== endpoint.dir_mode
    || (socket.mode & 0o7777) !== endpoint.socket_mode) bad('assigned HQ endpoint differs from Machine reservation');
  return { path: endpoint.socket_path, directory: { dev: dir.dev, ino: dir.ino } };
}

export function requestProtectedLive(start, { timeoutMs = 1_500 } = {}) {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 2_000) {
    throw new TypeError('protected Live deadline must be at most two seconds');
  }
  const endpoint = checkEndpoint(start);
  const challenge = randomBytes(32);
  const payload = { installation_id: start.installationId, start_id: start.startId,
    launch_id: start.launchId, reservation_sha256: start.reservationSha256,
    challenge: challenge.toString('base64url') };
  const request = Buffer.from(JSON.stringify({ id: 1, op: 'launch.live', payload }) + '\n');
  if (request.length > 4 * 1024) bad('Live request exceeds the private line limit');
  return new Promise((resolve, reject) => {
    const socket = connect(endpoint.path);
    let raw = Buffer.alloc(0);
    let settled = false;
    const finish = (error, reply) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      if (error) reject(error); else resolve({ challenge, reply });
    };
    const timer = setTimeout(() => finish(new Error('protected live client: HQ reply timed out')), timeoutMs);
    socket.once('connect', () => {
      let current;
      try { current = lstatSync(start.admissionEndpoint.directory); }
      catch { finish(new Error('protected live client: HQ endpoint changed')); return; }
      if (current.dev !== endpoint.directory.dev || current.ino !== endpoint.directory.ino) {
        finish(new Error('protected live client: HQ endpoint changed')); return;
      }
      socket.write(request);
    });
    socket.on('data', (chunk) => {
      raw = Buffer.concat([raw, chunk]);
      if (raw.length > MAX_REPLY) { finish(new Error('protected live client: reply exceeds 16 KiB')); return; }
      const newline = raw.indexOf(0x0a);
      if (newline < 0) return;
      if (newline !== raw.length - 1) { finish(new Error('protected live client: trailing reply bytes')); return; }
      let response;
      try { response = parseStrict(new TextDecoder('utf-8', { fatal: true }).decode(raw.subarray(0, -1))); }
      catch { finish(new Error('protected live client: invalid reply JSON')); return; }
      if (!exact(response, ['id', 'ok', 'result']) || response.id !== 1 || response.ok !== true
        || !exact(response.result, ['lease_envelope_base64url', 'lease_sha256', 'lease_sequence'])) {
        finish(new Error('protected live client: HQ refused or changed the Live reply')); return;
      }
      finish(null, response.result);
    });
    socket.once('error', () => finish(new Error('protected live client: HQ socket failed')));
    socket.once('close', () => { if (!settled) finish(new Error('protected live client: HQ closed before Live reply')); });
  });
}
