// Open a second connection to the same signed H admission socket. Its first
// request consumes HQ's one-use ticket, then the socket becomes raw ACP.
import { connect } from 'node:net';
import { isAbsolute, parse, resolve } from 'node:path';
import { parseStrict } from './contracts.mjs';

const MAX_REPLY = 1 << 20;
const SHA = /^sha256:[0-9a-f]{64}$/;
const START = /^st_[0-9a-f]{24}$/;
const LAUNCH = /^ln_[0-9a-f]{24}$/;
const exact = (value, fields) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === fields.length && fields.every((field) => Object.hasOwn(value, field));

export function connectCooperativeAcp(start, { signal, deadlineMs = 5_000 } = {}) {
  const ticket = start?.acpTicketBase64url;
  if (typeof start?.path !== 'string' || !isAbsolute(start.path) || resolve(start.path) !== start.path
    || start.path === parse(start.path).root || !SHA.test(start.reservationSha256 ?? '')
    || !START.test(start.startId ?? '') || !LAUNCH.test(start.launchId ?? '')
    || typeof ticket !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(ticket)
    || Buffer.from(ticket, 'base64url').length !== 32
    || Buffer.from(ticket, 'base64url').toString('base64url') !== ticket) {
    throw new Error('cooperative ACP: verified HQ ticket and signed endpoint are required');
  }
  return new Promise((resolveSocket, reject) => {
    signal?.throwIfAborted();
    const socket = connect(start.path);
    let data = Buffer.alloc(0);
    let settled = false;
    const fail = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      socket.destroy();
      reject(error);
    };
    const abort = () => fail(signal.reason ?? new Error('cooperative ACP aborted'));
    const timer = setTimeout(() => fail(new Error('cooperative ACP: HQ ticket reply timed out')), deadlineMs);
    timer.unref?.();
    signal?.addEventListener('abort', abort, { once: true });
    socket.on('error', (error) => fail(new Error(`cooperative ACP: ${error.code ?? error.message}`)));
    socket.once('close', () => fail(new Error('cooperative ACP: HQ closed before ticket reply')));
    socket.once('connect', () => {
      socket.write(`${JSON.stringify({ id: 1, op: 'cooperative.acp.v3', payload: {
        acp_ticket_base64url: ticket,
      } })}\n`);
    });
    const onData = (chunk) => {
      if (settled) return;
      data = data.length ? Buffer.concat([data, chunk]) : chunk;
      const nl = data.indexOf(0x0a);
      if (nl === -1) {
        if (data.length > MAX_REPLY) fail(new Error('cooperative ACP: ticket reply exceeds line limit'));
        return;
      }
      if (nl > MAX_REPLY) { fail(new Error('cooperative ACP: ticket reply exceeds line limit')); return; }
      let reply;
      try { reply = parseStrict(new TextDecoder('utf-8', { fatal: true }).decode(data.subarray(0, nl))); }
      catch { fail(new Error('cooperative ACP: invalid HQ ticket reply')); return; }
      if (!exact(reply, ['id', 'ok', 'result']) || reply.id !== 1 || reply.ok !== true
        || !exact(reply.result, ['schema', 'reservation_sha256', 'start_id', 'launch_id'])
        || reply.result.schema !== 'hq/cooperative-acp/v3'
        || reply.result.reservation_sha256 !== start.reservationSha256
        || reply.result.start_id !== start.startId || reply.result.launch_id !== start.launchId) {
        fail(new Error('cooperative ACP: HQ ticket reply differs from the signed start')); return;
      }
      const rest = data.subarray(nl + 1);
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      socket.pause();
      socket.off('data', onData);
      if (rest.length) socket.unshift(rest);
      resolveSocket(socket);
    };
    socket.on('data', onData);
  });
}
