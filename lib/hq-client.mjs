// A client for HQ's local sockets (agent-bot-hq plan §7.1): strict NDJSON,
//   request  {"id", "op", "payload"}
//   reply    {"id", "ok": true, "result"}
//          | {"id", "ok": false, "refusal": <common/v1 error response>}
//          | {"id", "ok": false, "host_refusal": {"code", "explanation"}}
// The entry point uses admission.sock; a member uses broker.sock, where `op`
// is a message kind. Nothing here holds authority: HQ decides every request.
import { connect } from 'node:net';
import { readLines, writeLine } from './ndjson.mjs';

// HQ said no, or the connection failed before it answered. `code` is the
// registry code, the host code, or `transport`. After `transport` the
// outcome of the request is unknown.
export class HqRefusal extends Error {
  constructor(op, { refusal, host_refusal: host, transport } = {}) {
    const code = refusal?.error ?? host?.code ?? 'transport';
    super(`${op}: ${code}: ${refusal?.explanation ?? host?.explanation ?? transport ?? 'refused'}`);
    this.name = 'HqRefusal';
    this.op = op;
    this.code = code;
    this.transport = !refusal && !host;
  }
}

export function connectHq(path) {
  return new Promise((resolve, reject) => {
    const socket = connect(path);
    const pending = new Map();
    let next = 1;
    let closed = false;
    const fail = (why) => {
      closed = true;
      for (const [, w] of pending) w.reject(new HqRefusal(w.op, { transport: why }));
      pending.clear();
    };
    readLines(socket, (line) => {
      let msg;
      try { msg = JSON.parse(line); } catch { socket.destroy(); return; }
      const w = pending.get(msg.id);
      if (!w) return;
      pending.delete(msg.id);
      if (msg.ok === true) w.resolve(msg.result);
      else w.reject(new HqRefusal(w.op, msg));
    }, () => socket.destroy());
    socket.on('close', () => fail('connection closed'));
    socket.once('error', (e) => { reject(new HqRefusal('connect', { transport: `${path}: ${e.message}` })); fail(e.message); });
    socket.once('connect', () => resolve({
      request(op, payload) {
        return new Promise((res, rej) => {
          if (closed) { rej(new HqRefusal(op, { transport: 'connection closed' })); return; }
          const id = next++;
          pending.set(id, { op, resolve: res, reject: rej });
          writeLine(socket, { id, op, ...(payload === undefined ? {} : { payload }) });
        });
      },
      get closed() { return closed; },
      close: () => new Promise((res) => {
        if (socket.destroyed) { res(); return; }
        socket.once('close', res);
        socket.end();
      }),
      // Drop the connection without a clean end (tests of lost replies).
      destroy: () => socket.destroy(),
    }));
  });
}
