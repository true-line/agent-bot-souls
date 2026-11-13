// A client for HQ's local sockets (agent-bot-hq plan §7.1): strict NDJSON,
//   request  {"id", "op", "payload"}
//   reply    {"id", "ok": true, "result"}
//          | {"id", "ok": false, "refusal": <common/v1 error response>}
//          | {"id", "ok": false, "host_refusal": {"code", "explanation"}}
// The entry point uses admission.sock; a member uses broker.sock, where `op`
// is a message kind. Nothing here holds authority: HQ decides every request.
import { connect } from 'node:net';
import { loadContracts, parseStrict, SCHEMAS } from './contracts.mjs';
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

export function connectHq(path, { contracts = loadContracts() } = {}) {
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
      try { msg = parseStrict(line); } catch { socket.destroy(); return; }
      if (!msg || typeof msg !== 'object' || Array.isArray(msg) || typeof msg.ok !== 'boolean') { socket.destroy(); return; }
      const w = pending.get(msg.id);
      // This request/reply connection has no unsolicited messages. A bad
      // ID or envelope must fail every waiter, rather than leave the actual
      // request hanging forever after its only reply was discarded.
      const fields = msg.ok ? ['id', 'ok', 'result'] : ['id', 'ok', msg.refusal ? 'refusal' : 'host_refusal'];
      if (!w || Object.keys(msg).length !== 3 || fields.some((key) => !Object.hasOwn(msg, key)) || Object.keys(msg).some((key) => !fields.includes(key))) { socket.destroy(); return; }
      if (!msg.ok && (!msg.refusal && (!msg.host_refusal || typeof msg.host_refusal !== 'object' || Array.isArray(msg.host_refusal) || typeof msg.host_refusal.code !== 'string' || typeof msg.host_refusal.explanation !== 'string'))) { socket.destroy(); return; }
      pending.delete(msg.id);
      try {
        if (msg.ok === true) {
          if (w.op === 'Hello') contracts.admission(msg.result, w.payload);
          if (w.op === 'Equip') contracts.record(SCHEMAS.equip, msg.result);
          if (w.op === 'task.get') contracts.record(SCHEMAS.task, msg.result?.task);
          if (w.op === 'task.directives') {
            if (!Array.isArray(msg.result?.directives)) throw new Error('HQ directives are not a list');
            for (const directive of msg.result.directives) {
              contracts.record(SCHEMAS.directive, directive);
              if (directive.payload?.task) contracts.record(SCHEMAS.task, directive.payload.task);
            }
          }
          w.resolve(msg.result);
        } else {
          if (msg.refusal) contracts.record(SCHEMAS.refusal, msg.refusal);
          w.reject(new HqRefusal(w.op, msg));
        }
      } catch (error) { w.reject(error); }
    }, () => socket.destroy());
    socket.on('close', () => fail('connection closed'));
    socket.once('error', (e) => { reject(new HqRefusal('connect', { transport: `${path}: ${e.message}` })); fail(e.message); });
    socket.once('connect', () => resolve({
      request(op, payload) {
        return new Promise((res, rej) => {
          if (closed) { rej(new HqRefusal(op, { transport: 'connection closed' })); return; }
          const id = next++;
          try {
            const schema = op === 'Hello' ? SCHEMAS.hello : ['Ready', 'Lease'].includes(op) ? SCHEMAS.renewal : op === 'task.commit' ? SCHEMAS.commitment : undefined;
            if (schema) contracts.record(schema, payload);
          } catch (error) { rej(error); return; }
          pending.set(id, { op, payload, resolve: res, reject: rej });
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
