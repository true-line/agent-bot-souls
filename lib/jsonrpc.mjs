// A JSON-RPC 2.0 peer over newline-delimited JSON, which is how the Agent
// Client Protocol frames messages on stdio. Either side may send requests
// and notifications.
import { readLines, writeLine } from './ndjson.mjs';

export class RpcError extends Error {
  constructor(code, message, data) {
    super(message);
    this.name = 'RpcError';
    this.code = code;
    if (data !== undefined) this.data = data;
  }
}

export const METHOD_NOT_FOUND = -32601;
export const INVALID_PARAMS = -32602;
export const INTERNAL_ERROR = -32603;

// methods: { name: async (params) => result }. onNotify(method, params).
// onClose(reason) runs once when the input ends.
export function rpcPeer({ input, output, methods = {}, onNotify = () => {}, onClose = () => {} }) {
  const pending = new Map();
  let next = 1;
  let closed = false;
  const end = (reason) => {
    if (closed) return;
    closed = true;
    for (const [, w] of pending) w.reject(new RpcError(INTERNAL_ERROR, `connection closed: ${reason}`, { closed: true }));
    pending.clear();
    onClose(reason);
  };
  async function serve(msg) {
    const handler = Object.hasOwn(methods, msg.method) ? methods[msg.method] : undefined;
    if (msg.id === undefined || msg.id === null) {
      if (!handler) { onNotify(msg.method, msg.params); return; }
      try { await handler(msg.params); } catch { /* a notification has no reply */ }
      return;
    }
    if (!handler) { writeLine(output, { jsonrpc: '2.0', id: msg.id, error: { code: METHOD_NOT_FOUND, message: `method not found: ${msg.method}` } }); return; }
    try {
      const result = await handler(msg.params);
      writeLine(output, { jsonrpc: '2.0', id: msg.id, result: result === undefined ? null : result });
    } catch (e) {
      const error = e instanceof RpcError
        ? { code: e.code, message: e.message, ...(e.data !== undefined ? { data: e.data } : {}) }
        : { code: INTERNAL_ERROR, message: String(e?.message ?? e) };
      writeLine(output, { jsonrpc: '2.0', id: msg.id, error });
    }
  }
  readLines(input, (line) => {
    let msg;
    try { msg = JSON.parse(line); } catch { return; }
    if (!msg || typeof msg !== 'object' || Array.isArray(msg)) return;
    if (typeof msg.method === 'string') { serve(msg); return; }
    const w = pending.get(msg.id);
    if (!w) return;
    pending.delete(msg.id);
    if (msg.error) w.reject(new RpcError(msg.error.code, msg.error.message, msg.error.data));
    else w.resolve(msg.result);
  }, (e) => end(e.message));
  input.on('end', () => end('input ended'));
  input.on('close', () => end('input closed'));
  input.on('error', (e) => end(e.message));
  output.on('error', () => {});
  return {
    request(method, params) {
      return new Promise((resolve, reject) => {
        if (closed) { reject(new RpcError(INTERNAL_ERROR, 'connection closed', { closed: true })); return; }
        const id = next++;
        pending.set(id, { resolve, reject });
        writeLine(output, { jsonrpc: '2.0', id, method, ...(params === undefined ? {} : { params }) });
      });
    },
    notify(method, params) { if (!closed) writeLine(output, { jsonrpc: '2.0', method, ...(params === undefined ? {} : { params }) }); },
    close: (reason = 'closed') => end(reason),
    get closed() { return closed; },
  };
}
