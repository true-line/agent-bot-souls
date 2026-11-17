// Preserve the Soul runtime's verified-contract default while sharing the
// mechanical local socket implementation with every SDK consumer.
import { connect } from 'node:net';
import { loadContracts } from './contracts.mjs';
import { parseStrict } from './contracts.mjs';
import { connectHq as sharedConnectHq } from './vendor/agent-bot-sdk/local-socket-client.mjs';
import { HqRefusal } from './vendor/agent-bot-sdk/local-socket-client.mjs';
import { MAX_LINE_BYTES } from './vendor/agent-bot-sdk/local-socket-lines.mjs';
export { HqRefusal, isRetryableMemberReadFailure } from './vendor/agent-bot-sdk/local-socket-client.mjs';

export function connectHq(path, { contracts = loadContracts() } = {}) {
  return sharedConnectHq(path, { contracts });
}

// `launch.attach` is the first and only HQ request on a new connection. Once
// HQ answers, that same byte stream becomes the launched adapter's stdio. The
// first adapter bytes may share a read with the answer, so put them back on
// the paused socket before handing it to the ACP peer.
export function attachHq(path, payload, { contracts = loadContracts() } = {}) {
  if (!contracts || typeof contracts.record !== 'function') throw new TypeError('launch attach requires verified shared contract validation');
  const checkRefusal = (refusal) => {
    const result = contracts.record('common/v1/error-response.schema.json', refusal);
    if (result && typeof result.then === 'function') {
      Promise.resolve(result).catch(() => {});
      throw new TypeError('launch attach contract validation must be synchronous');
    }
  };
  return new Promise((resolve, reject) => {
    const socket = connect(path);
    let buf = Buffer.alloc(0);
    let settled = false;
    const fail = (error, transport = false) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(transport ? new HqRefusal('launch.attach', { transport: error.message }) : error);
    };
    const onData = (chunk) => {
      if (settled) return;
      buf = buf.length ? Buffer.concat([buf, chunk]) : chunk;
      const nl = buf.indexOf(0x0a);
      if (nl === -1) {
        if (buf.length > MAX_LINE_BYTES) fail(new Error(`reply line exceeds ${MAX_LINE_BYTES} bytes`));
        return;
      }
      socket.pause();
      socket.off('data', onData);
      let msg;
      try { msg = parseStrict(buf.subarray(0, nl)); }
      catch (error) { fail(error); return; }
      const refusalKey = msg?.refusal ? 'refusal' : 'host_refusal';
      const fields = msg?.ok === true ? ['id', 'ok', 'result'] : ['id', 'ok', refusalKey];
      if (!msg || typeof msg !== 'object' || Array.isArray(msg) || msg.id !== 1 || typeof msg.ok !== 'boolean'
        || Object.keys(msg).length !== 3 || fields.some((key) => !Object.hasOwn(msg, key)) || Object.keys(msg).some((key) => !fields.includes(key))) {
        fail(new Error('invalid launch.attach reply envelope')); return;
      }
      if (!msg.ok) {
        try {
          if (msg.refusal) checkRefusal(msg.refusal);
          else if (!msg.host_refusal || typeof msg.host_refusal !== 'object' || Array.isArray(msg.host_refusal)
            || typeof msg.host_refusal.code !== 'string' || typeof msg.host_refusal.explanation !== 'string') {
            throw new Error('invalid launch.attach refusal envelope');
          }
        } catch (error) { fail(error); return; }
        fail(new HqRefusal('launch.attach', msg)); return;
      }
      if (!msg.result || typeof msg.result !== 'object' || Array.isArray(msg.result)
        || Object.keys(msg.result).length !== 1 || msg.result.launch_id !== payload.launch_id) {
        fail(new Error('invalid launch.attach result')); return;
      }
      const rest = buf.subarray(nl + 1);
      settled = true;
      socket.on('error', () => {});
      if (rest.length) socket.unshift(rest);
      resolve(socket);
    };
    socket.on('data', onData);
    socket.once('error', (error) => fail(error, true));
    socket.once('close', () => { if (!settled) fail(new Error('connection closed before launch.attach answered'), true); });
    socket.once('connect', () => socket.write(`${JSON.stringify({ id: 1, op: 'launch.attach', payload })}\n`));
  });
}
