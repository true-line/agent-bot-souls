// R verifies the first signed Live lease before HQ can admit its protected
// Hello. Renewals run during Hello/Equip, then R sends a private readiness ack.
// Owner ACP remains withheld pending Machine's separate child-start receipt.
import { requestProtectedLive } from './protected-live-client.mjs';
import { checkProtectedLive } from './protected-live.mjs';
import { watchProtectedLease } from './protected-watchdog.mjs';
import { checkProtectedChildStart } from './protected-child-start.mjs';
import { parseStrict } from './contracts.mjs';

function writeAck(output, ack) {
  const line = Buffer.from(JSON.stringify(ack) + '\n');
  if (line.length > 512) throw new Error('protected control: readiness ack exceeds 512 bytes');
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error) => {
      if (settled) return;
      settled = true; clearTimeout(timer); output.off('error', onError);
      if (error) reject(error); else resolve();
    };
    const onError = () => finish(new Error('protected control: private HQ pipe failed'));
    const timer = setTimeout(() => finish(new Error('protected control: readiness ack timed out')), 1_000);
    output.once('error', onError);
    try { output.write(line, finish); }
    catch (error) { finish(error); }
  });
}

export async function beginProtectedControl({ start, activation, input, output, signal,
  leaseSource, childVerifier = checkProtectedChildStart, renewIntervalMs = 2_000 } = {}) {
  if (!start || !activation || typeof input?.on !== 'function' || typeof output?.write !== 'function') {
    throw new TypeError('protected control requires signed start, finalization and private pipes');
  }
  if (signal?.aborted) throw new Error('protected control: start was cancelled');
  let soul;
  let closed = false;
  let childReceipt;
  let phase = 'admitting';
  let bytes = Buffer.alloc(0);
  let resolveChild, rejectChild;
  const childFrame = new Promise((resolve, reject) => { resolveChild = resolve; rejectChild = reject; });
  void childFrame.catch(() => {});
  const signedLease = async (previous) => {
    const { challenge, reply } = await requestProtectedLive(start);
    const lease = checkProtectedLive(reply, start, activation, challenge, previous, childReceipt);
    return { reply, lease };
  };
  const getLease = async (previous) => {
    const { reply, lease } = await (leaseSource ?? signedLease)(previous);
    if (!/^sha256:[0-9a-f]{64}$/.test(reply?.lease_sha256 ?? '')
      || !Number.isSafeInteger(lease?.sequence) || !Number.isSafeInteger(lease?.expiresAtMs)) {
      throw new Error('protected control: verified Live result is invalid');
    }
    return Object.freeze({ ...lease, sha256: reply.lease_sha256 });
  };
  const first = await getLease(null);
  if (signal?.aborted) throw new Error('protected control: start was cancelled during first Live request');
  const watcher = watchProtectedLease(first, {
    intervalMs: renewIntervalMs,
    renew: getLease,
    stop: async () => {
      closed = true;
      rejectChild(new Error('protected control: signed Live lease stopped before child handoff'));
      input.destroy();
      if (soul) await soul.stop();
    },
  });
  const unexpected = () => { rejectChild(new Error('protected control: private HQ pipe ended')); void watcher.stop(); };
  const onData = (chunk) => {
    if (phase !== 'waiting-child' || bytes.length + chunk.length > 32 * 1024) { unexpected(); return; }
    bytes = Buffer.concat([bytes, chunk]);
    const newline = bytes.indexOf(0x0a);
    if (newline < 0) return;
    if (newline === 0 || newline !== bytes.length - 1) { unexpected(); return; }
    let value;
    try { value = parseStrict(new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, -1))); }
    catch { unexpected(); return; }
    phase = 'checking-child';
    input.pause();
    resolveChild(value);
  };
  const aborted = () => { void watcher.stop(); };
  input.on('data', onData);
  input.once('end', unexpected);
  input.once('error', unexpected);
  signal?.addEventListener('abort', aborted, { once: true });
  input.resume();
  const done = watcher.done.finally(() => {
    input.off('data', onData); input.off('end', unexpected); input.off('error', unexpected);
    signal?.removeEventListener('abort', aborted);
  });
  return Object.freeze({
    done,
    stop: () => watcher.stop(),
    attachSoul(value) {
      if (soul || typeof value?.stop !== 'function') throw new TypeError('protected Soul may be attached once');
      soul = value;
      if (closed) { void value.stop(); throw new Error('protected control: signed lease expired during HQ admission'); }
    },
    async acknowledge() {
      if (!soul || closed || phase !== 'admitting' || watcher.current().expiresAtMs <= Date.now()) {
        throw new Error('protected control: HQ admission outlived the signed lease');
      }
      const current = watcher.current();
      phase = 'waiting-child';
      await writeAck(output, { schema: 'agent-bot-souls/protected-activation-ack/v1',
        reservation_sha256: start.reservationSha256, start_id: start.startId,
        launch_id: start.launchId, lease_sha256: current.sha256, lease_sequence: current.sequence });
      if (closed) throw new Error('protected control: lease expired before readiness ack');
    },
    async waitForChild() {
      if (!soul || closed || (phase !== 'waiting-child' && phase !== 'checking-child')) throw new Error('protected control: first readiness ack is required');
      const timer = setTimeout(() => { void watcher.stop(); }, 30_000);
      try {
        const frame = await childFrame;
        const current = watcher.current();
        if (closed || current.expiresAtMs <= Date.now()) throw new Error('protected control: signed Live lease expired before child handoff');
        childReceipt = childVerifier(frame, start, activation, current);
        return childReceipt;
      } finally { clearTimeout(timer); }
    },
    async acknowledgeChild(receipt) {
      if (!receipt || receipt !== childReceipt || closed || phase !== 'checking-child'
        || watcher.current().expiresAtMs <= Date.now()) {
        throw new Error('protected control: verified child handoff is required');
      }
      await writeAck(output, { schema: 'agent-bot-souls/protected-child-ready/v1',
        reservation_sha256: start.reservationSha256, start_id: start.startId,
        launch_id: start.launchId, child_start_sha256: receipt.sha256 });
      phase = 'sealed';
      input.resume();
      if (closed) throw new Error('protected control: lease expired before child ack');
    },
  });
}
