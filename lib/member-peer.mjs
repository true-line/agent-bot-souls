// Check the accepted Unix stream's kernel peer UID before parsing a member
// token. Node does not expose getpeereid/SO_PEERCRED; the child receives only
// this accepted descriptor as fd 3 and never reads application bytes.
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const darwin = process.platform === 'darwin';
const interpreter = darwin ? '/usr/bin/ruby' : '/usr/bin/python3';
const helper = fileURLToPath(new URL(darwin ? './helpers/member-peer.rb' : './helpers/member-peer.py', import.meta.url));
const argv = (op, uids = []) => darwin ? ['--disable-gems', helper, op, ...uids.map(String)] : ['-I', '-S', helper, op, ...uids.map(String)];

export function memberPeerSupported() {
  if (!['darwin', 'linux'].includes(process.platform)) return false;
  const probe = spawnSync(interpreter, argv('probe'), { env: {}, stdio: 'ignore', timeout: 2_000 });
  return !probe.error && probe.status === 0;
}

// The injected child factory is only for deterministic lifecycle tests. The
// production authenticator always uses spawn with the accepted stream as fd 3.
export function createMemberPeerAuthenticator({ spawnChild = spawn, probeTimeoutMs = 2_000, closeTimeoutMs = 2_000 } = {}) {
  return (socket, allowedUids) => {
    if (!Array.isArray(allowedUids) || allowedUids.length === 0) return { done: Promise.resolve(null), abort() {} };
    let probe;
    let timer;
    let closeTimer;
    let settled = false;
    let failed = false;
    let aborting = false;
    let output = '';
    let resolveDone;
    let rejectDone;
    const done = new Promise((resolve, reject) => { resolveDone = resolve; rejectDone = reject; });
    const clearTimers = () => { clearTimeout(timer); clearTimeout(closeTimer); };
    const finish = (uid) => {
      if (settled) return;
      settled = true;
      clearTimers();
      resolveDone(uid);
    };
    const armCloseTimeout = () => {
      if (settled || closeTimer) return;
      closeTimer = setTimeout(() => {
        if (settled) return;
        settled = true;
        clearTimers();
        rejectDone(new Error('member peer helper did not close after failure or abort'));
      }, closeTimeoutMs);
    };
    const abort = () => {
      if (settled || aborting) return;
      aborting = true;
      failed = true;
      try { probe?.kill('SIGKILL'); } catch { /* close remains the only proof of release */ }
      armCloseTimeout();
    };
    try {
      probe = spawnChild(interpreter, argv('peer', allowedUids), {
        env: {}, stdio: ['ignore', 'pipe', 'ignore', socket],
      });
    } catch { finish(null); return { done, abort }; }
    timer = setTimeout(abort, probeTimeoutMs);
    probe.on('error', () => {
      // A failed kill can emit error while the child still owns fd 3.
      failed = true;
      clearTimeout(timer);
      armCloseTimeout();
    });
    probe.once('close', (code) => {
      const match = !failed && !aborting && code === 0 && /^([0-9]{1,10})\n$/.exec(output);
      const uid = match && Number(match[1]);
      finish(Number.isSafeInteger(uid) && allowedUids.includes(uid) ? uid : null);
    });
    if (probe.stdout) {
      probe.stdout.on('data', (chunk) => {
        output += chunk;
        if (output.length > 16) abort();
      });
    } else abort();
    return { done, abort };
  };
}

export const authenticateMemberPeer = createMemberPeerAuthenticator();
