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

export function authenticateMemberPeer(socket, allowedUids) {
  if (!Array.isArray(allowedUids) || allowedUids.length === 0) return { done: Promise.resolve(null), abort() {} };
  let probe;
  let timer;
  const done = new Promise((resolve) => {
    let settled = false;
    let output = '';
    const finish = (uid) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(uid);
    };
    try {
      probe = spawn(interpreter, argv('peer', allowedUids), {
        env: {}, stdio: ['ignore', 'pipe', 'ignore', socket],
      });
    } catch { finish(null); return; }
    timer = setTimeout(() => probe.kill('SIGKILL'), 2_000);
    probe.stdout.on('data', (chunk) => {
      output += chunk;
      if (output.length > 16) probe.kill('SIGKILL');
    });
    probe.once('error', () => finish(null));
    probe.once('close', (code) => {
      const match = code === 0 && /^([0-9]{1,10})\n$/.exec(output);
      const uid = match && Number(match[1]);
      finish(Number.isSafeInteger(uid) && allowedUids.includes(uid) ? uid : null);
    });
  });
  return { done, abort() { probe?.kill('SIGKILL'); } };
}
