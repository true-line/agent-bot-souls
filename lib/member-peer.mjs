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
  if (!Array.isArray(allowedUids) || allowedUids.length === 0) return Promise.resolve(false);
  return new Promise((resolve) => {
    let settled = false;
    const finish = (ok) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(ok);
    };
    let probe;
    const timer = setTimeout(() => { probe?.kill('SIGKILL'); finish(false); }, 2_000);
    try {
      probe = spawn(interpreter, argv('peer', allowedUids), {
        env: {}, stdio: ['ignore', 'ignore', 'ignore', socket],
      });
    } catch { finish(false); return; }
    probe.once('error', () => finish(false));
    probe.once('close', (code) => finish(code === 0));
  });
}
