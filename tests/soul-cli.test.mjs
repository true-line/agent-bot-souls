import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import test from 'node:test';
import { runSoulCli } from '../lib/soul-cli.mjs';

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url)));
const executable = fileURLToPath(new URL('../' + pkg.bin.soul, import.meta.url));
const example = fileURLToPath(new URL('fixtures/terminal-example.mjs', import.meta.url));
const path = 'My Soul.soul';
const create = ['create', path, '--orchestrator', 'example'];
const signatures = ['soul create PATH --orchestrator HARNESS', 'soul inspect PATH', 'soul start PATH'];

function isolatedHome(t) {
  const home = mkdtempSync(join(tmpdir(), 'soul-terminal-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  return { cwd: home, env: { HOME: home } };
}

function run(bin, args, options) {
  const result = spawnSync(process.execPath, [bin, ...args], { ...options, encoding: 'utf8', timeout: 5000 });
  assert.ifError(result.error);
  assert.equal(result.signal, null);
  return result;
}

test('installed command signatures match help and dispatch', (t) => {
  const options = isolatedHome(t);
  const help = run(executable, ['--help'], options);
  assert.equal(help.status, 0);
  assert.deepEqual(help.stdout.split('\n').filter(line => line.startsWith('  ')).map(line => line.trim()), signatures);
  for (const [index, args] of [create, ['inspect', path], ['start', path]].entries()) {
    const detail = run(executable, [args[0], '--help'], options);
    assert.equal(detail.status, 0);
    assert.equal(detail.stdout.split('\n')[0], signatures[index]);
    const result = run(executable, args, options);
    assert.equal(result.status, 1);
    assert.equal(result.stdout, '');
    assert.match(result.stderr, /unavailable in this build/);
  }
  assert.deepEqual(readdirSync(options.cwd), []);
});

test('argument errors diagnose the command before dispatch', (t) => {
  const options = isolatedHome(t);
  for (const [args, expected] of [
    [[], /supply a command/], [['launch', path], /unknown command 'launch'.*--help/],
    [['create'], /supply a PATH/], [['inspect'], /supply a PATH/], [['start'], /supply a PATH/],
    [['create', path], /supply --orchestrator HARNESS/],
    [['create', path, '--orchestrator'], /supply --orchestrator HARNESS/],
    [['create', path, '--orchestrator', ' '], /supply --orchestrator HARNESS/],
    [['create', path, '--orchestrator', '--other'], /supply --orchestrator HARNESS/],
    [[...create, '--orchestrator', 'other'], /unexpected argument --orchestrator/],
    [['inspect', path, 'extra'], /unexpected argument extra/],
    [['start', path, '--standalone'], /unexpected argument --standalone/],
  ]) {
    const result = run(example, args, options);
    assert.equal(result.status, 2, args.join(' '));
    assert.equal(result.stdout, '');
    assert.match(result.stderr, expected);
  }
  assert.deepEqual(readdirSync(options.cwd), []);
});

test('inspect dispatches only the read-only handler with the original path', async () => {
  const calls = [];
  const handlers = {
    inspect(args) {
      calls.push(['inspect', args]);
      return { validity: 'valid', trust: 'unverified', readiness: 'ready' };
    },
    create() { calls.push('create'); }, start() { calls.push('start'); },
  };
  assert.equal(await runSoulCli(['inspect', path], handlers, { output: { write() {} } }), 0);
  assert.deepEqual(calls, [['inspect', { path }]]);
});

function openConversation(t, options) {
  const child = spawn(process.execPath, [example, 'start', path], { ...options, stdio: 'pipe' });
  t.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); });
  const lines = createInterface({ input: child.stdout })[Symbol.asyncIterator]();
  return { child, lines, closed: once(child, 'close') };
}

test('owner transcript, second local start, EOF, restart, and Ctrl-C', { timeout: 15000 }, async (t) => {
  const options = isolatedHome(t);
  const transcript = ['Contract example with simulated package and harness handlers.', ''];
  function record(args, command, stream, code) {
    const result = run(example, args, options);
    assert.equal(result.status, code);
    assert.equal(stream === 'stdout' ? result.stderr : result.stdout, '');
    transcript.push('$ ' + command, result[stream].trimEnd(), `[exit ${result.status}]`);
  }
  record(create, 'soul create "My Soul.soul" --orchestrator example', 'stdout', 0);
  const again = run(example, ['create', path, '--orchestrator', 'other'], options);
  assert.equal(again.status, 1);
  assert.match(again.stderr, /already exists. Choose a new path/);
  record(['inspect', path], 'soul inspect "My Soul.soul"', 'stdout', 0);
  record(['start', path], 'soul start "My Soul.soul"', 'stderr', 1);

  options.env.EXAMPLE_INSTALLED_HARNESS = 'example';
  transcript.push('', '[The example harness is now available locally.]', '$ soul start "My Soul.soul"');
  const session = openConversation(t, options);
  const opening = await session.lines.next();
  assert.equal(opening.value, 'Owner conversation open.');
  transcript.push(opening.value);
  const childPid = () => Number(readFileSync(join(options.cwd, path, 'example-writer', 'pid'), 'utf8'));
  const firstChild = childPid();
  const second = run(example, ['start', './' + path], options);
  assert.equal(second.status, 1);
  assert.equal(second.stdout, '');
  assert.match(second.stderr, /already running. End the first session/);
  assert.equal(childPid(), firstChild);
  process.kill(firstChild, 0);
  session.child.stdin.write('hello\n');
  transcript.push('hello', (await session.lines.next()).value);
  session.child.stdin.end();
  const [code, signal] = await session.closed;
  assert.equal(signal, null);
  assert.equal(code, 0);
  transcript.push('[EOF]', `[exit ${code}]`);
  assert.throws(() => process.kill(firstChild, 0), { code: 'ESRCH' });
  const snapshot = readFileSync(new URL('../docs/terminal-transcript.txt', import.meta.url), 'utf8');
  assert.equal(transcript.join('\n') + '\n', snapshot);

  const restart = openConversation(t, options);
  assert.equal((await restart.lines.next()).value, opening.value);
  const restartedChild = childPid();
  restart.child.kill('SIGINT');
  assert.deepEqual(await restart.closed, [130, null]);
  assert.throws(() => process.kill(restartedChild, 0), { code: 'ESRCH' });
  assert.equal(run(example, ['start', path], options).status, 0);
});

test('startup failure reaps a partially launched child and releases the writer before retry', (t) => {
  const options = isolatedHome(t);
  options.env.EXAMPLE_INSTALLED_HARNESS = 'example';
  assert.equal(run(example, create, options).status, 0);
  const failed = run(example, ['start', path], {
    ...options, env: { ...options.env, EXAMPLE_FAIL_AFTER_SPAWN: '1' },
  });
  assert.equal(failed.status, 1);
  assert.equal(failed.stdout, '');
  const message = /^soul start: example initialization failed for child (\d+)\n$/;
  assert.match(failed.stderr, message);
  const pid = Number(message.exec(failed.stderr)[1]);
  assert.throws(() => process.kill(pid, 0), { code: 'ESRCH' });
  assert.equal(run(example, ['start', path], options).status, 0);
});
