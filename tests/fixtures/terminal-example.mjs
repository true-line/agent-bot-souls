// Injected contract examples only. These files are test state, not Soul records.
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { runSoulCli } from '../../lib/soul-cli.mjs';

const foundingHarness = (path) => readFile(join(path, 'example-harness'), 'utf8');
const available = (harness) => process.env.EXAMPLE_INSTALLED_HARNESS === harness;
const handlers = {
  async create({ path, orchestrator }) {
    try {
      await mkdir(path);
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
      throw new Error(`${path} already exists. Choose a new path.`);
    }
    await writeFile(join(path, 'example-harness'), orchestrator);
  },
  async inspect({ path }) {
    const harness = await foundingHarness(path);
    return { validity: 'valid', trust: 'unverified', readiness: available(harness)
      ? 'ready' : `missing harness ${harness}. Install it before starting.` };
  },
  async start({ path }) {
    const harness = await foundingHarness(path);
    if (!available(harness)) throw new Error(`missing harness ${harness}. Install it and retry soul start.`);
    const writer = join(path, 'example-writer');
    try {
      await mkdir(writer);
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
      throw new Error(`${path} is already running. End the first session before restarting.`);
    }
    let child;
    let closed;
    async function stop() {
      if (child) {
        child.stdin.end();
        await closed;
      }
      await rm(writer, { recursive: true });
    }
    try {
      child = spawn(process.execPath, ['-e', 'process.stdin.resume()'], { stdio: ['pipe', 'ignore', 'ignore'] });
      // close also fires after a failed spawn, when there is no exit event.
      closed = new Promise(resolve => child.once('close', resolve));
      await once(child, 'spawn');
      if (process.env.EXAMPLE_FAIL_AFTER_SPAWN) throw new Error(`example initialization failed for child ${child.pid}`);
      await writeFile(join(writer, 'pid'), String(child.pid));
    } catch (error) {
      await stop();
      throw error;
    }
    return {
      async converse({ input, output, signal }) {
        const lines = createInterface({ input, signal, terminal: false });
        output.write('Owner conversation open.\n');
        for await (const line of lines) output.write(`Soul: received "${line}".\n`);
      },
      stop,
    };
  },
};

process.exitCode = await runSoulCli(process.argv.slice(2), handlers);
