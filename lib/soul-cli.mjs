// Package operations are supplied by the package and harness integrations.
const commands = {
  create: {
    usage: 'soul create PATH --orchestrator HARNESS',
    description: 'Create a Soul at a new path and save its founding harness choice. The harness can be installed later.',
  },
  inspect: {
    usage: 'soul inspect PATH',
    description: 'Read the package and report validity, trust, and local readiness. Inspection never provisions or launches a harness.',
  },
  start: {
    usage: 'soul start PATH',
    description: "Open the owner's conversation in the foreground. EOF (exit 0) or Ctrl-C (exit 130) stops its children and releases the instance for restart. A second local start is refused while the first owns it.",
  },
};

const usage = Object.values(commands).map(({ usage }) => '  ' + usage).join('\n');
const isHelp = (arg) => arg === '--help' || arg === '-h';

function parseArgs(verb, [path, ...rest]) {
  if (!path || path.startsWith('-')) throw new Error('supply a PATH (quote paths containing spaces)');
  if (verb === 'create') {
    if (rest[0] !== '--orchestrator' || !rest[1]?.trim() || rest[1].startsWith('-')) {
      throw new Error('supply --orchestrator HARNESS to choose the founding harness');
    }
    if (rest.length > 2) throw new Error(`unexpected argument ${rest[2]}`);
    return { path, orchestrator: rest[1] };
  }
  if (rest.length) throw new Error(`unexpected argument ${rest[0]}`);
  return { path };
}

// A start handler acquires the local writer before launching. Its conversation
// resolves on EOF and observes signal during input and pending turns. stop()
// waits for all owned children and releases the writer, including on failure.
async function foreground(start, args, input, output) {
  const interrupt = new AbortController();
  const cancel = () => interrupt.abort();
  process.on('SIGINT', cancel);
  try {
    let session;
    try {
      session = await start({ ...args, signal: interrupt.signal });
      if (!interrupt.signal.aborted) await session.converse({ input, output, signal: interrupt.signal });
    } catch (error) {
      if (!interrupt.signal.aborted || error !== interrupt.signal.reason) throw error;
    } finally {
      if (session) await session.stop();
    }
  } finally {
    process.off('SIGINT', cancel);
  }
  return interrupt.signal.aborted ? 130 : 0;
}

export async function runSoulCli([verb, ...rest], handlers = {}, {
  input = process.stdin, output = process.stdout, errorOutput = process.stderr,
} = {}) {
  if (isHelp(verb) && !rest.length) {
    output.write(`Usage:\n${usage}\n\nUse soul COMMAND --help for details.\n`);
    return 0;
  }
  if (!Object.hasOwn(commands, verb)) {
    errorOutput.write(`soul: ${verb ? `unknown command '${verb}'` : 'supply a command'}. Use soul --help.\n`);
    return 2;
  }
  const command = commands[verb];
  if (rest.length === 1 && isHelp(rest[0])) {
    output.write(`${command.usage}\n\n${command.description}\n`);
    return 0;
  }
  let args;
  try {
    args = parseArgs(verb, rest);
  } catch (error) {
    errorOutput.write(`soul ${verb}: ${error.message}\nUsage: ${command.usage}\n`);
    return 2;
  }
  try {
    const handler = handlers[verb];
    if (!handler) throw new Error('unavailable in this build');
    if (verb === 'start') return await foreground(handler, args, input, output);
    const result = await handler(args);
    if (verb === 'create') {
      output.write(`Created ${args.path} with founding harness ${args.orchestrator}.\n`);
    } else {
      output.write(`Validity: ${result.validity}\nTrust: ${result.trust}\nLocal readiness: ${result.readiness}\n`);
    }
    return 0;
  } catch (error) {
    errorOutput.write(`soul ${verb}: ${error.message}\n`);
    return 1;
  }
}
