// The Soul's front door (seam `acp-front-door`): one conversation with the
// owner, as an ACP agent on stdio for editors and tools, or as a terminal
// chat. Both are the same thing underneath: a prompt is one turn of the
// lead, and the lead's reply is streamed back. Every ACP session is a new
// session of the same Soul, never a new Soul.
import { randomBytes } from 'node:crypto';
import { createInterface } from 'node:readline';
import { ACP_PROTOCOL_VERSION, SoulUnavailable } from './entry-point.mjs';
import { INVALID_PARAMS, rpcPeer, RpcError } from './jsonrpc.mjs';

// Serve ACP on a pair of streams. Resolves when the client disconnects.
export function serveAcp({ soul, input, output }) {
  const sessions = new Set();
  return new Promise((resolve) => {
    const peer = rpcPeer({
      input,
      output,
      onClose: () => resolve(),
      methods: {
        initialize: async () => ({
          protocolVersion: ACP_PROTOCOL_VERSION,
          agentCapabilities: { loadSession: false, promptCapabilities: { image: false, audio: false, embeddedContext: false } },
          authMethods: [],
        }),
        'session/new': async () => {
          const sessionId = `sess_${randomBytes(8).toString('hex')}`;
          sessions.add(sessionId);
          return { sessionId };
        },
        'session/prompt': async (params) => {
          const sessionId = params?.sessionId;
          if (!sessions.has(sessionId)) throw new RpcError(INVALID_PARAMS, 'unknown session');
          const blocks = params?.prompt;
          if (!Array.isArray(blocks) || blocks.length === 0 || !blocks.every((b) => b?.type === 'text' && typeof b.text === 'string')) throw new RpcError(INVALID_PARAMS, 'a prompt is a list of text blocks');
          const say = (text) => peer.notify('session/update', { sessionId, update: { sessionUpdate: 'agent_message_chunk', content: { type: 'text', text } } });
          try {
            const result = await soul.prompt(blocks.map((b) => b.text).join('\n'), say);
            return { stopReason: result.stop_reason };
          } catch (e) {
            if (!(e instanceof SoulUnavailable)) throw e;
            say(e.message);
            return { stopReason: 'refusal' };
          }
        },
        'session/cancel': async () => { soul.cancel(); },
      },
    });
  });
}

// A terminal chat: each line is a prompt. `/status` prints the Soul's
// state, `/release` releases a quarantined Soul, `/quit` ends the chat.
export async function chat({ soul, input, output }) {
  const rl = createInterface({ input, terminal: false });
  const tty = Boolean(output.isTTY);
  if (tty) output.write('> ');
  for await (const raw of rl) {
    const line = raw.trim();
    if (line === '/quit') break;
    if (line === '/status') output.write(`${JSON.stringify(soul.status(), null, 2)}\n`);
    else if (line === '/release') { soul.release(); output.write('released\n'); }
    else if (line) {
      try {
        const result = await soul.prompt(line, (text) => output.write(text));
        output.write(result.text.endsWith('\n') ? '' : '\n');
      } catch (e) {
        output.write(`${e.message}\n`);
      }
    }
    if (tty) output.write('> ');
  }
}
