// The same strict local line codec serves HQ/member sockets and ACP stdio.
// This is local NDJSON, separate from comms wire/v1 framing.
export { MAX_LINE_BYTES, readLines, writeLine } from './vendor/agent-bot-sdk/local-socket-lines.mjs';
