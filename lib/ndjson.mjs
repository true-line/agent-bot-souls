// One JSON value per line, in both directions. Used for HQ's sockets, the
// member socket and JSON-RPC over stdio (ACP).
export const MAX_LINE_BYTES = 1 << 20;

// Call `onLine(text)` for each complete line on `stream`. A line longer than
// the limit ends the stream through `onError`.
export function readLines(stream, onLine, onError = () => {}) {
  let buf = '';
  stream.setEncoding('utf8');
  stream.on('data', (chunk) => {
    buf += chunk;
    let nl;
    while ((nl = buf.indexOf('\n')) !== -1) {
      const line = buf.slice(0, nl);
      buf = buf.slice(nl + 1);
      if (Buffer.byteLength(line) > MAX_LINE_BYTES) { buf = ''; onError(new Error(`line exceeds ${MAX_LINE_BYTES} bytes`)); return; }
      if (line.trim()) onLine(line);
    }
    if (Buffer.byteLength(buf) > MAX_LINE_BYTES) { buf = ''; onError(new Error(`line exceeds ${MAX_LINE_BYTES} bytes`)); }
  });
}

export const writeLine = (stream, value) => {
  if (!stream.destroyed && stream.writable) stream.write(`${JSON.stringify(value)}\n`);
};
