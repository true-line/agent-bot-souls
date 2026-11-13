// One JSON value per line, in both directions. Used for HQ's sockets, the
// member socket and JSON-RPC over stdio (ACP).
export const MAX_LINE_BYTES = 1 << 20;

// Call `onLine(text)` for each complete line on a raw byte stream. Decode
// incrementally and fatally: replacement decoding before strict JSON would
// turn an invalid wire message into different, apparently valid content.
// `false` from onLine stops all delivery, including later same-chunk lines.
// Errors latch even when onError leaves the stream open.
export function readLines(stream, onLine, onError = () => {}) {
  let buf = '';
  let stopped = false;
  // ignoreBOM preserves U+FEFF, so the strict JSON parser can refuse it.
  const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
  const fail = (error) => {
    if (stopped) return;
    stopped = true;
    buf = '';
    onError(error);
  };
  stream.on('data', (chunk) => {
    if (stopped) return;
    try {
      if (typeof chunk === 'string') throw new Error('NDJSON requires raw bytes before UTF-8 decoding');
      buf += decoder.decode(chunk, { stream: true });
    } catch (error) { fail(error); return; }
    let nl;
    while ((nl = buf.indexOf('\n')) !== -1) {
      const line = buf.slice(0, nl);
      buf = buf.slice(nl + 1);
      if (Buffer.byteLength(line) > MAX_LINE_BYTES) { fail(new Error(`line exceeds ${MAX_LINE_BYTES} bytes`)); return; }
      if (!/^[ \t\r]*$/.test(line)) {
        let result;
        try { result = onLine(line); }
        catch (error) { fail(error); return; }
        if (result === false || stream.destroyed) { stopped = true; buf = ''; return; }
      }
    }
    if (Buffer.byteLength(buf) > MAX_LINE_BYTES) fail(new Error(`line exceeds ${MAX_LINE_BYTES} bytes`));
  });
  stream.on('end', () => {
    if (stopped) return;
    try {
      buf += decoder.decode(); // A truncated final character is an error.
      if (!/^[ \t\r]*$/.test(buf)) throw new Error('NDJSON ended before the line terminator');
    } catch (error) { fail(error); }
  });
}

export const writeLine = (stream, value) => {
  if (!stream.destroyed && stream.writable) stream.write(`${JSON.stringify(value)}\n`);
};
