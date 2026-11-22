// Keep the protected control process within the last A-signed Live deadline.
// The renewal callback must return a lease already verified by protected-live.
export function watchProtectedLease(first, { renew, stop, now = Date.now, intervalMs = 2_000 } = {}) {
  if (!first || !Number.isSafeInteger(first.expiresAtMs) || first.expiresAtMs <= now()
    || typeof renew !== 'function' || typeof stop !== 'function'
    || !Number.isSafeInteger(intervalMs) || intervalMs < 1 || intervalMs > 2_000) {
    throw new TypeError('protected lease watchdog requires a current signed lease and stop path');
  }
  let current = first;
  let timer;
  let renewalTimer;
  let closed = false;
  let stopping;
  let finish;
  const done = new Promise((resolve) => { finish = resolve; });
  const halt = (reason) => {
    if (stopping) return stopping;
    closed = true;
    clearTimeout(timer); clearTimeout(renewalTimer);
    stopping = Promise.resolve().then(() => stop(reason)).then(
      () => ({ reason, stopError: null }),
      (stopError) => ({ reason, stopError }),
    );
    stopping.then(finish);
    return stopping;
  };
  const arm = () => {
    clearTimeout(timer); clearTimeout(renewalTimer);
    const remaining = current.expiresAtMs - now();
    if (remaining <= 0) { void halt('signed lease expired'); return; }
    timer = setTimeout(() => { void halt('signed lease expired'); }, remaining);
    // Renew before expiry, but the expiry timer remains armed even while a
    // stalled HQ/Machine request is pending.
    const delay = Math.min(intervalMs, Math.max(0, remaining - 1_000));
    renewalTimer = setTimeout(async () => {
      try {
        const next = await renew(current);
        if (closed) return;
        if (!next || !Number.isSafeInteger(next.expiresAtMs)
          || next.sequence <= current.sequence || next.expiresAtMs <= now()
          || next.expiresAtMs > now() + 5_000) {
          await halt('signed lease renewal invalid'); return;
        }
        current = next;
        arm();
      } catch { await halt('signed lease renewal failed'); }
    }, delay);
  };
  arm();
  return Object.freeze({ done, stop: () => halt('protected control stopped'), current: () => current });
}
