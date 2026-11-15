// A member-side capability, not a transport or an HQ authority service.
// The transport owner privately captures one authenticated connection together
// with the runtime freshness that connection bound. Only that pair may send.
const KIND = /^[a-z][a-z0-9_.-]{0,63}$(?![\s\S])/;
const READS = new Set(['task.get', 'task.directives', 'notices.peek']);
const plain = (value) => value !== null && typeof value === 'object' && !Array.isArray(value)
  && [Object.prototype, null].includes(Object.getPrototypeOf(value));

function snapshot(captured) {
  if (!plain(captured) || !Object.isFrozen(captured) || typeof captured.request !== 'function') throw new TypeError('member query driver must capture a frozen bound attempt');
  const freshness = captured.freshness;
  if (!plain(freshness) || !Object.isFrozen(freshness)
    || !Number.isSafeInteger(freshness.installation_epoch) || freshness.installation_epoch < 1
    || !Number.isSafeInteger(freshness.lease_generation) || freshness.lease_generation < 1) throw new TypeError('member query capture needs immutable positive epoch and generation');
  // Never pass a runtime record, connection, credential or private driver
  // object to a member-surface builder, even if the driver holds extra fields.
  return Object.freeze({ installation_epoch: freshness.installation_epoch, lease_generation: freshness.lease_generation });
}

export function createMemberQueryPort(driver) {
  if (!plain(driver) || ['capture', 'reconnect', 'isRetryableReadFailure'].some((key) => typeof driver[key] !== 'function')) throw new TypeError('member query port needs a private capture/reconnect/refusal driver');
  // Capture the trusted methods once. The exposed port never returns driver
  // state, binding material or a split currentRuntime/request capability.
  const capture = driver.capture.bind(driver);
  const reconnect = driver.reconnect.bind(driver);
  const retryable = driver.isRetryableReadFailure.bind(driver);
  return Object.freeze({
    async request(kind, buildPayload, options = {}) {
      if (typeof kind !== 'string' || !KIND.test(kind) || typeof buildPayload !== 'function') throw new TypeError('member query requires a kind and synchronous payload builder');
      if (!plain(options) || Object.keys(options).some((key) => key !== 'replay')) throw new TypeError('member query replay is never or read-once');
      const replay = Object.hasOwn(options, 'replay') ? options.replay : 'never';
      if (!['never', 'read-once', undefined].includes(replay)) throw new TypeError('member query replay is never or read-once');
      // This fixed allowlist cannot be widened by a caller or driver. In
      // particular, consume-one and task.commit always get one send at most.
      const canReplay = replay === 'read-once' && READS.has(kind);
      let captured = await capture();
      for (let attempt = 0; ; attempt++) {
        const freshness = snapshot(captured);
        const send = captured.request.bind(captured);
        const payload = buildPayload(freshness);
        if (payload && typeof payload.then === 'function') {
          // Do not await an async builder, or leave a rejected promise unobserved.
          Promise.resolve(payload).catch(() => {});
          throw new TypeError('member query payload builder must be synchronous');
        }
        if (!plain(payload)) throw new TypeError('member query payload must be an object');
        // Builder/clone failures are not transport failures and never recover.
        const message = structuredClone(payload);
        try { return await send(kind, message); }
        catch (error) {
          if (!canReplay || attempt !== 0) throw error;
          let allowed = false;
          try {
            const decision = retryable(error, captured);
            if (decision && typeof decision.then === 'function') Promise.resolve(decision).catch(() => {});
            allowed = decision === true;
          } catch { /* fail closed */ }
          if (!allowed) throw error;
          // The owner must preserve a newer concurrent binding and return its
          // pair rather than destroying it while recovering an older attempt.
          captured = await reconnect(captured, error);
        }
      }
    },
  });
}
