// The recovery ladder (0.4 §9; platform lifecycle). The entry point first
// classifies a failure, then takes the rung for that class:
//
//   crash                    restart the same member after 5 s, 30 s, 2 min,
//                            then 10 min; five crashes in an hour quarantine
//                            the Soul
//   auth                     ask HQ to re-equip; a second failure in a row
//                            is the owner's decision
//   provider                 fail over to the owner's next route, never
//                            restart a healthy process; a route is used only
//                            if it may receive the active work's data
//   credential_unavailable   an identity-service outage is not a member
//                            failure: wait, with no restart and no fail-over
//   unknown_outcome          reconcile by looking the operation up; never
//                            replay it under a new key
//
// This module decides and holds the counters. It starts nothing itself, so
// it can be tested with a clock and no processes.
export const BACKOFF_MS = Object.freeze([5_000, 30_000, 120_000, 600_000]);
export const QUARANTINE = Object.freeze({ crashes: 5, windowMs: 3_600_000 });
export const FAILURES = Object.freeze(['crash', 'auth', 'provider', 'credential_unavailable', 'unknown_outcome']);

// ACP's "authentication required" error code.
const ACP_AUTH_REQUIRED = -32000;

// What kind of failure is this? `exit` is a member process that ended;
// `rpc` is an error an adapter returned for a turn. An adapter names a
// provider outage or a missing credential in the error's `data.failure`.
// Returns undefined for an error that is not a member failure, such as a
// refused prompt.
export function classify(failure) {
  if (failure?.kind === 'exit') return 'crash';
  if (failure?.kind === 'transport') return 'unknown_outcome';
  if (failure?.kind === 'rpc') {
    if (failure.code === ACP_AUTH_REQUIRED) return 'auth';
    if (failure.data?.failure === 'provider_unavailable') return 'provider';
    if (failure.data?.failure === 'credential_unavailable') return 'credential_unavailable';
  }
  return undefined;
}

const covers = (accepts, labels) => labels.every((l) => accepts.includes(l));

export function createLadder({ clock = { now: () => Date.now() } } = {}) {
  const crashes = [];              // times of every member crash, for the Soul
  const consecutive = new Map();   // member → crashes in a row
  const authFailures = new Map();  // member → auth failures in a row
  let quarantined = false;

  return {
    get quarantined() { return quarantined; },
    // A member finished a turn: its failures in a row start again.
    healthy(memberId) { consecutive.delete(memberId); authFailures.delete(memberId); },
    // The owner reviewed the Soul and released it.
    release() { quarantined = false; crashes.length = 0; consecutive.clear(); authFailures.clear(); },
    // The rung for this failure. `routes` is the member's fail-over order,
    // `route` the index in use, and `restrictions` the labels of the active
    // work.
    next(failureClass, { memberId, routes = [], route = 0, restrictions = [] } = {}) {
      if (quarantined) return { action: 'quarantine' };
      switch (failureClass) {
        case 'crash': {
          const now = clock.now();
          crashes.push(now);
          while (crashes.length && crashes[0] <= now - QUARANTINE.windowMs) crashes.shift();
          if (crashes.length >= QUARANTINE.crashes) { quarantined = true; return { action: 'quarantine' }; }
          const n = (consecutive.get(memberId) ?? 0) + 1;
          consecutive.set(memberId, n);
          return { action: 'restart', delayMs: BACKOFF_MS[Math.min(n, BACKOFF_MS.length) - 1] };
        }
        case 'auth': {
          const n = (authFailures.get(memberId) ?? 0) + 1;
          authFailures.set(memberId, n);
          return n === 1 ? { action: 're-equip' } : { action: 'owner-decision', reason: 'authentication failed again after HQ re-equipped the member' };
        }
        case 'provider': {
          const later = routes.map((r, i) => ({ r, i })).filter(({ i }) => i > route);
          if (later.length === 0) return { action: 'unavailable', reason: 'no fail-over route is configured' };
          const allowed = later.find(({ r }) => covers(r.accepts ?? [], restrictions));
          if (!allowed) return { action: 'pause', reason: 'no fail-over route may receive the active work\'s data' };
          return { action: 'fail-over', route: allowed.i };
        }
        case 'credential_unavailable':
          return { action: 'wait', reason: 'credential_unavailable' };
        case 'unknown_outcome':
          return { action: 'reconcile' };
        default:
          return { action: 'none' };
      }
    },
  };
}
