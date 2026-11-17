// Narrow member-side bootstrap. The existing entry point still issues and
// revokes the member token and supplies the current runtime binding.
import { openMemberSession } from './member-session.mjs';
import { createMemberQueryPort } from './member-query.mjs';

export async function connectMemberQueries(options) {
  const signal = options?.signal;
  const session = await openMemberSession(options);
  try {
    signal?.throwIfAborted();
    return Object.freeze({ queries: createMemberQueryPort(session), close: session.close });
  } catch (error) {
    await session.close().catch(() => {});
    throw error;
  }
}
