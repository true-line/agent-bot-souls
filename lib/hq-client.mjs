// Preserve the Soul runtime's verified-contract default while sharing the
// mechanical local socket implementation with every SDK consumer.
import { loadContracts } from './contracts.mjs';
import { connectHq as sharedConnectHq } from './vendor/agent-bot-sdk/local-socket-client.mjs';
export { HqRefusal, isRetryableMemberReadFailure } from './vendor/agent-bot-sdk/local-socket-client.mjs';

export function connectHq(path, { contracts = loadContracts() } = {}) {
  return sharedConnectHq(path, { contracts });
}
