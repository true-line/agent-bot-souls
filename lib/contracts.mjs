// Runtime contract boundary. Schemas stay in soul-contracts, not this tree.
// Installation prepares the pinned release once; runtime use is offline and
// refuses a missing, changed or incomplete dependency before opening sockets.
import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalDigest } from './vendor/agent-bot-sdk/wire/canonical-json.mjs';
import { validate } from './vendor/agent-bot-sdk/wire/schema.mjs';
import { parseStrict } from './vendor/agent-bot-sdk/wire/strict-json.mjs';
import { checkRequiredCapabilities, negotiateVersions } from './vendor/agent-bot-sdk/wire/versions.mjs';

export { canonicalDigest, canonicalize } from './vendor/agent-bot-sdk/wire/canonical-json.mjs';
export { parseStrict } from './vendor/agent-bot-sdk/wire/strict-json.mjs';
export { checkRequiredCapabilities, negotiateVersions } from './vendor/agent-bot-sdk/wire/versions.mjs';

export const CONTRACT_PIN = Object.freeze(JSON.parse(readFileSync(new URL('../governance/soul-contracts.json', import.meta.url), 'utf8')));
export const DEFAULT_CONTRACTS_DIRECTORY = fileURLToPath(new URL(`../node_modules/.cache/soul-contracts-${CONTRACT_PIN.commit}/`, import.meta.url));
export const SUPPORTED_VERSIONS = Object.freeze({ hq: Object.freeze([1]), wire: Object.freeze([1]), task: Object.freeze([1]) });
export const SCHEMAS = Object.freeze({
  hello: 'hq/v1/hello.schema.json', admission: 'hq/v1/admission-result.schema.json',
  equip: 'hq/v1/equip.schema.json', renewal: 'hq/v1/ready-and-lease-renewal.schema.json',
  refusal: 'common/v1/error-response.schema.json', task: 'task/v1/task-record.schema.json',
  commitment: 'task/v1/task-commitment.schema.json', directive: 'wire/v1/directive-or-query.schema.json',
  note: 'records/v1/typed-note.schema.json', frame: 'wire/v1/wire-frame.schema.json',
});

export class ContractError extends Error {
  constructor(message, { code = 'souls.invalid_contract', schema, violations } = {}) {
    super(message); this.name = 'ContractError'; this.code = code;
    if (schema) this.schema = schema;
    if (violations) this.violations = violations;
  }
}

const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');

// Return exactly the regular files the manifest pins. Symlinks are never
// followed: a deployment cannot redirect a schema or a containing directory.
export function verifyContractTree(directory) {
  const entries = new Map();
  const walk = (rel) => {
    const path = join(directory, rel);
    const st = lstatSync(path);
    if (st.isDirectory()) {
      for (const name of readdirSync(path).sort()) walk(`${rel}/${name}`);
    } else {
      if (!st.isFile()) throw new Error(`${rel}: dependency contains a non-regular file`);
      entries.set(rel, { bytes: readFileSync(path), mode: st.mode & 0o111 ? '100755' : '100644' });
    }
  };
  try {
    if (!lstatSync(directory).isDirectory()) throw new Error('dependency root is not a directory');
    for (const rel of CONTRACT_PIN.paths) walk(rel);
    const manifest = Object.fromEntries([...entries].map(([path, { bytes, mode }]) => [path, { sha256: hash(bytes), size: bytes.length, mode }]));
    if (entries.size !== CONTRACT_PIN.files || canonicalDigest(manifest) !== CONTRACT_PIN.digest) throw new Error('content or mode does not match the release manifest');
    return entries;
  } catch (error) {
    throw new ContractError(`soul-contracts ${CONTRACT_PIN.tag} unavailable at ${directory}: ${error.message}; run npm run prepare:contracts or set AGENT_BOT_SOUL_CONTRACTS to the verified release directory`, { code: 'souls.contracts_unavailable' });
  }
}

export function loadContracts({ directory = process.env.AGENT_BOT_SOUL_CONTRACTS || DEFAULT_CONTRACTS_DIRECTORY } = {}) {
  const entries = verifyContractTree(directory);
  const schemas = new Map([...entries].filter(([path]) => path.startsWith('schemas/') && path.endsWith('.schema.json'))
    .map(([path, { bytes }]) => [path.slice('schemas/'.length), parseStrict(bytes)]));
  const record = (schema, value) => {
    const definition = schemas.get(schema);
    if (!definition) throw new ContractError(`no pinned schema ${schema}`, { schema });
    const violations = validate(definition, value);
    if (violations.length) throw new ContractError(`${schema}: ${violations[0].keyword} at ${violations[0].path}`, { schema, violations });
    return value;
  };
  return Object.freeze({
    directory, record,
    decode: (schema, text) => record(schema, parseStrict(text)),
    // A receiver checks negotiation independently of HQ. It neither admits
    // a Soul nor invents authority: an unsupported reply is unusable data.
    admission(result, hello) {
      record(SCHEMAS.admission, result);
      if (result.request_id !== hello.request_id) throw new ContractError('HQ admission does not answer this Hello');
      for (const [name, version] of Object.entries(result.negotiated_versions)) {
        negotiateVersions({ [name]: [version] }, { [name]: SUPPORTED_VERSIONS[name] ?? [] }, { required: [name] });
        if (!hello.supported_versions[name]?.includes(version)) throw new ContractError(`HQ selected an unoffered ${name} version`, { code: 'unsupported_version' });
      }
      return result;
    },
    frame(value, negotiatedCapabilities = []) {
      record(SCHEMAS.frame, value);
      negotiateVersions({ wire: [value.wire_version] }, { wire: SUPPORTED_VERSIONS.wire }, { required: ['wire'] });
      checkRequiredCapabilities(value.required_capabilities, negotiatedCapabilities);
      return value;
    },
  });
}
