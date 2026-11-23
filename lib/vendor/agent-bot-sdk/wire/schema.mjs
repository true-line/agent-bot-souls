// A JSON Schema (draft 2020-12) validator for the keywords the pinned
// soul-contracts schemas use, and no others. References resolve only against
// the caller's verified, offline schema registry. Unknown keywords and
// unresolved references are refused rather than half-checked (fail closed).
//
// `format: date-time` is asserted (RFC 3339), because records carry
// timestamps that HQ compares.

const ANNOTATIONS = new Set(['$schema', '$id', '$comment', 'title', 'description', 'examples', 'default', 'contentEncoding']);
const ASSERTIONS = new Set([
  'type', 'enum', 'const', 'properties', 'patternProperties', 'required', 'dependentRequired', 'additionalProperties', 'minProperties',
  'prefixItems', 'items', 'minItems', 'maxItems', 'uniqueItems', 'contains', 'minContains', 'maxContains',
  'minLength', 'maxLength', 'pattern', 'format', 'minimum', 'maximum', 'if', 'then', 'else',
  'maxProperties', '$ref', '$defs', 'allOf', 'anyOf', 'oneOf', 'not',
]);
const DATE_TIME = /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(\.\d+)?([Zz]|[+-](\d{2}):(\d{2}))$/;
const DIALECT = 'https://json-schema.org/draft/2020-12/schema';
// RFC 3986 generic URI grammar. Scheme-specific reachability is not asserted.
const URI_UNRESERVED = '[A-Za-z0-9._~-]';
const URI_PCT = '%[0-9A-Fa-f]{2}';
const URI_SUBDELIMS = "[!$&'()*+,;=]";
const URI_PCHAR = `(?:${URI_UNRESERVED}|${URI_PCT}|${URI_SUBDELIMS}|[:@])`;
const uriPart = (part) => new RegExp(`^(?:${part})*$`);
const URI_QUERY = uriPart(`${URI_PCHAR}|[/?]`);
const URI_REG_NAME = uriPart(`${URI_UNRESERVED}|${URI_PCT}|${URI_SUBDELIMS}`);
const URI_USERINFO = uriPart(`${URI_UNRESERVED}|${URI_PCT}|${URI_SUBDELIMS}|:`);
const URI_PATH_ABEMPTY = new RegExp(`^(?:/${URI_PCHAR}*)*$`);
const URI_PATH_ABSOLUTE = new RegExp(`^/(?:${URI_PCHAR}+(?:/${URI_PCHAR}*)*)?$`);
const URI_PATH_ROOTLESS = new RegExp(`^(?:${URI_PCHAR}+(?:/${URI_PCHAR}*)*)?$`);
const URI_IPVFUTURE = new RegExp(`^[vV][0-9A-Fa-f]+\\.(?:${URI_UNRESERVED}|${URI_SUBDELIMS}|:)+$`);

const typeOf = (v) => {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'array';
  if (typeof v === 'number') return Number.isInteger(v) ? 'integer' : 'number';
  return typeof v;
};
const isType = (v, t) => (t === 'number' ? typeof v === 'number' && Number.isFinite(v) : typeOf(v) === t);
const isObject = (v) => typeOf(v) === 'object';

// Structural equality for enum, const and uniqueItems (key order ignored).
function equal(a, b) {
  if (a === b) return true;
  if (typeOf(a) !== typeOf(b) || typeof a !== 'object' || a === null) return false;
  if (Array.isArray(a)) return a.length === b.length && a.every((x, i) => equal(x, b[i]));
  const ka = Object.keys(a);
  return ka.length === Object.keys(b).length && ka.every((k) => Object.hasOwn(b, k) && equal(a[k], b[k]));
}

function validDateTime(s) {
  const m = DATE_TIME.exec(s);
  if (!m) return false;
  const [, y, mo, d, h, mi, sec, , , oh, om] = m;
  const days = new Date(Date.UTC(+y, +mo, 0)).getUTCDate();
  return +mo >= 1 && +mo <= 12 && +d >= 1 && +d <= days && +h <= 23 && +mi <= 59 && +sec <= 60 && (oh === undefined || (+oh <= 23 && +om <= 59));
}

function validUri(s) {
  const colon = s.indexOf(':');
  if (colon < 1 || !/^[A-Za-z][A-Za-z0-9+.-]*$/.test(s.slice(0, colon))) return false;
  let hier = s.slice(colon + 1);
  const hash = hier.indexOf('#');
  if (hash >= 0) {
    if (!URI_QUERY.test(hier.slice(hash + 1))) return false;
    hier = hier.slice(0, hash);
  }
  const query = hier.indexOf('?');
  if (query >= 0) {
    if (!URI_QUERY.test(hier.slice(query + 1))) return false;
    hier = hier.slice(0, query);
  }
  if (!hier.startsWith('//')) return hier.startsWith('/') ? URI_PATH_ABSOLUTE.test(hier) : URI_PATH_ROOTLESS.test(hier);
  const rest = hier.slice(2);
  const slash = rest.indexOf('/');
  const authority = slash < 0 ? rest : rest.slice(0, slash);
  if (!URI_PATH_ABEMPTY.test(slash < 0 ? '' : rest.slice(slash))) return false;
  const at = authority.indexOf('@');
  if (at >= 0 && (!URI_USERINFO.test(authority.slice(0, at)) || authority.indexOf('@', at + 1) >= 0)) return false;
  const hostPort = authority.slice(at + 1);
  if (hostPort.startsWith('[')) {
    const close = hostPort.indexOf(']');
    if (close < 0 || !/^(?::[0-9]*)?$/.test(hostPort.slice(close + 1))) return false;
    const literal = hostPort.slice(1, close);
    if (URI_IPVFUTURE.test(literal)) return true;
    try { new URL(`http://[${literal}]/`); return true; } catch { return false; }
  }
  const port = hostPort.lastIndexOf(':');
  const host = port < 0 ? hostPort : hostPort.slice(0, port);
  return URI_REG_NAME.test(host) && (port < 0 || /^[0-9]*$/.test(hostPort.slice(port + 1)));
}

const patterns = new Map();
const regex = (p) => {
  if (!patterns.has(p)) patterns.set(p, new RegExp(p, 'u'));
  return patterns.get(p);
};

function registryFor(schema, schemas) {
  const registry = new Map();
  for (const document of schemas) {
    if (!isObject(document) || typeof document.$id !== 'string') throw new TypeError('registry schemas require a top-level $id');
    const id = new URL(document.$id);
    if (id.hash || registry.has(id.href)) throw new TypeError(`duplicate or fragment schema ID ${document.$id}`);
    registry.set(id.href, document);
  }
  if (isObject(schema) && typeof schema.$id === 'string') {
    const id = new URL(schema.$id);
    if (id.hash) throw new TypeError(`fragment schema ID ${schema.$id}`);
    const prior = registry.get(id.href);
    if (prior && !equal(prior, schema)) throw new TypeError(`conflicting schema ID ${schema.$id}`);
    if (!prior) registry.set(id.href, schema);
  }
  return registry;
}

function resolveRef(ref, root, registry, where) {
  if (typeof ref !== 'string') throw new TypeError(`${where}: $ref must be a string`);
  let url;
  try { url = new URL(ref, root?.$id); } catch { throw new TypeError(`${where}: unresolved reference ${ref}`); }
  const fragment = decodeURIComponent(url.hash.slice(1));
  url.hash = '';
  const document = registry.get(url.href);
  if (!document) throw new TypeError(`${where}: unresolved reference ${ref}`);
  if (fragment && !fragment.startsWith('/')) throw new TypeError(`${where}: unsupported reference fragment ${ref}`);
  let target = document;
  for (const token of fragment ? fragment.slice(1).split('/') : []) {
    if (/~(?![01])/.test(token)) throw new TypeError(`${where}: malformed reference ${ref}`);
    const key = token.replace(/~1/g, '/').replace(/~0/g, '~');
    if (target === null || typeof target !== 'object' || !Object.hasOwn(target, key)) throw new TypeError(`${where}: unresolved reference ${ref}`);
    target = target[key];
  }
  return { target, document, key: `${url.href}#${fragment}` };
}

// Throws on a schema this validator cannot fully check. Inspect unreachable
// $defs as well as branches reached by references, so additions fail loudly.
export function checkSchemaSupported(schema, where = '#', { schemas = [] } = {}) {
  const registry = registryFor(schema, schemas);
  const active = new Set();
  const check = (node, path, root) => {
    if (typeof node === 'boolean') return;
    if (!isObject(node)) throw new TypeError(`${path}: a schema is an object or a boolean`);
    if (node !== root && Object.hasOwn(node, '$id')) throw new TypeError(`${path}: nested $id is not supported`);
    for (const [k, v] of Object.entries(node)) {
      if (k === '$schema' && (node !== root || v !== DIALECT)) throw new TypeError(`${path}: unsupported schema dialect ${v}`);
      if (ANNOTATIONS.has(k)) continue;
      if (!ASSERTIONS.has(k)) throw new TypeError(`${path}: keyword ${k} is not supported by the SDK validator`);
      if (k === 'properties' || k === 'patternProperties' || k === '$defs') {
        if (!isObject(v)) throw new TypeError(`${path}/${k}: expected object`);
        for (const [p, s] of Object.entries(v)) {
          if (k === 'patternProperties') regex(p);
          check(s, `${path}/${k}/${p}`, root);
        }
      }
      if (['additionalProperties', 'items', 'contains', 'if', 'then', 'else', 'not'].includes(k)) check(v, `${path}/${k}`, root);
      if (k === 'prefixItems') {
        if (!Array.isArray(v) || v.length === 0) throw new TypeError(`${path}/${k}: expected non-empty array`);
        v.forEach((subschema, i) => check(subschema, `${path}/${k}/${i}`, root));
      }
      if (k === 'dependentRequired') {
        if (!isObject(v)) throw new TypeError(`${path}/${k}: expected object`);
        for (const [property, dependencies] of Object.entries(v)) {
          if (!Array.isArray(dependencies) || dependencies.length === 0
            || dependencies.some((name) => typeof name !== 'string')
            || new Set(dependencies).size !== dependencies.length)
            throw new TypeError(`${path}/${k}/${property}: expected non-empty unique string array`);
        }
      }
      if (['allOf', 'anyOf', 'oneOf'].includes(k)) {
        if (!Array.isArray(v) || v.length === 0) throw new TypeError(`${path}/${k}: expected non-empty array`);
        v.forEach((s, i) => check(s, `${path}/${k}/${i}`, root));
      }
      if (k === '$ref') {
        const resolved = resolveRef(v, root, registry, path);
        if (active.has(resolved.key)) throw new TypeError(`${path}: cyclic reference ${v}`);
        active.add(resolved.key);
        check(resolved.target, resolved.key, resolved.document);
        active.delete(resolved.key);
      }
      if (k === 'format' && !['date-time', 'uri'].includes(v)) throw new TypeError(`${path}: format ${v} is not supported`);
      if (k === 'pattern') regex(v);
    }
  };
  check(schema, where, schema);
}

// Returns a list of { path, keyword, message }; empty means valid.
export function validate(schema, value, { schemas = [] } = {}) {
  checkSchemaSupported(schema, '#', { schemas });
  const registry = registryFor(schema, schemas);
  const errors = [];
  walk(schema, value, '', errors, schema, registry);
  return errors;
}

function walk(schema, v, path, errors, root, registry) {
  if (schema === true) return;
  const err = (keyword, message) => errors.push({ path: path || '/', keyword, message });
  if (schema === false) { err('false', 'no value is allowed here'); return; }
  const s = schema;
  if (s.$ref !== undefined) {
    const resolved = resolveRef(s.$ref, root, registry, path || '#');
    walk(resolved.target, v, path, errors, resolved.document, registry);
  }
  const matches = (part) => { const e = []; walk(part, v, path, e, root, registry); return e.length === 0; };
  if (s.allOf) s.allOf.forEach((part) => walk(part, v, path, errors, root, registry));
  if (s.anyOf && !s.anyOf.some(matches)) err('anyOf', 'no branch matches');
  if (s.oneOf && s.oneOf.filter(matches).length !== 1) err('oneOf', 'exactly one branch must match');
  if (s.not !== undefined && matches(s.not)) err('not', 'forbidden schema matches');
  if (s.type !== undefined) {
    const types = Array.isArray(s.type) ? s.type : [s.type];
    if (!types.some((t) => isType(v, t) || (t === 'number' && typeOf(v) === 'integer'))) { err('type', `expected ${types.join(' or ')}, got ${typeOf(v)}`); return; }
  }
  if (s.enum !== undefined && !s.enum.some((e) => equal(e, v))) err('enum', `not one of ${JSON.stringify(s.enum)}`);
  if (s.const !== undefined && !equal(s.const, v)) err('const', `must be ${JSON.stringify(s.const)}`);

  if (typeof v === 'string') {
    const len = [...v].length; // code points, per the spec
    if (s.minLength !== undefined && len < s.minLength) err('minLength', `shorter than ${s.minLength}`);
    if (s.maxLength !== undefined && len > s.maxLength) err('maxLength', `longer than ${s.maxLength}`);
    if (s.pattern !== undefined && !regex(s.pattern).test(v)) err('pattern', `does not match ${s.pattern}`);
    if (s.format === 'date-time' && !validDateTime(v)) err('format', 'not an RFC 3339 date-time');
    if (s.format === 'uri' && !validUri(v)) err('format', 'not an absolute URI');
  }
  if (typeof v === 'number') {
    if (s.minimum !== undefined && v < s.minimum) err('minimum', `less than ${s.minimum}`);
    if (s.maximum !== undefined && v > s.maximum) err('maximum', `greater than ${s.maximum}`);
  }
  if (Array.isArray(v)) {
    if (s.minItems !== undefined && v.length < s.minItems) err('minItems', `fewer than ${s.minItems} items`);
    if (s.maxItems !== undefined && v.length > s.maxItems) err('maxItems', `more than ${s.maxItems} items`);
    if (s.uniqueItems && v.some((x, i) => v.findIndex((y) => equal(x, y)) !== i)) err('uniqueItems', 'items are not unique');
    if (s.prefixItems !== undefined) {
      for (let i = 0; i < Math.min(v.length, s.prefixItems.length); i++) {
        walk(s.prefixItems[i], v[i], `${path}/${i}`, errors, root, registry);
      }
    }
    if (s.items !== undefined) {
      for (let i = s.prefixItems?.length ?? 0; i < v.length; i++) {
        walk(s.items, v[i], `${path}/${i}`, errors, root, registry);
      }
    }
    if (s.contains !== undefined) {
      const n = v.filter((x) => { const e = []; walk(s.contains, x, '', e, root, registry); return e.length === 0; }).length;
      const min = s.minContains ?? 1;
      if (n < min) err('contains', `fewer than ${min} matching items`);
      if (s.maxContains !== undefined && n > s.maxContains) err('maxContains', `more than ${s.maxContains} matching items`);
    }
  }
  if (isObject(v)) {
    const keys = Object.keys(v);
    if (s.minProperties !== undefined && keys.length < s.minProperties) err('minProperties', `fewer than ${s.minProperties} properties`);
    if (s.maxProperties !== undefined && keys.length > s.maxProperties) err('maxProperties', `more than ${s.maxProperties} properties`);
    for (const r of s.required ?? []) if (!Object.hasOwn(v, r)) err('required', `missing ${r}`);
    for (const [property, dependencies] of Object.entries(s.dependentRequired ?? {})) {
      if (Object.hasOwn(v, property)) for (const dependency of dependencies) {
        if (!Object.hasOwn(v, dependency)) err('dependentRequired', `${property} requires ${dependency}`);
      }
    }
    const props = s.properties ?? {};
    const patterns = Object.entries(s.patternProperties ?? {}).map(([pattern, subschema]) =>
      [regex(pattern), subschema]);
    for (const k of keys) {
      const p = `${path}/${k.replace(/~/g, '~0').replace(/\//g, '~1')}`;
      if (Object.hasOwn(props, k)) walk(props[k], v[k], p, errors, root, registry);
      let matched = Object.hasOwn(props, k);
      for (const [pattern, subschema] of patterns) {
        if (pattern.test(k)) {
          matched = true;
          walk(subschema, v[k], p, errors, root, registry);
        }
      }
      if (!matched && s.additionalProperties !== undefined) {
        if (s.additionalProperties === false) errors.push({ path: p, keyword: 'additionalProperties', message: `unknown field ${k}` });
        else walk(s.additionalProperties, v[k], p, errors, root, registry);
      }
    }
  }
  if (s.if !== undefined) {
    const e = [];
    walk(s.if, v, path, e, root, registry);
    const branch = e.length === 0 ? s.then : s.else;
    if (branch !== undefined) walk(branch, v, path, errors, root, registry);
  }
}
