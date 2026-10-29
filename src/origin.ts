/**
 * Origin parsing and comparison.
 *
 * Every comparison in this tool is made on a parsed (scheme, host, port)
 * triple, never on the raw header string. That is not pedantry: the whole
 * family of CORS validation bugs this tool looks for comes from servers that
 * compare the raw `Origin` string instead of parsing it, so a tool that did
 * the same thing would reproduce the bug rather than find it.
 *
 * The WHATWG `URL` parser normalises more than people expect. It lowercases
 * the scheme and host, strips the port when it is the default for the scheme,
 * converts a unicode host to punycode, rewrites `0177.0.0.1` to `127.0.0.1`,
 * compresses IPv6 literals, and treats backslashes as slashes for special
 * schemes. `parseOriginValue` records whether normalisation changed the input
 * (`canonical: false`), because a divergence between the byte string a server
 * received and the canonical origin is itself a fingerprint of a string-based
 * check. See test/origin.test.ts for each case.
 */

/** Schemes for which the URL Standard defines a tuple origin we care about. */
const TUPLE_SCHEMES = new Set(['http', 'https', 'ws', 'wss']);

/** Default ports stripped by the URL parser, kept here for serialisation. */
const DEFAULT_PORTS: Readonly<Record<string, number>> = {
  http: 80,
  https: 443,
  ws: 80,
  wss: 443,
};

export interface TupleOrigin {
  readonly kind: 'origin';
  readonly scheme: string;
  /** Punycoded, lowercased host. Empty string for `file://`. */
  readonly host: string;
  /** Explicit non-default port, or null when the scheme default applies. */
  readonly port: number | null;
  /** `scheme://host[:port]` — the canonical serialisation. */
  readonly serialized: string;
  /** The input exactly as given. */
  readonly raw: string;
  /** False when the URL parser changed the input in any way. */
  readonly canonical: boolean;
  /**
   * True for a scheme the URL Standard gives an *opaque* origin (anything
   * outside http/https/ws/wss, e.g. `file:` or a WebView's custom scheme).
   * A conforming browser never sends such a value in `Origin`, but WebViews,
   * Electron and Cordova do, so it is parsed rather than rejected.
   */
  readonly opaqueScheme: boolean;
}

export interface NullOrigin {
  readonly kind: 'null';
  readonly raw: string;
}

export interface WildcardOrigin {
  readonly kind: 'wildcard';
  readonly raw: string;
}

export interface InvalidOrigin {
  readonly kind: 'invalid';
  readonly raw: string;
  readonly reason: string;
}

export type OriginValue = TupleOrigin | NullOrigin | WildcardOrigin | InvalidOrigin;

function invalid(raw: string, reason: string): InvalidOrigin {
  return { kind: 'invalid', raw, reason };
}

/**
 * Parse a value that occupies an origin position — an `Origin` request header
 * or an `Access-Control-Allow-Origin` response header.
 *
 * The literals `*` and `null` are returned as their own kinds because neither
 * is an origin: `*` is a wildcard and `null` is the serialisation of an opaque
 * origin.
 */
export function parseOriginValue(raw: string): OriginValue {
  if (raw === '*') return { kind: 'wildcard', raw };
  if (raw === 'null') return { kind: 'null', raw };
  if (raw.trim() !== raw) return invalid(raw, 'has leading or trailing whitespace');
  if (raw === '') return invalid(raw, 'is empty');

  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return invalid(raw, 'is not a parseable URL');
  }

  if (url.username !== '' || url.password !== '') {
    return invalid(raw, 'contains userinfo, which an origin never does');
  }
  if (url.search !== '') return invalid(raw, 'contains a query string');
  if (url.hash !== '') return invalid(raw, 'contains a fragment');

  const scheme = url.protocol.slice(0, -1);
  const opaqueScheme = !TUPLE_SCHEMES.has(scheme);

  // `new URL('https://x.test')` yields pathname '/', so a trailing slash is
  // indistinguishable here; it is caught by the `canonical` check below.
  if (url.pathname !== '/' && url.pathname !== '') {
    return invalid(raw, 'contains a path');
  }

  const port = url.port === '' ? null : Number(url.port);
  // One trailing root dot is stripped from the host. `app.acme.example.` and
  // `app.acme.example` are the same host in DNS, and treating them as
  // different ones made the defender's own host read as a *prefix* of itself:
  // hostRelationTo saw `app.acme.example.`.startsWith('app.acme.example.')
  // and reported prefix validation, critical, against a host the defender
  // already controls -- which is exactly what probe.ts says this probe is not.
  //
  // The divergence is not lost: `raw` keeps the dot, `serialized` does not,
  // so `canonical` is false and CM015 still reports it.
  const host = url.hostname.replace(/\.$/, '');
  const serialized = `${scheme}://${host}${url.port === '' ? '' : `:${url.port}`}`;

  return {
    kind: 'origin',
    scheme,
    host,
    port,
    serialized,
    raw,
    canonical: raw === serialized,
    opaqueScheme,
  };
}

/** True when two parsed origins are the same (scheme, host, port) triple. */
export function sameOrigin(a: OriginValue, b: OriginValue): boolean {
  if (a.kind !== 'origin' || b.kind !== 'origin') return false;
  return a.scheme === b.scheme && a.host === b.host && effectivePort(a) === effectivePort(b);
}

/** The port in effect, resolving the scheme default. Null for unknown schemes. */
export function effectivePort(o: TupleOrigin): number | null {
  if (o.port !== null) return o.port;
  return DEFAULT_PORTS[o.scheme] ?? null;
}

/**
 * Parse the origin of a resource URL. Unlike `parseOriginValue` this accepts a
 * path, query and fragment, because the input is a full URL.
 */
export function originOfUrl(resourceUrl: string): TupleOrigin | InvalidOrigin {
  let url: URL;
  try {
    url = new URL(resourceUrl);
  } catch {
    return invalid(resourceUrl, 'is not a parseable URL');
  }
  const scheme = url.protocol.slice(0, -1);
  const port = url.port === '' ? null : Number(url.port);
  return {
    kind: 'origin',
    scheme,
    host: url.hostname,
    port,
    serialized: `${scheme}://${url.host}`,
    raw: resourceUrl,
    canonical: false,
    opaqueScheme: !TUPLE_SCHEMES.has(scheme),
  };
}

/**
 * Parent domains of a host, down to a floor of two labels.
 *
 * `app.acme.example` yields `['acme.example']`. No Public Suffix List is
 * bundled — that would be a dependency and a data file that rots — so for a
 * host under a multi-label public suffix (`shop.acme.co.uk`) the derived set
 * includes `co.uk`. The consequence is documented in the README under
 * Limitations; in practice it only matters if a policy actually accepts an
 * origin whose host ends in that string.
 */
export function parentDomains(host: string): string[] {
  if (host === '' || isIpHost(host)) return [];
  const labels = host.replace(/\.$/, '').split('.');
  const out: string[] = [];
  for (let i = 1; i + 2 <= labels.length; i += 1) {
    out.push(labels.slice(i).join('.'));
  }
  return out;
}

/** True for an IPv4 literal or a bracketed IPv6 literal. */
export function isIpHost(host: string): boolean {
  if (host.startsWith('[') && host.endsWith(']')) return true;
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
}

/** How an accepted origin's *host* relates to a known-good host. */
export type HostRelation = 'same' | 'subdomain' | 'suffix' | 'prefix' | 'substring' | 'unrelated';

export interface OriginRelation {
  readonly hostRelation: HostRelation;
  /** The trusted host or derived parent domain that `hostRelation` is about. */
  readonly against: string | null;
  /** True when `against` was derived by label-stripping, not declared. */
  readonly againstIsDerived: boolean;
  /** The accepted origin is byte-identical to a trusted origin triple. */
  readonly exactTrustedOrigin: boolean;
  /** Host matches a trusted origin but the scheme differs. */
  readonly schemeMismatch: boolean;
  /** Scheme differs *and* the accepted origin is the insecure one. */
  readonly schemeDowngrade: boolean;
  /** Host and scheme match a trusted origin but the port differs. */
  readonly portMismatch: boolean;
}

export interface TrustAnchors {
  /** Full origins treated as legitimately allowed. */
  readonly origins: readonly TupleOrigin[];
  /** Declared hosts plus their derived parent domains, longest first. */
  readonly candidates: readonly { host: string; derived: boolean }[];
}

/** Build the trust anchors an analysis compares accepted origins against. */
export function buildTrustAnchors(origins: readonly TupleOrigin[]): TrustAnchors {
  const seen = new Map<string, boolean>();
  for (const o of origins) {
    if (o.host === '') continue;
    seen.set(o.host, false);
    for (const parent of parentDomains(o.host)) {
      if (!seen.has(parent)) seen.set(parent, true);
    }
  }
  const candidates = [...seen.entries()]
    .map(([host, derived]) => ({ host, derived }))
    .sort((a, b) => b.host.length - a.host.length || a.host.localeCompare(b.host));
  return { origins, candidates };
}

/**
 * Classify an accepted origin against the trust anchors.
 *
 * Host relation, scheme and port are deliberately orthogonal: an accepted
 * `http://app.acme.example` is a scheme downgrade *and* host-identical, and a
 * caller wants both facts rather than one collapsed verdict.
 */
export function relateOrigin(o: TupleOrigin, anchors: TrustAnchors): OriginRelation {
  const exactTrustedOrigin = anchors.origins.some((t) => sameOrigin(o, t));

  let schemeMismatch = false;
  let schemeDowngrade = false;
  let portMismatch = false;
  for (const t of anchors.origins) {
    if (t.host !== o.host) continue;
    if (t.scheme !== o.scheme) {
      schemeMismatch = true;
      if (o.scheme === 'http' && t.scheme === 'https') schemeDowngrade = true;
    } else if (effectivePort(o) !== effectivePort(t)) {
      portMismatch = true;
    }
  }

  for (const { host: c, derived } of anchors.candidates) {
    const rel = hostRelationTo(o.host, c);
    if (rel !== 'unrelated') {
      return {
        hostRelation: rel,
        against: c,
        againstIsDerived: derived,
        exactTrustedOrigin,
        schemeMismatch,
        schemeDowngrade,
        portMismatch,
      };
    }
  }

  return {
    hostRelation: 'unrelated',
    against: null,
    againstIsDerived: false,
    exactTrustedOrigin,
    schemeMismatch,
    schemeDowngrade,
    portMismatch,
  };
}

/**
 * The host relation of `host` to a single candidate.
 *
 * The order matters. `notacme.example` ends with `acme.example` without a dot
 * boundary, which is the `endsWith` bug; `acme.example.evil.invalid` starts
 * with `acme.example.`, which is the `startsWith` bug; anything else that
 * merely contains the candidate is the `includes` bug.
 */
export function hostRelationTo(host: string, candidate: string): HostRelation {
  if (host === candidate) return 'same';
  if (host.endsWith(`.${candidate}`)) return 'subdomain';
  if (host.endsWith(candidate)) return 'suffix';
  if (host.startsWith(`${candidate}.`)) return 'prefix';
  if (host.includes(candidate)) return 'substring';
  return 'unrelated';
}
