/**
 * Probe-plan generation.
 *
 * The plan is the half of the tool that is useful before you have any
 * captures. Given the resource and the origins you believe are legitimate, it
 * emits the exact set of `Origin` values that resolves the policy — one probe
 * per hypothesis about how the server's check is written, and no two probes
 * that resolve the same hypothesis.
 *
 * Generating a plan is pure string work. Nothing here opens a socket.
 */

import { originOfUrl, parentDomains, parseOriginValue, type TupleOrigin } from './origin.js';

export interface ProbePlanOptions {
  /** Absolute URL of the resource under test. */
  readonly resource: string;
  /** Origins believed to be legitimately allowed. */
  readonly trustedOrigins?: readonly string[];
  /**
   * A domain the tester controls, used where a probe needs an attacker-side
   * host. Defaults to `probe.example`, which is reserved and unregistrable —
   * change it to something you own before weaponising anything.
   */
  readonly attackerDomain?: string;
}

export interface Probe {
  /** The exact `Origin` header value to send. */
  readonly origin: string;
  /** Methods to send it with. `OPTIONS` entries carry pre-flight headers. */
  readonly methods: readonly string[];
  /** Pre-flight request headers, for the OPTIONS probes. */
  readonly requestHeaders?: Readonly<Record<string, string>>;
  /** What an "accepted" answer to this probe proves. */
  readonly resolves: string;
  /** Rule IDs this probe can trigger. */
  readonly rules: readonly string[];
  /**
   * Whether a browser can actually produce this `Origin` value. A probe that
   * is not browser-reachable still tells you how the check is written, but an
   * acceptance is not by itself exploitable from a web page.
   */
  readonly browserReachable: boolean;
  /**
   * Whether turning an acceptance into a working exploit requires registering
   * or controlling a domain. Sending the probe never does: it is one curl.
   */
  readonly requiresDomainControl: boolean;
}

export interface ProbePlan {
  readonly resource: string;
  readonly resourceOrigin: string;
  readonly trustedOrigins: readonly string[];
  readonly baseDomains: readonly string[];
  readonly attackerDomain: string;
  readonly probes: readonly Probe[];
  readonly notes: readonly string[];
}

export class ProbeError extends Error {}

const DEFAULT_ATTACKER_DOMAIN = 'probe.example';

export function buildProbePlan(options: ProbePlanOptions): ProbePlan {
  const resourceOrigin = originOfUrl(options.resource);
  if (resourceOrigin.kind !== 'origin') {
    throw new ProbeError(`resource ${resourceOrigin.reason}`);
  }
  if (resourceOrigin.host === '') {
    throw new ProbeError('resource URL has no host to build probes from');
  }

  const trusted: TupleOrigin[] = [resourceOrigin];
  for (const raw of options.trustedOrigins ?? []) {
    const parsed = parseOriginValue(raw);
    if (parsed.kind !== 'origin') {
      throw new ProbeError(`trusted origin ${JSON.stringify(raw)} is not an origin`);
    }
    if (!trusted.some((t) => t.serialized === parsed.serialized)) trusted.push(parsed);
  }

  const attackerDomain = options.attackerDomain ?? DEFAULT_ATTACKER_DOMAIN;
  const baseDomains = [...new Set(trusted.flatMap((t) => parentDomains(t.host)))].sort(
    (a, b) => b.length - a.length || a.localeCompare(b),
  );

  // The origin the policy is most likely to care about: the first declared
  // trusted origin, falling back to the resource's own origin.
  const primary = trusted[1] ?? resourceOrigin;
  const primaryBase = baseDomains[0] ?? primary.host;

  const probes: Probe[] = [];
  const seen = new Set<string>();
  const add = (p: Probe): void => {
    if (seen.has(p.origin)) return;
    seen.add(p.origin);
    probes.push(p);
  };

  add({
    origin: primary.serialized,
    methods: ['GET'],
    resolves:
      'the baseline. Establishes what an allowed origin looks like, and whether credentials ' +
      'are allowed at all. Every other probe is read against this one.',
    rules: [],
    browserReachable: true,
    requiresDomainControl: false,
  });

  add({
    origin: `https://${attackerDomain}`,
    methods: ['GET'],
    resolves:
      'wholesale reflection. An echo here means there is no origin validation; a fixed value ' +
      'or an absent header means there is some. This is the single highest-value probe.',
    rules: ['CM001', 'CM016'],
    browserReachable: true,
    requiresDomainControl: true,
  });

  add({
    origin: 'null',
    methods: ['GET'],
    resolves:
      'whether the null origin is allowed. Reachable from an iframe with ' +
      'sandbox="allow-scripts", so an acceptance needs no domain at all.',
    rules: ['CM002'],
    browserReachable: true,
    requiresDomainControl: false,
  });

  add({
    origin: `https://not${primaryBase}`,
    methods: ['GET'],
    resolves:
      `an endsWith(${JSON.stringify(primaryBase)}) check. This host ends with the trusted ` +
      'domain but not on a label boundary, so a parsed comparison rejects it and a string ' +
      'comparison does not.',
    rules: ['CM004'],
    browserReachable: true,
    requiresDomainControl: true,
  });

  add({
    origin: `https://${primaryBase}.${attackerDomain}`,
    methods: ['GET'],
    resolves:
      `a startsWith(${JSON.stringify(primaryBase)}) check, and any unanchored regular ` +
      'expression. Cheapest of the string bugs to exploit: one domain plus a wildcard DNS record.',
    rules: ['CM005'],
    browserReachable: true,
    requiresDomainControl: true,
  });

  add({
    origin: `https://x-${primaryBase}-x.${attackerDomain}`,
    methods: ['GET'],
    resolves:
      `an includes(${JSON.stringify(primaryBase)}) check that the two probes above miss, ` +
      'because the trusted domain sits in the middle of the host rather than at either end.',
    rules: ['CM005'],
    browserReachable: true,
    requiresDomainControl: true,
  });

  add({
    origin: `https://${attackerDomain.split('.')[0] ?? 'probe'}.${primaryBase}`,
    methods: ['GET'],
    resolves:
      `whether any subdomain of ${primaryBase} is allowed. An acceptance makes the policy only ` +
      'as strong as the weakest host under that domain, so the follow-up is subdomain ' +
      'enumeration for dangling or XSS-prone hosts.',
    rules: ['CM008'],
    browserReachable: true,
    requiresDomainControl: false,
  });

  if (primary.scheme === 'https') {
    add({
      origin: `http://${primary.host}`,
      methods: ['GET'],
      resolves:
        'whether the scheme is compared at all. An acceptance is exploitable from a network ' +
        'position rather than from a registered domain, so check for preloaded HSTS before ' +
        'grading it.',
      rules: ['CM006'],
      browserReachable: true,
      requiresDomainControl: false,
    });
  }

  add({
    origin: `https://${primary.host}:1337`,
    methods: ['GET'],
    resolves:
      'whether the port is compared. A check written against new URL(origin).hostname drops ' +
      'the port, which widens the policy to every port on that host.',
    rules: ['CM007'],
    browserReachable: true,
    requiresDomainControl: false,
  });

  add({
    origin: `https://${primary.host}.`,
    methods: ['GET'],
    resolves:
      'whether the check is string-based or parsed. A trailing root dot is a different byte ' +
      'string but resolves to the same host in DNS, and a browser will send it if the victim ' +
      'reaches the site by that name. It is a fingerprint rather than a primitive: the host it ' +
      'names is one the defender already controls.',
    rules: [],
    browserReachable: true,
    requiresDomainControl: false,
  });

  add({
    origin: `https://${primary.host.toUpperCase()}`,
    methods: ['GET'],
    resolves:
      'whether the comparison is case-sensitive. Informational only: a browser serialises the ' +
      'origin from a parsed URL, so it always sends a lowercase host and can never produce ' +
      'this value. An acceptance tells you the check is loose; it does not give you a vector.',
    rules: [],
    browserReachable: false,
    requiresDomainControl: false,
  });

  add({
    origin: `https://${primary.host}@${attackerDomain}`,
    methods: ['GET'],
    resolves:
      'whether the check parses the value at all. The origin of that URL is ' +
      `https://${attackerDomain}, so a browser sends that and never the whole string. Relevant ` +
      'only where the Origin value reaches the check from somewhere other than a browser — a ' +
      'proxy that rewrites headers, or an allowlist shared with redirect validation, which is ' +
      'where this payload shape actually pays off.',
    rules: [],
    browserReachable: false,
    requiresDomainControl: true,
  });

  // One pre-flight probe, sent with the reflection origin: pre-flight and
  // actual responses are produced by different code more often than not, and
  // a plan that only ever sends GET cannot see the difference.
  probes.push({
    origin: `https://${attackerDomain}`,
    methods: ['OPTIONS'],
    requestHeaders: {
      'Access-Control-Request-Method': 'PUT',
      'Access-Control-Request-Headers': 'authorization,content-type',
    },
    resolves:
      'the pre-flight half of the policy: which methods and headers are allowed, and whether ' +
      'the OPTIONS handler reaches the same verdict as the real handler. Compare it against the ' +
      'GET probe for the same origin.',
    rules: ['CM010', 'CM011', 'CM012'],
    browserReachable: true,
    requiresDomainControl: true,
  });

  return {
    resource: options.resource,
    resourceOrigin: resourceOrigin.serialized,
    trustedOrigins: trusted.map((t) => t.serialized),
    baseDomains,
    attackerDomain,
    probes,
    notes: [
      'Sending a probe requires no control of the domain in the Origin header. It is one header ' +
        'on one request. Domain control only matters at the exploitation step, and the plan ' +
        'marks which probes need it.',
      'Send every probe twice: once with the session cookie or bearer token and once without. ' +
        'Access-Control-Allow-Credentials is sometimes emitted only for authenticated requests, ' +
        'and a capture taken without credentials will under-report.',
      'Record the full response header block for each probe, including Vary and Set-Cookie. ' +
        'cors-matrix needs Vary to decide CM009 and Set-Cookie to decide whether the resource ' +
        'is authenticated.',
      'Only probe hosts you are authorised to test, and check the programme scope before ' +
        'registering anything the plan marks as requiring domain control.',
    ],
  };
}

/** The shell loop that turns a plan into a capture file. Printed with the plan. */
export function probeCommandHint(plan: ProbePlan): string {
  return [
    '# One request per probe. -D - dumps response headers; -o /dev/null drops the body.',
    'for origin in \\',
    ...plan.probes
      .filter((p) => p.methods.includes('GET'))
      .map((p) => `  ${JSON.stringify(p.origin)} \\`),
    '; do',
    `  printf '\\n=== %s\\n' "$origin"`,
    `  curl -sS -o /dev/null -D - -H "Origin: $origin" ${JSON.stringify(plan.resource)}`,
    'done',
  ].join('\n');
}
