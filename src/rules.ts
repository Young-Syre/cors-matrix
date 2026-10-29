import type { RuleMeta } from './types.js';

/**
 * The rule table.
 *
 * `maxSeverity` is the worst grade a rule can reach. Most rules are graded on
 * whether credentials are allowed, because almost every CORS misconfiguration
 * is harmless without them: a cross-origin read of a response that carries no
 * session is a read of something the attacker could have fetched from their
 * own server.
 */
export const RULES: readonly RuleMeta[] = [
  {
    id: 'CM001',
    name: 'Arbitrary origin accepted with credentials',
    maxSeverity: 'critical',
    summary:
      'An origin unrelated to the resource was echoed into Access-Control-Allow-Origin with ' +
      'Access-Control-Allow-Credentials: true. Any page on the internet can read the ' +
      "authenticated response, so this is account takeover reduced to one victim's page visit.",
  },
  {
    id: 'CM002',
    name: 'null origin allowed with credentials',
    maxSeverity: 'high',
    summary:
      'Access-Control-Allow-Origin was null alongside credentials. The null origin is not an ' +
      'unreachable sentinel: an attacker gets it from an iframe with sandbox="allow-scripts" ' +
      '(no allow-same-origin), or from a data: document, both of which they can embed anywhere.',
  },
  {
    id: 'CM003',
    name: 'Wildcard ACAO with credentials (not honoured)',
    maxSeverity: 'low',
    summary:
      'Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. No browser ' +
      'honours this combination, so it is not exploitable. It is graded low because it means ' +
      'nobody has tested the credentialed path, and the usual fix — reflecting the origin so ' +
      'the combination becomes legal — turns it straight into CM001.',
  },
  {
    id: 'CM004',
    name: 'Suffix-match origin validation',
    maxSeverity: 'critical',
    summary:
      'An origin was accepted whose host ends with a trusted domain but not on a label ' +
      'boundary, e.g. notacme.example for acme.example. The check was endsWith() on a string ' +
      'rather than a comparison of parsed hosts. The attacker registers the domain.',
  },
  {
    id: 'CM005',
    name: 'Prefix or substring origin validation',
    maxSeverity: 'critical',
    summary:
      'An origin was accepted whose host merely starts with or contains a trusted domain, ' +
      'e.g. acme.example.attacker.invalid. The check was startsWith() or includes(). The ' +
      'attacker needs one domain and a wildcard DNS record.',
  },
  {
    id: 'CM006',
    name: 'Insecure-scheme origin accepted',
    maxSeverity: 'high',
    summary:
      'An http:// origin was accepted for an https:// resource, or an origin with a scheme that ' +
      'has no tuple origin (file:, a WebView scheme) was accepted. A network attacker who can ' +
      'inject into any plaintext page on the host then reads the authenticated response.',
  },
  {
    id: 'CM007',
    name: 'Port-blind origin matching',
    maxSeverity: 'high',
    summary:
      'An origin was accepted that differs from a trusted origin only in its port. The check ' +
      'compared hostnames and dropped the port, so an XSS or an attacker-controlled service on ' +
      'any port of the same host — a dev server, a debug listener — becomes a CORS bypass.',
  },
  {
    id: 'CM008',
    name: 'Subdomain wildcarding with credentials',
    maxSeverity: 'medium',
    summary:
      'Any subdomain of a trusted domain is accepted with credentials. This is often ' +
      'deliberate, so it is graded medium and reported as a dependency: the policy is only as ' +
      'strong as the weakest subdomain, including ones that are dangling or claimable.',
  },
  {
    id: 'CM009',
    name: 'Vary: Origin missing while ACAO varies',
    maxSeverity: 'medium',
    summary:
      'The ACAO value depends on the request origin but the response does not vary on Origin. ' +
      'Any shared cache in front of the resource may store one origin’s ACAO and serve it ' +
      'to another, which either breaks a legitimate origin or hands a third party a cached ' +
      'allow it was never granted.',
  },
  {
    id: 'CM010',
    name: 'Over-permissive Access-Control-Allow-Headers',
    maxSeverity: 'medium',
    summary:
      'Access-Control-Allow-Headers is * on a credentialed response — where Fetch treats it as ' +
      'the literal header name "*", not a wildcard — or Authorization is allowed alongside an ' +
      'origin that should not have been accepted.',
  },
  {
    id: 'CM011',
    name: 'Over-permissive Access-Control-Allow-Methods',
    maxSeverity: 'medium',
    summary:
      'Access-Control-Allow-Methods is * on a credentialed response (again literal, not a ' +
      'wildcard), or a state-changing method is allowed for an origin that should not have ' +
      'been accepted, turning a read bug into a write bug.',
  },
  {
    id: 'CM012',
    name: 'Pre-flight and actual response disagree',
    maxSeverity: 'medium',
    summary:
      'The OPTIONS response and the real response reach different CORS verdicts for the same ' +
      'origin. Whichever way round it is, a tester who probed only one of the two drew the ' +
      'wrong conclusion, and that is the most common source of both false positives and ' +
      'missed findings in CORS testing.',
  },
  {
    id: 'CM013',
    name: 'CORS headers on an unauthenticated resource',
    maxSeverity: 'info',
    summary:
      'ACAO is present on a resource that shows no sign of carrying credentials. Nothing is ' +
      'leaked that an attacker could not fetch from their own server. Reported so that it is ' +
      'not re-triaged as a finding.',
  },
  {
    id: 'CM014',
    name: 'Access-Control-Allow-Credentials not exactly "true"',
    maxSeverity: 'info',
    summary:
      'The header is present with a value such as True or 1. The Fetch standard compares it ' +
      'against the byte string true, so the value is not honoured and the credentialed path is ' +
      'closed — almost certainly by accident. Verify against a real browser before relying on it.',
  },
  {
    id: 'CM015',
    name: 'Malformed or non-canonical ACAO value',
    maxSeverity: 'low',
    summary:
      'ACAO was sent twice, carried a comma-separated list, or was not a canonical origin ' +
      'serialisation (a trailing slash, a path, an explicit default port). Browsers reject all ' +
      'of these, so the policy is closed by accident; it means the header is assembled by ' +
      'string concatenation, which is where the other rules in this table come from.',
  },
  {
    id: 'CM016',
    name: 'Origin reflected without credentials',
    maxSeverity: 'low',
    summary:
      'An unrelated origin was echoed into ACAO but credentials are not allowed, so no ' +
      'authenticated data crosses. Origin validation is nonetheless absent: the finding is the ' +
      'one line of configuration between here and CM001, and it already matters for a resource ' +
      "reachable only from inside a network the victim's browser sits in.",
  },
];

const BY_ID = new Map(RULES.map((r) => [r.id, r]));

export function ruleMeta(id: string): RuleMeta {
  const meta = BY_ID.get(id);
  if (meta === undefined) throw new Error(`unknown rule id ${id}`);
  return meta;
}
