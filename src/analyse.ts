/** Turn a capture into findings. */

import { varyCoversOrigin } from './headers.js';
import {
  buildTrustAnchors,
  relateOrigin,
  type OriginRelation,
  type TrustAnchors,
  type TupleOrigin,
} from './origin.js';
import { ruleMeta } from './rules.js';
import {
  severityRank,
  type AnalysisResult,
  type Capture,
  type Finding,
  type Observation,
  type PolicySummary,
  type Severity,
} from './types.js';

type AuthState = 'authenticated' | 'unauthenticated' | 'unknown';

/** An observation in which the server allowed a specific origin to read. */
interface Accepted {
  readonly observation: Observation;
  readonly origin: TupleOrigin;
  readonly relation: OriginRelation;
  readonly withCredentials: boolean;
}

interface Context {
  readonly capture: Capture;
  readonly anchors: TrustAnchors;
  readonly authState: AuthState;
  readonly reflectsOrigin: boolean;
  readonly echoedUntrusted: number;
  readonly accepted: readonly Accepted[];
  /**
   * `url \0 origin` keys for which a non-pre-flight response did *not* pass
   * the CORS check. An origin accepted only by the pre-flight and refused by
   * the real response is not readable, so findings about it must be graded
   * down rather than reported as exploitable.
   */
  readonly rejectedByActual: ReadonlySet<string>;
  readonly warnings: string[];
}

function verdictKey(o: Observation): string {
  return `${o.url}\u0000${describeRequestOrigin(o)}`;
}

export function analyse(capture: Capture): AnalysisResult {
  const warnings: string[] = [];
  const anchors = buildTrustAnchors(capture.trustedOrigins);

  for (const o of capture.observations) {
    if (o.requestOrigin !== null && o.requestOrigin.kind === 'invalid') {
      warnings.push(
        `observation ${o.index}: request origin ${JSON.stringify(o.requestOrigin.raw)} ` +
          `${o.requestOrigin.reason}; no browser sends that value, so the observation only ` +
          'tells you how the server treats an invalid header',
      );
    }
  }

  const accepted: Accepted[] = [];
  for (const o of capture.observations) {
    const acao = o.headers.acao;
    if (acao === null) continue;
    if (acao.value.kind !== 'origin') continue;
    if (!o.passesCorsCheckWithoutCredentials && !o.passesCorsCheckWithCredentials) continue;
    accepted.push({
      observation: o,
      origin: acao.value,
      relation: relateOrigin(acao.value, anchors),
      withCredentials: o.passesCorsCheckWithCredentials,
    });
  }

  // Reflection is only *confirmed* by origins outside the trusted set. A
  // server matching an allowlist also echoes the origin it matched, so a
  // trusted origin coming back proves nothing either way.
  const reflectedUntrusted = new Set(
    capture.observations
      .filter((o) => o.acaoShape === 'reflected' && o.requestOrigin?.kind === 'origin')
      .map((o) => o.requestOrigin as TupleOrigin)
      .filter((o) => !capture.trustedOrigins.some((t) => t.serialized === o.serialized))
      .map((o) => o.serialized),
  );

  const rejectedByActual = new Set(
    capture.observations
      .filter(
        (o) =>
          !o.isPreflight && !o.passesCorsCheckWithCredentials && !o.passesCorsCheckWithoutCredentials,
      )
      .map(verdictKey),
  );

  const ctx: Context = {
    capture,
    anchors,
    authState: authStateOf(capture),
    reflectsOrigin: reflectedUntrusted.size >= 2,
    echoedUntrusted: reflectedUntrusted.size,
    accepted,
    rejectedByActual,
    warnings,
  };

  const findings = [
    ...ruleArbitraryReflection(ctx),
    ...ruleNullOrigin(ctx),
    ...ruleWildcardWithCredentials(ctx),
    ...ruleSuffixMatch(ctx),
    ...rulePrefixMatch(ctx),
    ...ruleSchemeDowngrade(ctx),
    ...rulePortBlind(ctx),
    ...ruleSubdomainWildcard(ctx),
    ...ruleVaryOrigin(ctx),
    ...ruleAllowHeaders(ctx),
    ...ruleAllowMethods(ctx),
    ...rulePreflightMismatch(ctx),
    ...ruleUnauthenticatedResource(ctx),
    ...ruleCredentialsCasing(ctx),
    ...ruleMalformedAcao(ctx),
    ...ruleReflectionWithoutCredentials(ctx),
  ].sort(
    (a, b) =>
      severityRank(b.severity) - severityRank(a.severity) ||
      a.rule.localeCompare(b.rule) ||
      (a.origin ?? '').localeCompare(b.origin ?? ''),
  );

  return {
    resource: capture.resource,
    source: capture.source,
    description: capture.description,
    trustedOrigins: capture.trustedOrigins.map((t) => t.serialized),
    observationCount: capture.observations.length,
    policy: summarise(ctx),
    findings,
    warnings,
  };
}

function authStateOf(capture: Capture): AuthState {
  if (capture.authenticated === true) return 'authenticated';
  if (capture.authenticated === false) return 'unauthenticated';
  const signal = capture.observations.some(
    (o) => o.requestCarriedCredentials || o.headers.setsCookie || o.headers.acacHonoured,
  );
  return signal ? 'authenticated' : 'unknown';
}

function summarise(ctx: Context): PolicySummary {
  const acaoValues = new Set<string>();
  const acceptedOrigins = new Set<string>();
  const rejectedOrigins = new Set<string>();
  for (const o of ctx.capture.observations) {
    if (o.headers.acao !== null) acaoValues.add(o.headers.acao.raw);
    const label = describeRequestOrigin(o);
    if (o.passesCorsCheckWithCredentials || o.passesCorsCheckWithoutCredentials) acceptedOrigins.add(label);
    else rejectedOrigins.add(label);
  }
  return {
    reflectsOrigin: ctx.reflectsOrigin,
    echoedUntrustedOrigins: ctx.echoedUntrusted,
    distinctAcaoValues: [...acaoValues].sort(),
    credentialsAllowed: ctx.capture.observations.some((o) => o.headers.acacHonoured),
    acceptedOrigins: [...acceptedOrigins].sort(),
    rejectedOrigins: [...rejectedOrigins].sort(),
    preflightCount: ctx.capture.observations.filter((o) => o.isPreflight).length,
  };
}

function describeRequestOrigin(o: Observation): string {
  if (o.requestOrigin === null) return '(no Origin header)';
  if (o.requestOrigin.kind === 'origin') return o.requestOrigin.serialized;
  return o.requestOrigin.raw;
}

/* ------------------------------------------------------------------ *
 * Helpers
 * ------------------------------------------------------------------ */

function finding(
  id: string,
  severity: Severity,
  detail: string,
  evidence: readonly number[],
  extra: Partial<Pick<Finding, 'origin' | 'facts' | 'dependency' | 'browserReachable'>> = {},
): Finding {
  const meta = ruleMeta(id);
  return {
    rule: meta.id,
    name: meta.name,
    severity,
    detail,
    evidence: [...evidence].sort((a, b) => a - b),
    browserReachable: extra.browserReachable ?? true,
    ...(extra.origin === undefined ? {} : { origin: extra.origin }),
    ...(extra.facts === undefined ? {} : { facts: extra.facts }),
    ...(extra.dependency === undefined ? {} : { dependency: extra.dependency }),
  };
}

interface AcceptedGroup {
  origin: TupleOrigin;
  relation: OriginRelation;
  withCredentials: boolean;
  evidence: number[];
  /** The acceptance was seen on a real response, not only on a pre-flight. */
  onActual: boolean;
  /** Only the pre-flight accepted it; the real response for the same origin refused. */
  contradictedByActual: boolean;
}

/** Group accepted observations by origin, so one origin yields one finding. */
function groupAccepted(ctx: Context, predicate: (a: Accepted) => boolean): AcceptedGroup[] {
  const groups = new Map<string, AcceptedGroup & { keys: Set<string> }>();
  for (const a of ctx.accepted) {
    if (!predicate(a)) continue;
    const key = a.origin.serialized;
    const existing = groups.get(key);
    if (existing === undefined) {
      groups.set(key, {
        origin: a.origin,
        relation: a.relation,
        withCredentials: a.withCredentials,
        evidence: [a.observation.index],
        onActual: !a.observation.isPreflight,
        contradictedByActual: false,
        keys: new Set([verdictKey(a.observation)]),
      });
    } else {
      existing.evidence.push(a.observation.index);
      existing.withCredentials = existing.withCredentials || a.withCredentials;
      existing.onActual = existing.onActual || !a.observation.isPreflight;
      existing.keys.add(verdictKey(a.observation));
    }
  }
  const out: AcceptedGroup[] = [];
  for (const g of groups.values()) {
    const { keys, ...rest } = g;
    out.push({
      ...rest,
      contradictedByActual: !g.onActual && [...keys].some((k) => ctx.rejectedByActual.has(k)),
    });
  }
  return out.sort((x, y) => x.origin.serialized.localeCompare(y.origin.serialized));
}

/**
 * Where the acceptance was observed decides how it is graded.
 *
 * An origin that only the pre-flight accepted is not readable: the browser
 * completes the pre-flight, issues the real request, and then discards the
 * response because the real response does not allow the origin. Reporting that
 * as critical is the most common false positive in CORS testing, so it is
 * graded low here and cross-referenced to CM012 instead.
 */
function gradeAcceptance(
  g: AcceptedGroup,
  base: Severity,
): { severity: Severity; suffix: string; dependency?: string } {
  if (g.contradictedByActual) {
    return {
      severity: 'low',
      suffix:
        ' Acceptance was observed on the pre-flight response only: the real response for the same ' +
        'origin did not pass the CORS check, so a browser discards it and there is no ' +
        `cross-origin read today. Graded low for that reason rather than ${base}, and reported ` +
        'because the two responses come from different code — see CM012 — and the day the real ' +
        `response starts allowing the origin as well, it is a ${base}.`,
      dependency: 'the actual response must also allow the origin; today it does not',
    };
  }
  if (!g.onActual) {
    return {
      severity: base,
      suffix:
        ' Acceptance was observed on a pre-flight response, and the capture contains no real ' +
        'response for the same origin. Capture one before reporting: a pre-flight that allows an ' +
        'origin does not by itself make the response readable.',
      dependency: 'confirm the real (non-OPTIONS) response allows the same origin',
    };
  }
  return { severity: base, suffix: '' };
}

function isUntrusted(a: Accepted): boolean {
  return !a.relation.exactTrustedOrigin;
}

/* ------------------------------------------------------------------ *
 * CM001 — arbitrary origin accepted with credentials
 * ------------------------------------------------------------------ */

function ruleArbitraryReflection(ctx: Context): Finding[] {
  const groups = groupAccepted(
    ctx,
    (a) => isUntrusted(a) && a.relation.hostRelation === 'unrelated' && a.withCredentials,
  );
  return groups.map((g) => {
    const grade = gradeAcceptance(g, 'critical');
    const confirmation = ctx.reflectsOrigin
      ? 'At least two distinct origins were echoed back, so the server is reflecting the Origin ' +
        'header rather than matching an allowlist that happens to contain this origin.'
      : 'Only one origin was echoed in this capture, so reflection is inferred rather than ' +
        'confirmed. Capture a second unrelated origin to settle it — either way the origin ' +
        'below was accepted, which is the finding.';
    const impact = g.onActual
      ? `A page served from ${g.origin.serialized} can therefore read the authenticated response ` +
        `to ${ctx.capture.resource} using fetch(..., { credentials: 'include' }), with the ` +
        "victim's session, from any browser that visits it."
      : `Were the real response to answer the same way, a page served from ${g.origin.serialized} ` +
        `could read the authenticated response to ${ctx.capture.resource} using ` +
        "fetch(..., { credentials: 'include' }), with the victim's session.";
    return finding(
      'CM001',
      grade.severity,
      `${g.origin.serialized} is unrelated to ${ctx.capture.resourceOrigin.serialized} and to every ` +
        'declared trusted origin, yet the server returned it in Access-Control-Allow-Origin ' +
        `together with Access-Control-Allow-Credentials: true. ${impact} ${confirmation}${grade.suffix}`,
      g.evidence,
      {
        origin: g.origin.serialized,
        facts: {
          'resource origin': ctx.capture.resourceOrigin.serialized,
          'reflection confirmed': String(ctx.reflectsOrigin),
          'seen on a real response': String(g.onActual),
        },
        ...(grade.dependency === undefined ? {} : { dependency: grade.dependency }),
      },
    );
  });
}

/* ------------------------------------------------------------------ *
 * CM002 — null origin
 * ------------------------------------------------------------------ */

function ruleNullOrigin(ctx: Context): Finding[] {
  const matching = ctx.capture.observations.filter((o) => o.headers.acao?.value.kind === 'null');
  if (matching.length === 0) return [];
  const credentialed = matching.some((o) => o.headers.acacHonoured);
  const echoed = matching.some((o) => o.requestOrigin?.kind === 'null');
  const how = echoed
    ? 'The capture shows it echoed back after the probe sent Origin: null, so it is reachable.'
    : 'The capture shows it returned as a fixed value rather than echoed, which is still ' +
      'reachable: a null-origin document satisfies the CORS check against a literal null.';
  return [
    finding(
      'CM002',
      credentialed ? 'high' : 'low',
      `Access-Control-Allow-Origin was null${
        credentialed ? ' alongside Access-Control-Allow-Credentials: true' : ' but credentials are not allowed'
      }. ${how} An attacker obtains the null origin without owning any domain: an iframe with ` +
        'sandbox="allow-scripts" and no allow-same-origin has a null origin, and so does a ' +
        'data: or about:blank document, all of which they can embed in a page they control.' +
        (credentialed
          ? ''
          : ' Without credentials nothing authenticated crosses, so this is graded low.'),
      matching.map((o) => o.index),
      { origin: 'null', facts: { 'credentials allowed': String(credentialed) } },
    ),
  ];
}

/* ------------------------------------------------------------------ *
 * CM003 — wildcard with credentials
 * ------------------------------------------------------------------ */

function ruleWildcardWithCredentials(ctx: Context): Finding[] {
  const matching = ctx.capture.observations.filter(
    (o) => o.headers.acao?.value.kind === 'wildcard' && o.headers.acacHonoured,
  );
  if (matching.length === 0) return [];
  return [
    finding(
      'CM003',
      'low',
      'The response set Access-Control-Allow-Origin: * together with ' +
        'Access-Control-Allow-Credentials: true. This is not exploitable. Step 3 of the Fetch ' +
        "standard's CORS check requires Access-Control-Allow-Origin to equal the serialised " +
        'request origin when the credentials mode is include, and * never does, so every ' +
        'conforming browser fails the credentialed read. It is reported at low rather than ' +
        'dismissed for two reasons: it proves the credentialed path has never been exercised, ' +
        'and the instinctive fix — echo the request origin so the wildcard restriction goes ' +
        'away — converts it directly into CM001. Grade it as a configuration defect, not a ' +
        'data exposure, and say so in the report.',
      matching.map((o) => o.index),
      { origin: '*' },
    ),
  ];
}

/* ------------------------------------------------------------------ *
 * CM004 / CM005 — string-matching bugs
 * ------------------------------------------------------------------ */

function ruleSuffixMatch(ctx: Context): Finding[] {
  const groups = groupAccepted(ctx, (a) => isUntrusted(a) && a.relation.hostRelation === 'suffix');
  return groups.map((g) => {
    const against = g.relation.against ?? '(unknown)';
    const grade = gradeAcceptance(g, g.withCredentials ? 'critical' : 'medium');
    return finding(
      'CM004',
      grade.severity,
      `${g.origin.serialized} was accepted. Its host ends with ${against} but not on a label ` +
        `boundary: the host is ${g.origin.host}, and the character before ${against} is not a dot. ` +
        `That is the signature of a check written as origin.endsWith(${JSON.stringify(against)}) ` +
        'or a regular expression with an unanchored, undotted suffix. The attacker registers ' +
        `a domain ending in ${against}, which costs the price of a domain and nothing else` +
        (g.withCredentials
          ? ', and then reads the authenticated response from a page they control.'
          : '. Credentials are not allowed here, so the immediate impact is limited; the broken ' +
            'check is the finding.') +
        (g.relation.againstIsDerived
          ? ` The domain ${against} was derived by stripping labels from a trusted host rather ` +
            'than declared, so confirm it is the string the server actually compares against.'
          : '') +
        grade.suffix,
      g.evidence,
      {
        origin: g.origin.serialized,
        facts: { host: g.origin.host, 'matched against': against, 'derived domain': String(g.relation.againstIsDerived) },
        dependency:
          grade.dependency ??
          `the attacker must be able to register a domain whose host ends in ${against}`,
      },
    );
  });
}

function rulePrefixMatch(ctx: Context): Finding[] {
  const groups = groupAccepted(
    ctx,
    (a) => isUntrusted(a) && (a.relation.hostRelation === 'prefix' || a.relation.hostRelation === 'substring'),
  );
  return groups.map((g) => {
    const against = g.relation.against ?? '(unknown)';
    const isPrefix = g.relation.hostRelation === 'prefix';
    const grade = gradeAcceptance(g, g.withCredentials ? 'critical' : 'medium');
    return finding(
      'CM005',
      grade.severity,
      `${g.origin.serialized} was accepted. Its host ${
        isPrefix ? `starts with ${against}.` : `merely contains ${against}`
      }, so the check is ${
        isPrefix ? `startsWith(${JSON.stringify(against)})` : `includes(${JSON.stringify(against)})`
      } or an unanchored regular expression rather than a comparison of parsed hosts. This is ` +
        'cheaper to exploit than CM004: the attacker needs one domain they already own plus a ' +
        `wildcard DNS record, and then serves the page from ${g.origin.host}` +
        (g.withCredentials
          ? ' and reads the authenticated response.'
          : '. Credentials are not allowed here, so grade the impact accordingly.') +
        grade.suffix,
      g.evidence,
      {
        origin: g.origin.serialized,
        facts: { host: g.origin.host, 'matched against': against, relation: g.relation.hostRelation },
        dependency: grade.dependency ?? 'the attacker must control DNS for one domain of their own',
      },
    );
  });
}

/* ------------------------------------------------------------------ *
 * CM006 — scheme
 * ------------------------------------------------------------------ */

function ruleSchemeDowngrade(ctx: Context): Finding[] {
  const out: Finding[] = [];
  const resourceScheme = ctx.capture.resourceOrigin.scheme;

  const downgrades = groupAccepted(
    ctx,
    (a) => isUntrusted(a) && a.origin.scheme === 'http' && resourceScheme === 'https',
  );
  for (const g of downgrades) {
    const grade = gradeAcceptance(g, g.withCredentials ? 'high' : 'medium');
    out.push(
      finding(
        'CM006',
        grade.severity,
        `${g.origin.serialized} was accepted for an https resource. The policy compares hosts ` +
          'without comparing schemes, so a plaintext origin is allowed to read an encrypted ' +
          `resource${g.withCredentials ? ' with credentials' : ''}. The exploit does not need a ` +
          'registered domain: an attacker positioned on the network injects script into any ' +
          `http:// response for ${g.origin.host} — a captive portal, an http redirect that has ` +
          'not been HSTS-preloaded, any plaintext asset — and that script then holds an origin ' +
          'the policy trusts. HSTS on the host closes it; verify whether it is set, and ' +
          'preloaded, before deciding the severity.' +
          grade.suffix,
        g.evidence,
        {
          origin: g.origin.serialized,
          facts: { 'resource scheme': resourceScheme, 'accepted scheme': 'http' },
          dependency:
            grade.dependency ??
            'a network position allowing injection into plaintext traffic for that host, ' +
              'and the absence of preloaded HSTS',
        },
      ),
    );
  }

  const opaque = groupAccepted(ctx, (a) => isUntrusted(a) && a.origin.opaqueScheme);
  for (const g of opaque) {
    out.push(
      finding(
        'CM006',
        g.withCredentials && g.onActual ? 'medium' : 'low',
        `${g.origin.serialized} was accepted, and its scheme (${g.origin.scheme}) is not one the ` +
          'URL Standard gives a tuple origin. A conforming browser therefore never sends this ' +
          'value in an Origin header — it would send null instead — so this is not reachable ' +
          'from a normal web page. It is reachable from a WebView, an Electron renderer or a ' +
          'Cordova container that sets a custom scheme, which is usually exactly why such a ' +
          'value is in an allowlist. Treat it as an attack surface on the mobile or desktop ' +
          'client rather than on the web app, and check CM002 as well: a sandboxed frame in ' +
          'that same container sends null.',
        g.evidence,
        {
          origin: g.origin.serialized,
          browserReachable: false,
          facts: { scheme: g.origin.scheme },
          dependency: 'a client that actually emits this scheme in the Origin header',
        },
      ),
    );
  }

  return out;
}

/* ------------------------------------------------------------------ *
 * CM007 — port
 * ------------------------------------------------------------------ */

function rulePortBlind(ctx: Context): Finding[] {
  const groups = groupAccepted(ctx, (a) => isUntrusted(a) && a.relation.portMismatch);
  return groups.map((g) => {
    const grade = gradeAcceptance(g, g.withCredentials ? 'high' : 'medium');
    return finding(
      'CM007',
      grade.severity,
      `${g.origin.serialized} was accepted although it differs from a trusted origin only in its ` +
        'port. The check compared hostnames and discarded the port, which is what happens when ' +
        'the comparison is written against new URL(origin).hostname. An origin is a (scheme, ' +
        'host, port) triple, so this widens the policy to every port on that host: a forgotten ' +
        'dev server, a debug listener, a container that binds a high port, or an XSS in any ' +
        'application on a non-standard port now inherits the trusted origin' +
        (g.withCredentials ? ' and reads the authenticated response.' : '.') +
        grade.suffix,
      g.evidence,
      {
        origin: g.origin.serialized,
        facts: { host: g.origin.host, port: g.origin.port === null ? '(default)' : String(g.origin.port) },
        dependency:
          grade.dependency ?? 'the attacker must be able to serve content from some port on that host',
      },
    );
  });
}

/* ------------------------------------------------------------------ *
 * CM008 — subdomain wildcarding
 * ------------------------------------------------------------------ */

function ruleSubdomainWildcard(ctx: Context): Finding[] {
  const groups = groupAccepted(ctx, (a) => isUntrusted(a) && a.relation.hostRelation === 'subdomain');
  return groups.map((g) => {
    const against = g.relation.against ?? '(unknown)';
    const grade = gradeAcceptance(g, g.withCredentials ? 'medium' : 'low');
    return finding(
      'CM008',
      grade.severity,
      `${g.origin.serialized} was accepted as a subdomain of ${against}` +
        `${g.withCredentials ? ' with credentials' : ''}. This is frequently deliberate, so it ` +
        'is reported as a dependency rather than a bug: the policy is now exactly as strong as ' +
        `the weakest host under ${against}. That includes subdomains that are dangling — a CNAME ` +
        'to a deprovisioned bucket, app or CDN tenancy that someone else can claim — and ' +
        'subdomains that merely have an XSS. This tool is offline and resolves nothing, so it ' +
        'cannot tell you whether such a subdomain exists; that enumeration is the next step, ' +
        'and it is the step that decides whether this is a note or a critical.' +
        grade.suffix,
      g.evidence,
      {
        origin: g.origin.serialized,
        facts: { 'wildcarded domain': against, 'derived domain': String(g.relation.againstIsDerived) },
        dependency:
          `the existence of a claimable, dangling or XSS-prone host under ${against}; resolve ` +
          'this separately, as cors-matrix makes no network requests',
      },
    );
  });
}

/* ------------------------------------------------------------------ *
 * CM009 — Vary: Origin
 * ------------------------------------------------------------------ */

function ruleVaryOrigin(ctx: Context): Finding[] {
  const actual = ctx.capture.observations.filter((o) => !o.isPreflight && o.headers.acao !== null);
  const distinct = new Set(actual.map((o) => o.headers.acao?.raw ?? ''));
  if (distinct.size < 2 && !ctx.reflectsOrigin) return [];
  const missing = actual.filter((o) => !varyCoversOrigin(o.headers.vary));
  if (missing.length === 0) return [];
  const credentialed = missing.some((o) => o.headers.acacHonoured);
  return [
    finding(
      'CM009',
      credentialed ? 'medium' : 'low',
      `The Access-Control-Allow-Origin value depends on the request origin — ${distinct.size} ` +
        'distinct values were observed — but at least one of those responses did not carry a ' +
        'Vary header covering Origin. Origin is not in any cache’s default key, so a shared ' +
        'cache (a CDN, a reverse proxy, a corporate forward proxy) is free to store the response ' +
        'for one origin and serve it to another. That cuts both ways: a legitimate origin gets a ' +
        "third party's ACAO and breaks, or a third party gets an allow it was never granted and " +
        'can read the response for as long as the entry lives. The second case is a genuine ' +
        'cross-origin read that no amount of correct origin validation prevents, which is why ' +
        'this is a finding and not a performance note.',
      missing.map((o) => o.index),
      {
        facts: {
          'distinct ACAO values': String(distinct.size),
          'responses missing Vary: Origin': String(missing.length),
        },
        dependency: 'a shared cache in front of the resource; confirm the caching topology',
      },
    ),
  ];
}

/* ------------------------------------------------------------------ *
 * CM010 / CM011 — allowed headers and methods
 * ------------------------------------------------------------------ */

const STATE_CHANGING = ['put', 'delete', 'patch'];

function acceptedUntrustedIndices(ctx: Context): Set<number> {
  return new Set(ctx.accepted.filter(isUntrusted).map((a) => a.observation.index));
}

function ruleAllowHeaders(ctx: Context): Finding[] {
  const out: Finding[] = [];
  const untrusted = acceptedUntrustedIndices(ctx);

  const literalWildcard = ctx.capture.observations.filter(
    (o) => o.headers.allowHeaders?.includes('*') === true && o.headers.acacHonoured,
  );
  if (literalWildcard.length > 0) {
    out.push(
      finding(
        'CM010',
        'low',
        'Access-Control-Allow-Headers is * on a response that also sets ' +
          'Access-Control-Allow-Credentials: true. Fetch treats * literally in that case — as ' +
          'permission to send a header whose name is the single character "*" — so it grants ' +
          'nothing, and every non-safelisted header the client tries to send is refused at the ' +
          'pre-flight. This is the same class of mistake as CM003: a wildcard written where the ' +
          'credentialed path requires an explicit list. The endpoint is more closed than ' +
          'intended, and the fix someone reaches for is to enumerate the headers, which is when ' +
          'Authorization usually appears.',
        literalWildcard.map((o) => o.index),
      ),
    );
  }

  const authAllowed = ctx.capture.observations.filter(
    (o) => o.headers.allowHeaders?.includes('authorization') === true && untrusted.has(o.index),
  );
  if (authAllowed.length > 0) {
    out.push(
      finding(
        'CM010',
        'medium',
        'Access-Control-Allow-Headers lists Authorization on a response to an origin that ' +
          'should not have been accepted. This does not hand the attacker a token they do not ' +
          'already have. What it does is remove the implicit protection that a custom or ' +
          'authorization header gives an endpoint: a request carrying one is never a simple ' +
          'request, so it cannot be forged cross-origin without the server agreeing to it at ' +
          'the pre-flight, and plenty of APIs rely on exactly that instead of CSRF tokens. ' +
          'With this header allowed, an attacker page can forge those requests too. Note also ' +
          'that Fetch requires Authorization to be listed explicitly: it is the one header ' +
          'Access-Control-Allow-Headers: * never covers, so its presence here is a deliberate ' +
          'entry rather than a side effect of a wildcard.',
        authAllowed.map((o) => o.index),
      ),
    );
  }

  return out;
}

function ruleAllowMethods(ctx: Context): Finding[] {
  const out: Finding[] = [];
  const untrusted = acceptedUntrustedIndices(ctx);

  const literalWildcard = ctx.capture.observations.filter(
    (o) => o.headers.allowMethods?.includes('*') === true && o.headers.acacHonoured,
  );
  if (literalWildcard.length > 0) {
    out.push(
      finding(
        'CM011',
        'low',
        'Access-Control-Allow-Methods is * on a credentialed response. As with ' +
          'Access-Control-Allow-Headers, Fetch treats the wildcard literally once credentials ' +
          'are in play, so no non-simple method is actually permitted and the pre-flight fails ' +
          'for PUT, DELETE and PATCH. Reported because it misstates the intent of the policy, ' +
          'not because it opens anything.',
        literalWildcard.map((o) => o.index),
      ),
    );
  }

  const dangerous = ctx.capture.observations.filter((o) => {
    if (!untrusted.has(o.index)) return false;
    const methods = o.headers.allowMethods;
    return methods !== null && methods !== undefined && STATE_CHANGING.some((m) => methods.includes(m));
  });
  if (dangerous.length > 0) {
    const listed = [
      ...new Set(dangerous.flatMap((o) => (o.headers.allowMethods ?? []).filter((m) => STATE_CHANGING.includes(m)))),
    ].sort();
    out.push(
      finding(
        'CM011',
        'medium',
        `Access-Control-Allow-Methods permits ${listed.join(', ').toUpperCase()} for an origin ` +
          'that should not have been accepted. The origin bug on its own is a read primitive: ' +
          "the attacker's page learns the contents of an authenticated response. With a " +
          'state-changing method allowed as well it is also a write primitive, so the impact ' +
          'section of the report should cover modification and deletion, not just disclosure.',
        dangerous.map((o) => o.index),
        { facts: { 'state-changing methods allowed': listed.join(', ') } },
      ),
    );
  }

  return out;
}

/* ------------------------------------------------------------------ *
 * CM012 — pre-flight versus actual
 * ------------------------------------------------------------------ */

function rulePreflightMismatch(ctx: Context): Finding[] {
  const out: Finding[] = [];
  const groups = new Map<string, { preflight: Observation[]; actual: Observation[] }>();
  for (const o of ctx.capture.observations) {
    const key = `${o.url}\u0000${describeRequestOrigin(o)}`;
    const group = groups.get(key) ?? { preflight: [], actual: [] };
    if (o.isPreflight) group.preflight.push(o);
    else group.actual.push(o);
    groups.set(key, group);
  }

  for (const [key, group] of [...groups.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    const origin = key.split('\u0000')[1] ?? '';
    const pre = group.preflight[0];
    const act = group.actual[0];
    if (pre === undefined || act === undefined) continue;

    const preAllows = pre.passesCorsCheckWithCredentials || pre.passesCorsCheckWithoutCredentials;
    const actAllows = act.passesCorsCheckWithCredentials || act.passesCorsCheckWithoutCredentials;

    if (preAllows && !actAllows) {
      out.push(
        finding(
          'CM012',
          'medium',
          `For origin ${origin} the pre-flight passes the CORS check but the actual response does ` +
            'not. A tester who probed with OPTIONS alone would report this as exploitable and be ' +
            'wrong: the browser completes the pre-flight, issues the real request, and then ' +
            'discards the response because the real response does not allow the origin. The ' +
            'mismatch is still worth reporting as a configuration defect, because the two ' +
            'responses are produced by different code — typically a gateway answering OPTIONS ' +
            'and the application answering everything else — and whichever is wrong today, the ' +
            'two will not stay in step.',
          [pre.index, act.index],
          { origin },
        ),
      );
    } else if (!preAllows && actAllows) {
      out.push(
        finding(
          'CM012',
          'medium',
          `For origin ${origin} the actual response passes the CORS check but the pre-flight does ` +
            'not. Simple requests — GET, HEAD, and POST with a safelisted content type — never ' +
            'trigger a pre-flight, so they go through and the response is readable. Anything ' +
            'non-simple is blocked. A tester who probed only with OPTIONS would have concluded ' +
            'the endpoint was safe and closed the lead; the read primitive is real.',
          [pre.index, act.index],
          { origin },
        ),
      );
    } else if (pre.headers.acacHonoured !== act.headers.acacHonoured) {
      out.push(
        finding(
          'CM012',
          'medium',
          `For origin ${origin} exactly one of the pre-flight and the actual response sets ` +
            'Access-Control-Allow-Credentials: true. The credentials check in Fetch is applied ' +
            'to both, so the credentialed read fails at whichever response omits it — but the ' +
            'policy plainly intends to allow credentials, and a tester probing the other ' +
            'response will read the opposite verdict off it.',
          [pre.index, act.index],
          {
            origin,
            facts: {
              'pre-flight ACAC': pre.headers.acacRaw ?? '(absent)',
              'actual ACAC': act.headers.acacRaw ?? '(absent)',
            },
          },
        ),
      );
    }

    if (act.headers.allowMethods !== null || act.headers.allowHeaders !== null) {
      if (pre.headers.allowMethods === null && pre.headers.allowHeaders === null) {
        out.push(
          finding(
            'CM012',
            'info',
            `For origin ${origin} the actual response carries Access-Control-Allow-Methods or ` +
              'Access-Control-Allow-Headers while the pre-flight carries neither. Browsers read ' +
              'those two headers from the pre-flight response only and ignore them anywhere ' +
              'else, so the policy they describe is not in force. Harmless, but it means a ' +
              'reviewer reading the application config will see a method and header allowlist ' +
              'that no browser consults.',
            [pre.index, act.index],
            { origin },
          ),
        );
      }
    }
  }

  return out;
}

/* ------------------------------------------------------------------ *
 * CM013 / CM014 / CM015 / CM016
 * ------------------------------------------------------------------ */

function ruleUnauthenticatedResource(ctx: Context): Finding[] {
  if (ctx.authState === 'authenticated') return [];
  const withAcao = ctx.capture.observations.filter((o) => o.headers.acao !== null);
  if (withAcao.length === 0) return [];
  const declared = ctx.capture.authenticated === false;
  return [
    finding(
      'CM013',
      'info',
      `Access-Control-Allow-Origin is present on ${ctx.capture.resource}, but ${
        declared
          ? 'the capture declares the resource carries no credentials.'
          : 'nothing in the capture indicates the resource carries credentials: no request sent a ' +
            'Cookie or Authorization header, no response set a cookie, and no response allowed ' +
            'credentials.'
      } A cross-origin read of a response that carries no session discloses nothing the attacker ` +
        'could not have fetched from their own server, so a permissive ACAO here is a design ' +
        'choice rather than a vulnerability. This is recorded so the next person triaging the ' +
        'capture does not spend an afternoon on it.' +
        (declared
          ? ''
          : ' If the resource does return authenticated content, set "authenticated": true in ' +
            'the capture and re-run: the credential-dependent rules will then grade it properly.'),
      withAcao.map((o) => o.index),
    ),
  ];
}

function ruleCredentialsCasing(ctx: Context): Finding[] {
  const matching = ctx.capture.observations.filter((o) => {
    const raw = o.headers.acacRaw;
    if (raw === null || raw === 'true') return false;
    return raw.toLowerCase() !== 'false';
  });
  if (matching.length === 0) return [];
  const values = [...new Set(matching.map((o) => o.headers.acacRaw ?? ''))].sort();
  return [
    finding(
      'CM014',
      'info',
      `Access-Control-Allow-Credentials was present with the value ${values
        .map((v) => JSON.stringify(v))
        .join(', ')}. The CORS check in Fetch compares this header against the byte string ` +
        '"true", so anything else — True, TRUE, 1, yes — is not honoured and the credentialed ' +
        'read fails. The practical reading is that someone meant to allow credentials and the ' +
        'policy does not, which makes every credential-dependent rule in this report grade ' +
        'lower than the configuration intends. Confirm the browser behaviour directly before ' +
        'relying on either reading: this tool implements the standard, and an implementation ' +
        'may be more lenient than the standard.',
      matching.map((o) => o.index),
      { facts: { 'observed values': values.join(', ') } },
    ),
  ];
}

function ruleMalformedAcao(ctx: Context): Finding[] {
  const matching = ctx.capture.observations.filter((o) => {
    const acao = o.headers.acao;
    if (acao === null) return false;
    if (acao.multiple) return true;
    if (acao.value.kind === 'invalid') return true;
    return acao.value.kind === 'origin' && !acao.value.canonical;
  });
  if (matching.length === 0) return [];
  const reasons = new Set<string>();
  for (const o of matching) {
    const acao = o.headers.acao;
    if (acao === null) continue;
    if (acao.multiple) reasons.add('sent more than once, or as a comma-separated list');
    else if (acao.value.kind === 'invalid') reasons.add(`${acao.value.reason}`);
    else reasons.add('not the canonical origin serialisation (a trailing slash, a path, or an explicit default port)');
  }
  return [
    finding(
      'CM015',
      'low',
      `The Access-Control-Allow-Origin value is malformed: ${[...reasons].sort().join('; ')}. ` +
        'Browsers compare the header against the serialised request origin byte for byte, so ' +
        'none of these forms matches anything and the endpoint is closed — by accident rather ' +
        'than by policy. It is reported because the value is evidently being assembled by ' +
        'string concatenation somewhere, and that is the same code path that produces the ' +
        'suffix and prefix bugs elsewhere in this table. Re-test after the header is fixed; the ' +
        'policy underneath it has never actually been exercised.',
      matching.map((o) => o.index),
    ),
  ];
}

function ruleReflectionWithoutCredentials(ctx: Context): Finding[] {
  if (ctx.authState === 'unauthenticated') return [];
  const groups = groupAccepted(
    ctx,
    (a) => isUntrusted(a) && a.relation.hostRelation === 'unrelated' && !a.withCredentials,
  );
  return groups.map((g) =>
    finding(
      'CM016',
      'low',
      `${g.origin.serialized} is unrelated to the resource and to every declared trusted origin, ` +
        'and the server echoed it into Access-Control-Allow-Origin. Credentials are not allowed, ' +
        "so the victim's session does not cross and nothing authenticated is disclosed. The " +
        'finding is that origin validation is absent: the distance between this and CM001 is one ' +
        'line of configuration, and that line gets added the first time a feature needs cookies. ' +
        'It also already matters if the resource is only reachable from inside a network the ' +
        "victim's browser sits in — an intranet host, a cloud metadata service, a service bound " +
        'to localhost — because there the browser itself is the privileged position, and no ' +
        'session is needed.',
      g.evidence,
      {
        origin: g.origin.serialized,
        ...(ctx.authState === 'unknown'
          ? {
              dependency:
                'confirm whether the resource returns authenticated content; the capture does not say',
            }
          : {}),
      },
    ),
  );
}
