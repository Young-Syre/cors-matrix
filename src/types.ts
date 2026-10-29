import type { OriginValue, TupleOrigin } from './origin.js';

/* ------------------------------------------------------------------ *
 * Input: the capture file format
 * ------------------------------------------------------------------ */

/**
 * A capture file records what a server answered for a set of request origins.
 * It is deliberately flat JSON: a tester produces one with a short shell loop
 * over `curl -H "Origin: ..." -D -`, and `cors-matrix probe` emits the exact
 * list of origins to loop over.
 */
export interface CaptureFile {
  /** Format version. Only `1` is understood. Optional, defaults to 1. */
  version?: number;
  /** Absolute URL of the resource whose policy is under test. */
  resource: string;
  /** Free text, echoed into reports. */
  description?: string;
  /**
   * Origins the operator asserts are legitimately allowed. The resource's own
   * origin is always trusted. Without this, a legitimately-allowed first-party
   * origin is reported as an accepted third-party origin.
   */
  trustedOrigins?: string[];
  /**
   * Whether the resource carries anything worth stealing — a session cookie, a
   * bearer token, or any authenticated response body. Omit to let the analyser
   * infer it from `Cookie`/`Authorization` request headers and `Set-Cookie`.
   */
  authenticated?: boolean;
  observations: ObservationInput[];
}

export interface ObservationInput {
  /**
   * The value sent in the `Origin` request header. Omit the field entirely to
   * record a request that sent no `Origin` header. Use the string `"null"` for
   * the literal null origin that a sandboxed iframe or a `data:` document
   * sends. JSON `null` is rejected, because it reads as both.
   */
  requestOrigin?: string;
  /** Defaults to `GET`. `OPTIONS` marks the observation as a pre-flight. */
  method?: string;
  /** Defaults to the capture's `resource`. */
  url?: string;
  status?: number;
  /** Request headers, used to infer whether credentials were in play. */
  requestHeaders?: Record<string, string>;
  /** Response headers. A repeated header may be given as an array. */
  responseHeaders: Record<string, string | string[]>;
  note?: string;
}

/* ------------------------------------------------------------------ *
 * Parsed observations
 * ------------------------------------------------------------------ */

export interface AcaoHeader {
  readonly raw: string;
  readonly value: OriginValue;
  /** The response carried more than one ACAO header or a comma-joined value. */
  readonly multiple: boolean;
}

export interface CorsResponseHeaders {
  readonly acao: AcaoHeader | null;
  /** The raw `Access-Control-Allow-Credentials` value, if the header is present. */
  readonly acacRaw: string | null;
  /**
   * True only for the byte string `true`. The Fetch standard compares the
   * header against `true` byte-for-byte, so `True` is not honoured.
   */
  readonly acacHonoured: boolean;
  readonly allowMethods: readonly string[] | null;
  readonly allowHeaders: readonly string[] | null;
  readonly exposeHeaders: readonly string[] | null;
  readonly maxAge: string | null;
  readonly vary: readonly string[] | null;
  readonly setsCookie: boolean;
}

export type AcaoShape = 'absent' | 'wildcard' | 'null' | 'reflected' | 'fixed' | 'invalid';

export interface Observation {
  /** 1-based index as it appeared in the capture, used in evidence lines. */
  readonly index: number;
  readonly requestOrigin: OriginValue | null;
  readonly method: string;
  readonly url: string;
  readonly isPreflight: boolean;
  readonly status: number | null;
  readonly headers: CorsResponseHeaders;
  readonly acaoShape: AcaoShape;
  /** Fetch CORS check with credentials mode "same-origin"/"omit". */
  readonly passesCorsCheckWithoutCredentials: boolean;
  /** Fetch CORS check with credentials mode "include". */
  readonly passesCorsCheckWithCredentials: boolean;
  /** The request carried a `Cookie` or `Authorization` header. */
  readonly requestCarriedCredentials: boolean;
  readonly note: string | null;
}

export interface Capture {
  readonly resource: string;
  readonly resourceOrigin: TupleOrigin;
  readonly description: string | null;
  readonly trustedOrigins: readonly TupleOrigin[];
  readonly authenticated: boolean | null;
  readonly observations: readonly Observation[];
  /** Where the capture came from, for report headings. */
  readonly source: string;
}

/* ------------------------------------------------------------------ *
 * Output: findings
 * ------------------------------------------------------------------ */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export const SEVERITY_ORDER: readonly Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

export function severityRank(s: Severity): number {
  return SEVERITY_ORDER.indexOf(s);
}

export interface RuleMeta {
  readonly id: string;
  readonly name: string;
  /** The severity this rule reaches at worst. Used for the README table. */
  readonly maxSeverity: Severity;
  readonly summary: string;
}

export interface Finding {
  readonly rule: string;
  readonly name: string;
  readonly severity: Severity;
  /** One paragraph: what was observed and why it matters. */
  readonly detail: string;
  /** Capture observation indices that support the finding. */
  readonly evidence: readonly number[];
  /** Accepted origin at the centre of the finding, when there is one. */
  readonly origin?: string;
  /** Extra machine-readable facts, rendered as a key/value list. */
  readonly facts?: Readonly<Record<string, string>>;
  /** Whether a browser can actually produce the condition. */
  readonly browserReachable: boolean;
  /** Something the operator must establish for the finding to be exploitable. */
  readonly dependency?: string;
}

export interface PolicySummary {
  /**
   * The server echoes the request origin back, confirmed by at least two
   * distinct origins *outside* the trusted set coming back in ACAO. It does
   * not mean every origin is echoed: a policy that echoes whatever passes a
   * broken check reflects too, within the set its check accepts.
   */
  readonly reflectsOrigin: boolean;
  /** How many origins outside the trusted set were echoed back. */
  readonly echoedUntrustedOrigins: number;
  readonly distinctAcaoValues: readonly string[];
  readonly credentialsAllowed: boolean;
  readonly acceptedOrigins: readonly string[];
  readonly rejectedOrigins: readonly string[];
  readonly preflightCount: number;
}

export interface AnalysisResult {
  readonly resource: string;
  readonly source: string;
  readonly description: string | null;
  readonly trustedOrigins: readonly string[];
  readonly observationCount: number;
  readonly policy: PolicySummary;
  readonly findings: readonly Finding[];
  /** Non-fatal input problems: an unparseable origin, a duplicate probe. */
  readonly warnings: readonly string[];
}
