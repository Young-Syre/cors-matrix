/** Header-map handling and the Fetch CORS check. */

import { parseOriginValue, sameOrigin, type OriginValue } from './origin.js';
import type { AcaoHeader, AcaoShape, CorsResponseHeaders } from './types.js';

/** A case-insensitive view over a plain header object. */
export class HeaderMap {
  private readonly entries = new Map<string, string[]>();

  constructor(source?: Readonly<Record<string, string | string[]>>) {
    if (source === undefined) return;
    for (const [name, value] of Object.entries(source)) {
      this.append(name, value);
    }
  }

  append(name: string, value: string | string[]): void {
    const key = name.toLowerCase();
    const list = this.entries.get(key) ?? [];
    if (Array.isArray(value)) list.push(...value);
    else list.push(value);
    this.entries.set(key, list);
  }

  /** All values for a header, in order. */
  all(name: string): string[] {
    return this.entries.get(name.toLowerCase()) ?? [];
  }

  /** The first value for a header, trimmed, or null when absent. */
  get(name: string): string | null {
    const list = this.all(name);
    const first = list[0];
    return first === undefined ? null : first.trim();
  }

  has(name: string): boolean {
    return this.entries.has(name.toLowerCase());
  }

  /** Comma-separated list value, split and lowercased. Empty entries dropped. */
  list(name: string): string[] | null {
    const list = this.all(name);
    if (list.length === 0) return null;
    return list
      .join(',')
      .split(',')
      .map((part) => part.trim().toLowerCase())
      .filter((part) => part !== '');
  }
}

/**
 * Extract the `Access-Control-Allow-Origin` header.
 *
 * A response carrying the header twice, or once with a comma-joined value, is
 * malformed. Browsers reject it outright, so the policy is effectively closed
 * — but the fact is reported, because it means the value is being concatenated
 * by hand somewhere and the next refactor may well make it work.
 */
export function readAcao(headers: HeaderMap): AcaoHeader | null {
  const all = headers.all('access-control-allow-origin');
  if (all.length === 0) return null;
  const raw = (all[0] ?? '').trim();
  const multiple = all.length > 1 || raw.includes(',');
  return { raw, value: parseOriginValue(raw), multiple };
}

export function readCorsResponseHeaders(headers: HeaderMap): CorsResponseHeaders {
  const acacRaw = headers.get('access-control-allow-credentials');
  return {
    acao: readAcao(headers),
    acacRaw,
    // The Fetch standard's CORS check compares this header against the byte
    // string `true`. `True` and `TRUE` are therefore not honoured -- and
    // neither is a response that sends the header twice, which Fetch combines
    // into `true, false`. readAcao already handles that case for ACAO; this
    // read used `get`, which is `all(name)[0]`, so it honoured the first value
    // and graded on a credentialed read the browser would refuse.
    acacHonoured:
      headers.all('access-control-allow-credentials').length === 1 && acacRaw === 'true',
    allowMethods: headers.list('access-control-allow-methods'),
    allowHeaders: headers.list('access-control-allow-headers'),
    exposeHeaders: headers.list('access-control-expose-headers'),
    maxAge: headers.get('access-control-max-age'),
    vary: headers.list('vary'),
    setsCookie: headers.has('set-cookie'),
  };
}

/** True when a `Vary` list covers the `Origin` header. */
export function varyCoversOrigin(vary: readonly string[] | null): boolean {
  if (vary === null) return false;
  return vary.includes('origin') || vary.includes('*');
}

/**
 * The CORS check from the Fetch standard, step for step -- plus the header
 * extraction the steps assume has already succeeded, which is the
 * `acao.multiple` test below: a response sending the header twice, or once
 * comma-joined, has no single value for step 1 to take.
 *
 *   1. Let origin be ACAO. If absent, return failure.
 *   2. If credentials mode is not "include" and origin is `*`, return success.
 *   3. If the serialised request origin is not origin, return failure.
 *   4. If credentials mode is not "include", return success.
 *   5. If ACAC is `true`, return success.
 *   6. Return failure.
 *
 * Two consequences fall out of this and both matter for grading:
 * `ACAO: *` with `ACAC: true` fails at step 3 for a credentialed request, and
 * a request that sent no `Origin` header has no serialised request origin to
 * match at step 3, so only the wildcard path can succeed.
 */
export function corsCheck(
  acao: AcaoHeader | null,
  acacHonoured: boolean,
  requestOrigin: OriginValue | null,
  credentialsMode: 'include' | 'omit',
): boolean {
  if (acao === null) return false;
  if (acao.multiple) return false;
  if (credentialsMode !== 'include' && acao.value.kind === 'wildcard') return true;
  if (!originsMatch(acao.value, requestOrigin)) return false;
  if (credentialsMode !== 'include') return true;
  return acacHonoured;
}

/**
 * Step 3 of the CORS check: ACAO equals the serialised request origin.
 *
 * A byte comparison, as the standard says, on the values as they appeared on
 * the wire. Comparing parsed triples instead was wrong in the direction that
 * invents a finding: `Access-Control-Allow-Origin: https://evil.invalid:443`
 * parses to the same triple as `https://evil.invalid` and was graded CM001
 * critical, while CM015 in the same report said the endpoint was closed by
 * accident. A browser agrees with CM015 -- it rejects the response and the
 * generated proof-of-concept page could not have worked.
 *
 * This is also why the equality is on `raw` rather than `serialized`: a page
 * served from `https://app.acme.example.` sends that trailing dot in Origin,
 * and a server echoing it back byte for byte does pass the check.
 */
function originsMatch(acao: OriginValue, requestOrigin: OriginValue | null): boolean {
  if (requestOrigin === null) return false;
  if (acao.kind === 'null' && requestOrigin.kind === 'null') return true;
  if (acao.kind === 'origin' && requestOrigin.kind === 'origin') {
    return acao.raw === requestOrigin.raw;
  }
  return false;
}

/** Describe the shape of the ACAO value relative to the request origin. */
export function acaoShapeOf(acao: AcaoHeader | null, requestOrigin: OriginValue | null): AcaoShape {
  if (acao === null) return 'absent';
  switch (acao.value.kind) {
    case 'wildcard':
      return 'wildcard';
    case 'null':
      return 'null';
    case 'invalid':
      return 'invalid';
    case 'origin':
      if (requestOrigin !== null && sameOrigin(acao.value, requestOrigin)) return 'reflected';
      return 'fixed';
  }
}

/** True when the request headers show a session cookie or bearer token. */
export function requestCarriedCredentials(headers: HeaderMap): boolean {
  return headers.has('cookie') || headers.has('authorization');
}
