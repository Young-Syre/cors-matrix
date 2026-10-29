/** Loading and validating capture files, and converting HAR files into them. */

import { readFileSync } from 'node:fs';
import { basename } from 'node:path';

import {
  HeaderMap,
  acaoShapeOf,
  corsCheck,
  readCorsResponseHeaders,
  requestCarriedCredentials,
} from './headers.js';
import { originOfUrl, parseOriginValue, type TupleOrigin } from './origin.js';
import type { Capture, CaptureFile, Observation, ObservationInput } from './types.js';

export class CaptureError extends Error {}

export interface LoadOptions {
  /** Trusted origins supplied on the command line, merged with the file's. */
  readonly trustedOrigins?: readonly string[];
}

/**
 * Read a capture file or a HAR file from disk.
 *
 * A HAR can describe requests to many resources, so it yields one capture per
 * distinct request URL that carried an `Origin` header.
 */
export function loadCaptures(path: string, options: LoadOptions = {}): Capture[] {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch (err) {
    throw new CaptureError(`cannot read ${path}: ${(err as Error).message}`);
  }
  return parseCaptures(text, basename(path), options);
}

/** Parse capture JSON or HAR JSON already in memory. */
export function parseCaptures(text: string, source: string, options: LoadOptions = {}): Capture[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new CaptureError(`${source} is not valid JSON: ${(err as Error).message}`);
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new CaptureError(`${source} must contain a JSON object at the top level`);
  }
  if ('log' in parsed) return captureFromHar(parsed as HarFile, source, options);
  return [buildCapture(parsed as CaptureFile, source, options)];
}

/* ------------------------------------------------------------------ *
 * Native capture format
 * ------------------------------------------------------------------ */

function buildCapture(file: CaptureFile, source: string, options: LoadOptions): Capture {
  if (file.version !== undefined && file.version !== 1) {
    throw new CaptureError(`${source} declares version ${String(file.version)}; only 1 is understood`);
  }
  if (typeof file.resource !== 'string' || file.resource === '') {
    throw new CaptureError(`${source} must set "resource" to the absolute URL under test`);
  }
  const resourceOrigin = originOfUrl(file.resource);
  if (resourceOrigin.kind !== 'origin') {
    throw new CaptureError(`${source}: "resource" ${resourceOrigin.reason}`);
  }
  if (!Array.isArray(file.observations) || file.observations.length === 0) {
    throw new CaptureError(`${source} must set "observations" to a non-empty array`);
  }

  const declared = [...(file.trustedOrigins ?? []), ...(options.trustedOrigins ?? [])];
  const trusted: TupleOrigin[] = [resourceOrigin];
  for (const value of declared) {
    const parsedTrusted = parseOriginValue(value);
    if (parsedTrusted.kind !== 'origin') {
      throw new CaptureError(`${source}: trusted origin ${JSON.stringify(value)} is not an origin`);
    }
    if (!trusted.some((t) => t.serialized === parsedTrusted.serialized)) trusted.push(parsedTrusted);
  }

  const observations = file.observations.map((input, i) =>
    buildObservation(input, i + 1, file.resource, source),
  );

  return {
    resource: file.resource,
    resourceOrigin,
    description: file.description ?? null,
    trustedOrigins: trusted,
    authenticated: file.authenticated ?? null,
    observations,
    source,
  };
}

function buildObservation(
  input: ObservationInput,
  index: number,
  defaultUrl: string,
  source: string,
): Observation {
  if (typeof input !== 'object' || input === null) {
    throw new CaptureError(`${source}: observation ${index} is not an object`);
  }
  if (input.requestOrigin === null) {
    throw new CaptureError(
      `${source}: observation ${index} sets "requestOrigin" to JSON null, which is ambiguous. ` +
        'Omit the field for "no Origin header was sent", or use the string "null" for the ' +
        'literal null origin a sandboxed iframe sends.',
    );
  }
  if (typeof input.responseHeaders !== 'object' || input.responseHeaders === null) {
    throw new CaptureError(`${source}: observation ${index} must set "responseHeaders" to an object`);
  }

  const requestOrigin = input.requestOrigin === undefined ? null : parseOriginValue(input.requestOrigin);
  const method = (input.method ?? 'GET').toUpperCase();
  const responseHeaders = new HeaderMap(input.responseHeaders);
  const requestHeaders = new HeaderMap(input.requestHeaders);
  const headers = readCorsResponseHeaders(responseHeaders);

  return {
    index,
    requestOrigin,
    method,
    url: input.url ?? defaultUrl,
    isPreflight: method === 'OPTIONS',
    status: input.status ?? null,
    headers,
    acaoShape: acaoShapeOf(headers.acao, requestOrigin),
    passesCorsCheckWithoutCredentials: corsCheck(headers.acao, headers.acacHonoured, requestOrigin, 'omit'),
    passesCorsCheckWithCredentials: corsCheck(headers.acao, headers.acacHonoured, requestOrigin, 'include'),
    requestCarriedCredentials: requestCarriedCredentials(requestHeaders),
    note: input.note ?? null,
  };
}

/* ------------------------------------------------------------------ *
 * HAR conversion
 * ------------------------------------------------------------------ */

interface HarHeader {
  name?: unknown;
  value?: unknown;
}

interface HarEntry {
  request?: {
    method?: unknown;
    url?: unknown;
    headers?: unknown;
  };
  response?: {
    status?: unknown;
    headers?: unknown;
  };
}

interface HarFile {
  log?: {
    pages?: { title?: unknown }[];
    entries?: HarEntry[];
  };
}

function harHeaders(raw: unknown): Record<string, string | string[]> {
  const out: Record<string, string | string[]> = {};
  if (!Array.isArray(raw)) return out;
  for (const item of raw as HarHeader[]) {
    if (typeof item?.name !== 'string' || typeof item.value !== 'string') continue;
    const existing = out[item.name];
    if (existing === undefined) out[item.name] = item.value;
    else if (Array.isArray(existing)) existing.push(item.value);
    else out[item.name] = [existing, item.value];
  }
  return out;
}

function headerValue(headers: Record<string, string | string[]>, name: string): string | undefined {
  const map = new HeaderMap(headers);
  return map.get(name) ?? undefined;
}

/**
 * Convert a HAR into one capture per distinct request URL.
 *
 * Entries with no `Origin` request header are skipped: without an origin there
 * is no policy decision to observe. A HAR does not record which origins the
 * operator considers legitimate, so the page origin recorded in `log.pages`
 * (when it parses as a URL) is adopted as a trusted origin, and `--trusted`
 * remains available.
 */
function captureFromHar(har: HarFile, source: string, options: LoadOptions): Capture[] {
  const entries = har.log?.entries;
  if (!Array.isArray(entries)) {
    throw new CaptureError(`${source} looks like a HAR but has no log.entries array`);
  }

  const pageOrigins: string[] = [];
  for (const page of har.log?.pages ?? []) {
    if (typeof page?.title !== 'string') continue;
    const origin = originOfUrl(page.title);
    if (origin.kind === 'origin' && origin.host !== '') pageOrigins.push(origin.serialized);
  }

  const grouped = new Map<string, ObservationInput[]>();
  for (const entry of entries) {
    const url = entry.request?.url;
    if (typeof url !== 'string') continue;
    const requestHeaders = harHeaders(entry.request?.headers);
    const origin = headerValue(requestHeaders, 'origin');
    if (origin === undefined) continue;
    const method = typeof entry.request?.method === 'string' ? entry.request.method : 'GET';
    const status = typeof entry.response?.status === 'number' ? entry.response.status : undefined;
    const observation: ObservationInput = {
      requestOrigin: origin,
      method,
      url,
      requestHeaders: flatten(requestHeaders),
      responseHeaders: harHeaders(entry.response?.headers),
      ...(status === undefined ? {} : { status }),
    };
    const key = stripQuery(url);
    const list = grouped.get(key) ?? [];
    list.push(observation);
    grouped.set(key, list);
  }

  if (grouped.size === 0) {
    throw new CaptureError(
      `${source}: no HAR entry carried an Origin request header, so there is no CORS policy to analyse`,
    );
  }

  return [...grouped.entries()].map(([url, observations]) =>
    buildCapture(
      {
        version: 1,
        resource: url,
        description: `derived from HAR ${source}`,
        trustedOrigins: [...pageOrigins, ...(options.trustedOrigins ?? [])],
        observations,
      },
      `${source} (${url})`,
      {},
    ),
  );
}

function flatten(headers: Record<string, string | string[]>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) {
    out[name] = Array.isArray(value) ? (value[0] ?? '') : value;
  }
  return out;
}

function stripQuery(url: string): string {
  const q = url.indexOf('?');
  return q === -1 ? url : url.slice(0, q);
}
