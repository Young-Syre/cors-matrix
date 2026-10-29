/** Builders for the test suite. Every value here is fabricated. */

import { analyse } from '../src/analyse.js';
import { parseCaptures } from '../src/capture.js';
import type { AnalysisResult, CaptureFile, Finding, ObservationInput } from '../src/types.js';

export const RESOURCE = 'https://api.acme-widgets.example/v1/me';
export const APP_ORIGIN = 'https://app.acme-widgets.example';
export const EVIL_ORIGIN = 'https://probe.example';

/** A credentialed observation whose ACAO echoes the request origin. */
export function echo(requestOrigin: string, extra: Record<string, string> = {}): ObservationInput {
  return {
    requestOrigin,
    method: 'GET',
    status: 200,
    requestHeaders: { Cookie: 'sid=synthetic' },
    responseHeaders: {
      'access-control-allow-origin': requestOrigin,
      'access-control-allow-credentials': 'true',
      ...extra,
    },
  };
}

/** An observation whose ACAO echoes the origin but allows no credentials. */
export function echoNoCreds(requestOrigin: string, extra: Record<string, string> = {}): ObservationInput {
  return {
    requestOrigin,
    method: 'GET',
    status: 200,
    requestHeaders: { Cookie: 'sid=synthetic' },
    responseHeaders: { 'access-control-allow-origin': requestOrigin, ...extra },
  };
}

/** An observation in which the server returned no CORS headers at all. */
export function reject(requestOrigin: string): ObservationInput {
  return {
    requestOrigin,
    method: 'GET',
    status: 200,
    requestHeaders: { Cookie: 'sid=synthetic' },
    responseHeaders: { 'content-type': 'application/json' },
  };
}

export function raw(
  requestOrigin: string | undefined,
  responseHeaders: Record<string, string | string[]>,
  method = 'GET',
): ObservationInput {
  return {
    ...(requestOrigin === undefined ? {} : { requestOrigin }),
    method,
    status: 200,
    requestHeaders: { Cookie: 'sid=synthetic' },
    responseHeaders,
  };
}

export function capture(observations: ObservationInput[], overrides: Partial<CaptureFile> = {}): CaptureFile {
  return {
    version: 1,
    resource: RESOURCE,
    trustedOrigins: [APP_ORIGIN],
    authenticated: true,
    observations,
    ...overrides,
  };
}

/** Build, parse and analyse a capture in one step. */
export function run(observations: ObservationInput[], overrides: Partial<CaptureFile> = {}): AnalysisResult {
  const file = capture(observations, overrides);
  const captures = parseCaptures(JSON.stringify(file), 'test-capture.json');
  const first = captures[0];
  if (first === undefined) throw new Error('no capture produced');
  return analyse(first);
}

/**
 * Analyse a capture that does not declare whether the resource is
 * authenticated, which is the state the analyser has to infer.
 */
export function runUndeclaredAuth(
  observations: ObservationInput[],
  overrides: Partial<CaptureFile> = {},
): AnalysisResult {
  const file: CaptureFile = capture(observations, overrides);
  delete file.authenticated;
  const captures = parseCaptures(JSON.stringify(file), 'test-capture.json');
  const first = captures[0];
  if (first === undefined) throw new Error('no capture produced');
  return analyse(first);
}

export function rules(result: AnalysisResult): string[] {
  return [...new Set(result.findings.map((f) => f.rule))].sort();
}

export function findingFor(result: AnalysisResult, rule: string): Finding {
  const match = result.findings.find((f) => f.rule === rule);
  if (match === undefined) {
    throw new Error(`expected rule ${rule}, got ${JSON.stringify(rules(result))}`);
  }
  return match;
}

export function hasRule(result: AnalysisResult, rule: string): boolean {
  return result.findings.some((f) => f.rule === rule);
}
