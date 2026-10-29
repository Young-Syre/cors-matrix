import assert from 'node:assert/strict';
import { test } from 'node:test';

import { CaptureError, parseCaptures } from '../src/capture.js';

function load(file: unknown): ReturnType<typeof parseCaptures> {
  return parseCaptures(JSON.stringify(file), 'fixture.json');
}

const MINIMAL = {
  version: 1,
  resource: 'https://api.acme.example/v1/me',
  observations: [{ requestOrigin: 'https://app.acme.example', responseHeaders: {} }],
};

test('a minimal capture loads, defaults the method to GET and inherits the resource URL', () => {
  const [capture] = load(MINIMAL);
  assert.ok(capture);
  assert.equal(capture.observations.length, 1);
  const first = capture.observations[0];
  assert.equal(first?.method, 'GET');
  assert.equal(first?.url, 'https://api.acme.example/v1/me');
  assert.equal(first?.isPreflight, false);
  assert.equal(first?.index, 1);
});

test('the resource origin is always trusted, even with no trustedOrigins', () => {
  const [capture] = load(MINIMAL);
  assert.deepEqual(capture?.trustedOrigins.map((t) => t.serialized), ['https://api.acme.example']);
});

test('trusted origins from the file and from options are merged and de-duplicated', () => {
  const captures = parseCaptures(
    JSON.stringify({ ...MINIMAL, trustedOrigins: ['https://app.acme.example'] }),
    'fixture.json',
    { trustedOrigins: ['https://app.acme.example', 'https://admin.acme.example'] },
  );
  assert.deepEqual(captures[0]?.trustedOrigins.map((t) => t.serialized), [
    'https://api.acme.example',
    'https://app.acme.example',
    'https://admin.acme.example',
  ]);
});

test('an OPTIONS observation is marked as a pre-flight', () => {
  const [capture] = load({
    ...MINIMAL,
    observations: [{ requestOrigin: 'https://app.acme.example', method: 'options', responseHeaders: {} }],
  });
  assert.equal(capture?.observations[0]?.isPreflight, true);
  assert.equal(capture?.observations[0]?.method, 'OPTIONS');
});

test('omitting requestOrigin records a request that sent no Origin header', () => {
  const [capture] = load({ ...MINIMAL, observations: [{ responseHeaders: {} }] });
  assert.equal(capture?.observations[0]?.requestOrigin, null);
});

test('requestOrigin set to JSON null is rejected as ambiguous', () => {
  // The literal null origin and "no Origin header" are different observations
  // and must not share a representation.
  assert.throws(
    () => load({ ...MINIMAL, observations: [{ requestOrigin: null, responseHeaders: {} }] }),
    (err: unknown) => err instanceof CaptureError && /ambiguous/.test((err as Error).message),
  );
});

test('the string "null" records the literal null origin', () => {
  const [capture] = load({ ...MINIMAL, observations: [{ requestOrigin: 'null', responseHeaders: {} }] });
  assert.equal(capture?.observations[0]?.requestOrigin?.kind, 'null');
});

test('invalid JSON, a non-object top level, and a bad version are all rejected', () => {
  assert.throws(() => parseCaptures('{oops', 'fixture.json'), CaptureError);
  assert.throws(() => parseCaptures('[]', 'fixture.json'), CaptureError);
  assert.throws(() => load({ ...MINIMAL, version: 2 }), CaptureError);
});

test('a missing resource, a non-URL resource and empty observations are all rejected', () => {
  assert.throws(() => load({ observations: [] }), CaptureError);
  assert.throws(() => load({ ...MINIMAL, resource: 'api.acme.example/v1' }), CaptureError);
  assert.throws(() => load({ ...MINIMAL, observations: [] }), CaptureError);
});

test('an observation without responseHeaders is rejected by index', () => {
  assert.throws(
    () => load({ ...MINIMAL, observations: [{ requestOrigin: 'https://app.acme.example' }] }),
    (err: unknown) => err instanceof CaptureError && /observation 1/.test((err as Error).message),
  );
});

test('a trusted origin that is not an origin is rejected', () => {
  assert.throws(
    () => load({ ...MINIMAL, trustedOrigins: ['https://app.acme.example/path'] }),
    CaptureError,
  );
});

test('a repeated response header may be given as an array', () => {
  const [capture] = load({
    ...MINIMAL,
    observations: [
      {
        requestOrigin: 'https://app.acme.example',
        responseHeaders: { 'access-control-allow-origin': ['https://a.test', 'https://b.test'] },
      },
    ],
  });
  assert.equal(capture?.observations[0]?.headers.acao?.multiple, true);
});

/* HAR conversion */

const HAR = {
  log: {
    version: '1.2',
    pages: [{ id: 'p1', title: 'https://app.acme.example/dashboard' }],
    entries: [
      {
        request: {
          method: 'GET',
          url: 'https://api.acme.example/v1/me?a=1',
          headers: [
            { name: 'origin', value: 'https://app.acme.example' },
            { name: 'cookie', value: 'sid=synthetic' },
          ],
        },
        response: {
          status: 200,
          headers: [
            { name: 'access-control-allow-origin', value: 'https://app.acme.example' },
            { name: 'access-control-allow-credentials', value: 'true' },
          ],
        },
      },
      {
        request: {
          method: 'GET',
          url: 'https://api.acme.example/v1/me?a=2',
          headers: [{ name: 'origin', value: 'https://probe.example' }],
        },
        response: {
          status: 200,
          headers: [{ name: 'access-control-allow-origin', value: 'https://probe.example' }],
        },
      },
      {
        request: {
          method: 'GET',
          url: 'https://api.acme.example/v1/other',
          headers: [{ name: 'origin', value: 'https://app.acme.example' }],
        },
        response: { status: 200, headers: [] },
      },
      {
        request: { method: 'GET', url: 'https://cdn.acme.example/app.css', headers: [] },
        response: { status: 200, headers: [] },
      },
    ],
  },
};

test('a HAR yields one capture per distinct request URL, ignoring the query string', () => {
  const captures = parseCaptures(JSON.stringify(HAR), 'capture.har');
  assert.equal(captures.length, 2);
  assert.deepEqual(
    captures.map((c) => c.resource).sort(),
    ['https://api.acme.example/v1/me', 'https://api.acme.example/v1/other'],
  );
});

test('HAR entries with no Origin header are skipped', () => {
  const captures = parseCaptures(JSON.stringify(HAR), 'capture.har');
  // The stylesheet request carried no Origin, so it produced no capture.
  assert.equal(
    captures.some((c) => c.resource.includes('cdn.acme.example')),
    false,
  );
});

test('the HAR page URL is adopted as a trusted origin', () => {
  const captures = parseCaptures(JSON.stringify(HAR), 'capture.har');
  const me = captures.find((c) => c.resource.endsWith('/v1/me'));
  assert.ok(me);
  assert.ok(me.trustedOrigins.some((t) => t.serialized === 'https://app.acme.example'));
});

test('HAR observations keep their method, status and both header sets', () => {
  const captures = parseCaptures(JSON.stringify(HAR), 'capture.har');
  const me = captures.find((c) => c.resource.endsWith('/v1/me'));
  assert.equal(me?.observations.length, 2);
  const first = me?.observations[0];
  assert.equal(first?.status, 200);
  assert.equal(first?.requestCarriedCredentials, true);
  assert.equal(first?.headers.acacHonoured, true);
  assert.equal(me?.observations[1]?.requestCarriedCredentials, false);
});

test('a HAR with no Origin header anywhere is rejected with a useful message', () => {
  assert.throws(
    () =>
      parseCaptures(
        JSON.stringify({ log: { entries: [{ request: { method: 'GET', url: 'https://a.test/', headers: [] } }] } }),
        'capture.har',
      ),
    (err: unknown) => err instanceof CaptureError && /Origin request header/.test((err as Error).message),
  );
});

test('a file that looks like a HAR but has no entries array is rejected', () => {
  assert.throws(() => parseCaptures(JSON.stringify({ log: {} }), 'capture.har'), CaptureError);
});
