import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  HeaderMap,
  acaoShapeOf,
  corsCheck,
  readAcao,
  readCorsResponseHeaders,
  requestCarriedCredentials,
  varyCoversOrigin,
} from '../src/headers.js';
import { parseOriginValue } from '../src/origin.js';

const APP = parseOriginValue('https://app.acme.example');
const EVIL = parseOriginValue('https://probe.example');
const NULL_ORIGIN = parseOriginValue('null');

test('HeaderMap is case-insensitive and trims values', () => {
  const h = new HeaderMap({ 'Access-Control-Allow-Origin': '  https://app.acme.example  ' });
  assert.equal(h.get('access-control-allow-origin'), 'https://app.acme.example');
  assert.equal(h.has('ACCESS-CONTROL-ALLOW-ORIGIN'), true);
  assert.equal(h.get('missing'), null);
});

test('HeaderMap keeps repeated headers in order and can list them', () => {
  const h = new HeaderMap({ vary: ['Origin', 'Accept-Encoding'] });
  assert.deepEqual(h.all('vary'), ['Origin', 'Accept-Encoding']);
  assert.deepEqual(h.list('vary'), ['origin', 'accept-encoding']);
});

test('a comma-separated list header is split and lowercased', () => {
  const h = new HeaderMap({ 'Access-Control-Allow-Methods': 'GET, POST , PUT,,' });
  assert.deepEqual(h.list('access-control-allow-methods'), ['get', 'post', 'put']);
});

test('readAcao flags a repeated header as multiple', () => {
  const twice = readAcao(new HeaderMap({ 'access-control-allow-origin': ['https://a.test', 'https://b.test'] }));
  assert.equal(twice?.multiple, true);
});

test('readAcao flags a comma-joined value as multiple', () => {
  const joined = readAcao(new HeaderMap({ 'access-control-allow-origin': 'https://a.test, https://b.test' }));
  assert.equal(joined?.multiple, true);
  assert.equal(joined?.value.kind, 'invalid');
});

test('an absent ACAO reads as null', () => {
  assert.equal(readAcao(new HeaderMap({ 'content-type': 'application/json' })), null);
});

test('Access-Control-Allow-Credentials is honoured only for the exact byte string "true"', () => {
  // Step 7 of the Fetch CORS check compares the header against `true`, so a
  // differently-cased value is not honoured by a conforming browser.
  for (const [value, expected] of [
    ['true', true],
    ['True', false],
    ['TRUE', false],
    ['1', false],
    ['yes', false],
    ['false', false],
  ] as const) {
    const headers = readCorsResponseHeaders(new HeaderMap({ 'access-control-allow-credentials': value }));
    assert.equal(headers.acacHonoured, expected, `${value} -> ${String(expected)}`);
    assert.equal(headers.acacRaw, value);
  }
});

test('readCorsResponseHeaders collects every CORS header plus Set-Cookie', () => {
  const headers = readCorsResponseHeaders(
    new HeaderMap({
      'access-control-allow-origin': 'https://app.acme.example',
      'access-control-allow-credentials': 'true',
      'access-control-allow-methods': 'GET,PUT',
      'access-control-allow-headers': 'Authorization',
      'access-control-expose-headers': 'X-Total',
      'access-control-max-age': '600',
      vary: 'Origin',
      'set-cookie': 'sid=synthetic; Path=/',
    }),
  );
  assert.deepEqual(headers.allowMethods, ['get', 'put']);
  assert.deepEqual(headers.allowHeaders, ['authorization']);
  assert.deepEqual(headers.exposeHeaders, ['x-total']);
  assert.equal(headers.maxAge, '600');
  assert.equal(headers.setsCookie, true);
});

test('varyCoversOrigin accepts Origin and the wildcard, and rejects anything else', () => {
  assert.equal(varyCoversOrigin(['origin']), true);
  assert.equal(varyCoversOrigin(['accept-encoding', 'origin']), true);
  assert.equal(varyCoversOrigin(['*']), true);
  assert.equal(varyCoversOrigin(['accept-encoding']), false);
  assert.equal(varyCoversOrigin(null), false);
});

/* The CORS check, step by step. */

test('an absent ACAO fails the check in both credentials modes', () => {
  assert.equal(corsCheck(null, false, APP, 'omit'), false);
  assert.equal(corsCheck(null, true, APP, 'include'), false);
});

test('a wildcard succeeds without credentials and fails with them', () => {
  const star = readAcao(new HeaderMap({ 'access-control-allow-origin': '*' }));
  assert.equal(corsCheck(star, false, EVIL, 'omit'), true);
  // This is the whole of CM003: step 3 requires ACAO to equal the serialised
  // request origin once credentials are included, and `*` never does.
  assert.equal(corsCheck(star, true, EVIL, 'include'), false);
});

test('an echoed origin succeeds with credentials only when ACAC is true', () => {
  const echoed = readAcao(new HeaderMap({ 'access-control-allow-origin': 'https://probe.example' }));
  assert.equal(corsCheck(echoed, false, EVIL, 'omit'), true);
  assert.equal(corsCheck(echoed, false, EVIL, 'include'), false);
  assert.equal(corsCheck(echoed, true, EVIL, 'include'), true);
});

test('an ACAO for a different origin fails', () => {
  const fixed = readAcao(new HeaderMap({ 'access-control-allow-origin': 'https://app.acme.example' }));
  assert.equal(corsCheck(fixed, true, EVIL, 'include'), false);
  assert.equal(corsCheck(fixed, false, EVIL, 'omit'), false);
});

test('ACAO null matches only a null request origin', () => {
  const nullAcao = readAcao(new HeaderMap({ 'access-control-allow-origin': 'null' }));
  assert.equal(corsCheck(nullAcao, true, NULL_ORIGIN, 'include'), true);
  assert.equal(corsCheck(nullAcao, true, APP, 'include'), false);
});

test('a request that sent no Origin header can only pass via the wildcard', () => {
  const star = readAcao(new HeaderMap({ 'access-control-allow-origin': '*' }));
  const echoed = readAcao(new HeaderMap({ 'access-control-allow-origin': 'https://app.acme.example' }));
  assert.equal(corsCheck(star, false, null, 'omit'), true);
  assert.equal(corsCheck(echoed, false, null, 'omit'), false);
  assert.equal(corsCheck(star, true, null, 'include'), false);
});

test('a duplicated ACAO fails the check outright', () => {
  const twice = readAcao(new HeaderMap({ 'access-control-allow-origin': ['https://probe.example', '*'] }));
  assert.equal(corsCheck(twice, true, EVIL, 'include'), false);
  assert.equal(corsCheck(twice, false, EVIL, 'omit'), false);
});

test('a non-canonical ACAO fails the check, because step 3 is a byte comparison', () => {
  // The old comment here had it exactly backwards: *because* the serialised
  // request origin is always canonical, a non-canonical ACAO cannot equal it.
  // A browser rejects these responses, so grading them as an accepted origin
  // invented a critical finding and emitted a PoC page that could not work.
  for (const value of [
    'https://probe.example:443',
    'https://probe.example/',
    'HTTPS://probe.example',
  ]) {
    const acao = readAcao(new HeaderMap({ 'access-control-allow-origin': value }));
    assert.equal(corsCheck(acao, true, EVIL, 'include'), false, value);
    assert.equal(corsCheck(acao, false, EVIL, 'omit'), false, value);
  }
});

test('a trailing root dot echoed back byte for byte does match', () => {
  // A page served from app.acme.example. sends that dot in Origin, so a server
  // echoing it is passing the check the browser actually runs.
  const dotted = parseOriginValue('https://app.acme.example.');
  const acao = readAcao(new HeaderMap({ 'access-control-allow-origin': 'https://app.acme.example.' }));
  assert.equal(corsCheck(acao, true, dotted, 'include'), true);
});

test('ACAC sent twice is not honoured', () => {
  // Fetch combines duplicate headers into `true, false`, which is not the byte
  // string `true`. Reading only the first value graded a credentialed read the
  // browser would refuse.
  const headers = new HeaderMap({ 'access-control-allow-origin': 'https://probe.example' });
  headers.append('access-control-allow-credentials', 'true');
  headers.append('access-control-allow-credentials', 'false');
  const read = readCorsResponseHeaders(headers);
  assert.equal(read.acacHonoured, false);
  assert.equal(corsCheck(read.acao, read.acacHonoured, EVIL, 'include'), false);
});

test('acaoShapeOf names what the server did', () => {
  const shape = (acao: string | null, origin = EVIL): string =>
    acaoShapeOf(
      acao === null ? null : readAcao(new HeaderMap({ 'access-control-allow-origin': acao })),
      origin,
    );
  assert.equal(shape(null), 'absent');
  assert.equal(shape('*'), 'wildcard');
  assert.equal(shape('null'), 'null');
  assert.equal(shape('https://probe.example'), 'reflected');
  assert.equal(shape('https://app.acme.example'), 'fixed');
  assert.equal(shape('https://probe.example/path'), 'invalid');
});

test('credentials in the request are detected from Cookie or Authorization', () => {
  assert.equal(requestCarriedCredentials(new HeaderMap({ Cookie: 'sid=synthetic' })), true);
  assert.equal(requestCarriedCredentials(new HeaderMap({ authorization: 'Bearer synthetic' })), true);
  assert.equal(requestCarriedCredentials(new HeaderMap({ accept: '*/*' })), false);
});
