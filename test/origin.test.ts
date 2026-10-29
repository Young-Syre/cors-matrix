import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  buildTrustAnchors,
  effectivePort,
  hostRelationTo,
  isIpHost,
  originOfUrl,
  parentDomains,
  parseOriginValue,
  relateOrigin,
  sameOrigin,
  type TupleOrigin,
} from '../src/origin.js';

function tuple(value: string): TupleOrigin {
  const parsed = parseOriginValue(value);
  assert.equal(parsed.kind, 'origin', `${value} should parse as an origin`);
  return parsed as TupleOrigin;
}

test('the literals * and null are their own kinds, not origins', () => {
  assert.equal(parseOriginValue('*').kind, 'wildcard');
  assert.equal(parseOriginValue('null').kind, 'null');
});

test('a plain origin parses into a scheme, host and port', () => {
  const o = tuple('https://app.acme.example');
  assert.equal(o.scheme, 'https');
  assert.equal(o.host, 'app.acme.example');
  assert.equal(o.port, null);
  assert.equal(o.serialized, 'https://app.acme.example');
  assert.equal(o.canonical, true);
  assert.equal(o.opaqueScheme, false);
});

test('an explicit non-default port is kept and serialised', () => {
  const o = tuple('https://app.acme.example:8443');
  assert.equal(o.port, 8443);
  assert.equal(o.serialized, 'https://app.acme.example:8443');
  assert.equal(effectivePort(o), 8443);
});

// The normalisations below are the reason this tool parses rather than
// string-compares. Each is a case where the byte string a server received is
// not the canonical origin, so a string-based check and a parsed check differ.

test('URL lowercases the host, and the tool records that it was not canonical', () => {
  const o = tuple('https://APP.ACME.EXAMPLE');
  assert.equal(o.host, 'app.acme.example');
  assert.equal(o.serialized, 'https://app.acme.example');
  assert.equal(o.canonical, false);
});

test('URL lowercases the scheme', () => {
  assert.equal(tuple('HTTPS://app.acme.example').scheme, 'https');
});

test('URL strips a default port, so :443 is the same origin as no port', () => {
  const explicit = tuple('https://app.acme.example:443');
  assert.equal(explicit.port, null);
  assert.equal(explicit.serialized, 'https://app.acme.example');
  assert.equal(explicit.canonical, false);
  assert.equal(sameOrigin(explicit, tuple('https://app.acme.example')), true);
});

test('a trailing slash is parsed away but marks the value non-canonical', () => {
  const o = tuple('https://app.acme.example/');
  assert.equal(o.serialized, 'https://app.acme.example');
  assert.equal(o.canonical, false);
});

test('a unicode host is converted to punycode', () => {
  const o = tuple('https://exämple.test');
  assert.equal(o.host, 'xn--exmple-cua.test');
  assert.equal(o.canonical, false);
});

test('an IPv4 host in octal form is rewritten to dotted decimal', () => {
  assert.equal(tuple('http://0177.0.0.1').host, '127.0.0.1');
  assert.equal(tuple('http://192.168.000.1').host, '192.168.0.1');
});

test('an IPv6 literal is compressed', () => {
  const o = tuple('https://[0:0:0:0:0:0:0:1]');
  assert.equal(o.host, '[::1]');
  assert.equal(isIpHost(o.host), true);
});

test('backslashes are treated as slashes for a special scheme', () => {
  assert.equal(tuple('https:\\\\app.acme.example').host, 'app.acme.example');
});

test('a trailing root dot is the same host, and still reported as non-canonical', () => {
  // The same host in DNS. Treating it as a different one made the defender's
  // own host read as a prefix of itself, which hostRelationTo reported as
  // prefix validation -- critical, against a host the defender controls.
  const dotted = tuple('https://app.acme.example.');
  assert.equal(dotted.host, 'app.acme.example');
  assert.equal(dotted.serialized, 'https://app.acme.example');
  assert.equal(sameOrigin(dotted, tuple('https://app.acme.example')), true);
  assert.equal(dotted.canonical, false, 'the divergence is still reported');
  assert.equal(dotted.raw, 'https://app.acme.example.', 'the wire value is kept');
});

test('a port survives the trailing-dot strip', () => {
  const dotted = tuple('https://app.acme.example.:8443');
  assert.equal(dotted.host, 'app.acme.example');
  assert.equal(dotted.port, 8443);
  assert.equal(dotted.serialized, 'https://app.acme.example:8443');
});

test('userinfo, a query string, a fragment and a path are all rejected', () => {
  for (const value of [
    'https://app.acme.example@probe.example',
    'https://app.acme.example?a=1',
    'https://app.acme.example#f',
    'https://app.acme.example/v1/me',
  ]) {
    assert.equal(parseOriginValue(value).kind, 'invalid', value);
  }
});

test('surrounding whitespace and an empty value are rejected', () => {
  assert.equal(parseOriginValue(' https://app.acme.example').kind, 'invalid');
  assert.equal(parseOriginValue('').kind, 'invalid');
});

test('a value that is not a URL at all is rejected with a reason', () => {
  const parsed = parseOriginValue('not an origin');
  assert.equal(parsed.kind, 'invalid');
  assert.match(parsed.kind === 'invalid' ? parsed.reason : '', /parseable URL/);
});

test('a custom scheme parses but is flagged as having an opaque origin', () => {
  const o = tuple('app://widget');
  assert.equal(o.scheme, 'app');
  assert.equal(o.host, 'widget');
  assert.equal(o.opaqueScheme, true);
  assert.equal(effectivePort(o), null);
});

test('file:// parses with an empty host and an opaque scheme', () => {
  const o = tuple('file://');
  assert.equal(o.host, '');
  assert.equal(o.opaqueScheme, true);
});

test('ws and wss are tuple schemes with the usual default ports', () => {
  assert.equal(tuple('wss://app.acme.example').opaqueScheme, false);
  assert.equal(effectivePort(tuple('ws://app.acme.example')), 80);
  assert.equal(effectivePort(tuple('wss://app.acme.example')), 443);
});

test('sameOrigin compares the triple, not the string', () => {
  assert.equal(sameOrigin(tuple('https://a.test:443'), tuple('HTTPS://A.TEST/')), true);
  assert.equal(sameOrigin(tuple('https://a.test'), tuple('http://a.test')), false);
  assert.equal(sameOrigin(tuple('https://a.test'), tuple('https://a.test:8443')), false);
  assert.equal(sameOrigin(parseOriginValue('null'), parseOriginValue('null')), false);
});

test('originOfUrl takes the origin of a full resource URL', () => {
  const o = originOfUrl('https://api.acme.example:8443/v1/me?x=1#f');
  assert.equal(o.kind, 'origin');
  assert.equal((o as TupleOrigin).serialized, 'https://api.acme.example:8443');
});

test('originOfUrl rejects a value that is not a URL', () => {
  assert.equal(originOfUrl('api.acme.example/v1').kind, 'invalid');
});

test('parentDomains strips labels down to a floor of two', () => {
  assert.deepEqual(parentDomains('a.b.acme.example'), ['b.acme.example', 'acme.example']);
  assert.deepEqual(parentDomains('acme.example'), []);
  assert.deepEqual(parentDomains('localhost'), []);
});

test('parentDomains yields nothing for an IP literal', () => {
  assert.deepEqual(parentDomains('192.168.0.1'), []);
  assert.deepEqual(parentDomains('[::1]'), []);
});

test('hostRelationTo distinguishes the four string-matching bugs', () => {
  assert.equal(hostRelationTo('acme.example', 'acme.example'), 'same');
  assert.equal(hostRelationTo('app.acme.example', 'acme.example'), 'subdomain');
  assert.equal(hostRelationTo('notacme.example', 'acme.example'), 'suffix');
  assert.equal(hostRelationTo('acme.example.probe.example', 'acme.example'), 'prefix');
  assert.equal(hostRelationTo('x-acme.example-x.probe.example', 'acme.example'), 'substring');
  assert.equal(hostRelationTo('unrelated.invalid', 'acme.example'), 'unrelated');
});

test('trust anchors include declared hosts and their derived parents, longest first', () => {
  const anchors = buildTrustAnchors([tuple('https://api.acme.example'), tuple('https://app.acme.example')]);
  assert.deepEqual(
    anchors.candidates.map((c) => c.host),
    ['api.acme.example', 'app.acme.example', 'acme.example'],
  );
  assert.equal(anchors.candidates.find((c) => c.host === 'acme.example')?.derived, true);
  assert.equal(anchors.candidates.find((c) => c.host === 'api.acme.example')?.derived, false);
});

test('relateOrigin reports host relation, scheme and port independently', () => {
  const anchors = buildTrustAnchors([tuple('https://api.acme.example'), tuple('https://app.acme.example')]);

  const exact = relateOrigin(tuple('https://app.acme.example'), anchors);
  assert.equal(exact.exactTrustedOrigin, true);
  assert.equal(exact.hostRelation, 'same');

  const downgrade = relateOrigin(tuple('http://app.acme.example'), anchors);
  assert.equal(downgrade.schemeDowngrade, true);
  assert.equal(downgrade.exactTrustedOrigin, false);
  assert.equal(downgrade.hostRelation, 'same');

  const port = relateOrigin(tuple('https://app.acme.example:1337'), anchors);
  assert.equal(port.portMismatch, true);
  assert.equal(port.schemeDowngrade, false);

  const suffix = relateOrigin(tuple('https://notacme.example'), anchors);
  assert.equal(suffix.hostRelation, 'suffix');
  assert.equal(suffix.against, 'acme.example');
  assert.equal(suffix.againstIsDerived, true);

  const unrelated = relateOrigin(tuple('https://probe.example'), anchors);
  assert.equal(unrelated.hostRelation, 'unrelated');
  assert.equal(unrelated.against, null);
});

test('relateOrigin prefers the most specific candidate', () => {
  const anchors = buildTrustAnchors([tuple('https://app.acme.example')]);
  const relation = relateOrigin(tuple('https://notapp.acme.example'), anchors);
  assert.equal(relation.hostRelation, 'suffix');
  assert.equal(relation.against, 'app.acme.example');
  assert.equal(relation.againstIsDerived, false);
});
