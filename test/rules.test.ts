import assert from 'node:assert/strict';
import { test } from 'node:test';

import { RULES, ruleMeta } from '../src/rules.js';
import {
  APP_ORIGIN,
  EVIL_ORIGIN,
  echo,
  echoNoCreds,
  findingFor,
  hasRule,
  raw,
  reject,
  run,
  runUndeclaredAuth,
  rules,
} from './helpers.js';

test('every rule in the table has a unique id and a non-trivial summary', () => {
  const ids = RULES.map((r) => r.id);
  assert.equal(new Set(ids).size, ids.length);
  for (const rule of RULES) {
    assert.match(rule.id, /^CM0\d\d$/);
    assert.ok(rule.name.length > 10, rule.id);
    assert.ok(rule.summary.length > 80, `${rule.id} summary is too thin to be useful`);
    assert.equal(ruleMeta(rule.id).id, rule.id);
  }
});

test('ruleMeta throws for an unknown id rather than returning a blank', () => {
  assert.throws(() => ruleMeta('CM999'));
});

/* ---------------- CM001 ---------------- */

test('CM001: an unrelated origin echoed with credentials is critical', () => {
  const result = run([echo(APP_ORIGIN), echo(EVIL_ORIGIN), echo('https://other.invalid')]);
  const f = findingFor(result, 'CM001');
  assert.equal(f.severity, 'critical');
  assert.deepEqual(
    result.findings.filter((x) => x.rule === 'CM001').map((x) => x.origin),
    ['https://other.invalid', EVIL_ORIGIN],
  );
  assert.equal(f.facts?.['reflection confirmed'], 'true');
  assert.equal(result.policy.reflectsOrigin, true);
});

test('CM001: one echoed origin is still critical but reflection is not claimed as confirmed', () => {
  const result = run([echo(APP_ORIGIN), echo(EVIL_ORIGIN)]);
  const f = findingFor(result, 'CM001');
  assert.equal(f.severity, 'critical');
  assert.equal(f.facts?.['reflection confirmed'], 'false');
  assert.match(f.detail, /inferred rather than\s+confirmed/);
});

test('CM001 does not fire for the trusted origin itself', () => {
  const result = run([echo(APP_ORIGIN)]);
  assert.equal(hasRule(result, 'CM001'), false);
  assert.deepEqual(result.findings, []);
});

test('CM001 does not fire when the ACAO names a different origin than the request', () => {
  const result = run([raw(EVIL_ORIGIN, { 'access-control-allow-origin': APP_ORIGIN, 'access-control-allow-credentials': 'true' })]);
  assert.equal(hasRule(result, 'CM001'), false);
});

/* ---------------- CM002 ---------------- */

test('CM002: ACAO null with credentials is high and names the sandbox vector', () => {
  const result = run([echo(APP_ORIGIN), echo('null')]);
  const f = findingFor(result, 'CM002');
  assert.equal(f.severity, 'high');
  assert.match(f.detail, /sandbox="allow-scripts"/);
  assert.equal(f.browserReachable, true);
});

test('CM002: a static ACAO null is still reachable from a null-origin document', () => {
  const result = run([raw(APP_ORIGIN, { 'access-control-allow-origin': 'null', 'access-control-allow-credentials': 'true' })]);
  const f = findingFor(result, 'CM002');
  assert.equal(f.severity, 'high');
  assert.match(f.detail, /fixed value rather than echoed/);
});

test('CM002 drops to low without credentials', () => {
  const result = run([echoNoCreds('null')]);
  assert.equal(findingFor(result, 'CM002').severity, 'low');
});

/* ---------------- CM003 ---------------- */

test('CM003: wildcard with credentials is low, not critical, and explains why', () => {
  const result = run([raw(APP_ORIGIN, { 'access-control-allow-origin': '*', 'access-control-allow-credentials': 'true' })]);
  const f = findingFor(result, 'CM003');
  assert.equal(f.severity, 'low');
  assert.match(f.detail, /not exploitable/);
  assert.match(f.detail, /Step 3 of the Fetch/);
  // The grading claim matters more than the detection: a report that calls
  // this critical gets closed.
  assert.equal(ruleMeta('CM003').maxSeverity, 'low');
});

test('CM003 does not fire for a wildcard without credentials', () => {
  const result = run([raw(APP_ORIGIN, { 'access-control-allow-origin': '*' })], { authenticated: false });
  assert.equal(hasRule(result, 'CM003'), false);
});

/* ---------------- CM004 / CM005 ---------------- */

test('CM004: a suffix match without a label boundary is critical with credentials', () => {
  const result = run([echo(APP_ORIGIN), echo('https://notacme-widgets.example')]);
  const f = findingFor(result, 'CM004');
  assert.equal(f.severity, 'critical');
  assert.equal(f.origin, 'https://notacme-widgets.example');
  assert.match(f.detail, /endsWith/);
  assert.ok(f.dependency);
  // Not CM001: the host is related to the trusted domain, and saying which
  // string bug produced it is the useful part of the report.
  assert.equal(hasRule(result, 'CM001'), false);
});

test('CM004 drops to medium without credentials', () => {
  const result = run([echoNoCreds('https://notacme-widgets.example')]);
  assert.equal(findingFor(result, 'CM004').severity, 'medium');
});

test('CM005: a prefix match is critical and names startsWith', () => {
  const result = run([echo(APP_ORIGIN), echo('https://acme-widgets.example.probe.example')]);
  const f = findingFor(result, 'CM005');
  assert.equal(f.severity, 'critical');
  assert.match(f.detail, /startsWith/);
  assert.equal(f.facts?.['relation'], 'prefix');
});

test('CM005: a substring match in the middle of the host is caught too', () => {
  const result = run([echo(APP_ORIGIN), echo('https://x-acme-widgets.example-x.probe.example')]);
  const f = findingFor(result, 'CM005');
  assert.match(f.detail, /includes/);
  assert.equal(f.facts?.['relation'], 'substring');
});

/* ---------------- CM006 ---------------- */

test('CM006: an http origin accepted for an https resource is high', () => {
  const result = run([echo(APP_ORIGIN), echo('http://app.acme-widgets.example')]);
  const f = findingFor(result, 'CM006');
  assert.equal(f.severity, 'high');
  assert.match(f.detail, /HSTS/);
  assert.equal(f.facts?.['accepted scheme'], 'http');
});

test('CM006: an opaque-scheme origin is reported as not browser-reachable', () => {
  const result = run([echo(APP_ORIGIN), echo('app://widget')]);
  const f = result.findings.find((x) => x.rule === 'CM006' && x.origin === 'app://widget');
  assert.ok(f, `expected an app:// finding, got ${JSON.stringify(rules(result))}`);
  assert.equal(f.browserReachable, false);
  assert.match(f.detail, /WebView/);
});

/* ---------------- CM007 ---------------- */

test('CM007: an origin differing only in port is high with credentials', () => {
  const result = run([echo(APP_ORIGIN), echo(`${APP_ORIGIN}:1337`)]);
  const f = findingFor(result, 'CM007');
  assert.equal(f.severity, 'high');
  assert.equal(f.facts?.['port'], '1337');
  assert.match(f.detail, /new URL\(origin\)\.hostname/);
});

test('CM007 does not fire for an explicit default port, which is the same origin', () => {
  const result = run([echo(`${APP_ORIGIN}:443`)]);
  assert.equal(hasRule(result, 'CM007'), false);
  // It is however a non-canonical ACAO value, which CM015 reports.
  assert.equal(hasRule(result, 'CM015'), true);
});

/* ---------------- CM008 ---------------- */

test('CM008: a subdomain accepted with credentials is medium and states the dependency', () => {
  const result = run([echo(APP_ORIGIN), echo('https://preview.acme-widgets.example')]);
  const f = findingFor(result, 'CM008');
  assert.equal(f.severity, 'medium');
  assert.match(f.dependency ?? '', /claimable, dangling or XSS-prone/);
  // The tool must not pretend to know whether such a host exists.
  assert.match(f.detail, /resolves nothing/);
});

/* ---------------- CM009 ---------------- */

test('CM009: a varying ACAO without Vary: Origin is medium', () => {
  const result = run([echo(APP_ORIGIN), echo(EVIL_ORIGIN)]);
  const f = findingFor(result, 'CM009');
  assert.equal(f.severity, 'medium');
  assert.equal(f.facts?.['distinct ACAO values'], '2');
});

test('CM009 does not fire when Vary: Origin is present', () => {
  const result = run([echo(APP_ORIGIN, { vary: 'Origin' }), echo(EVIL_ORIGIN, { vary: 'Origin' })]);
  assert.equal(hasRule(result, 'CM009'), false);
});

test('CM009 accepts Vary: * as covering Origin', () => {
  const result = run([echo(APP_ORIGIN, { vary: '*' }), echo(EVIL_ORIGIN, { vary: '*' })]);
  assert.equal(hasRule(result, 'CM009'), false);
});

test('CM009 does not fire when only one ACAO value was ever seen', () => {
  const result = run([echo(APP_ORIGIN), reject(EVIL_ORIGIN)]);
  assert.equal(hasRule(result, 'CM009'), false);
});

/* ---------------- CM010 / CM011 ---------------- */

test('CM010: a wildcard Allow-Headers on a credentialed response is low and literal', () => {
  const result = run([
    raw(APP_ORIGIN, {
      'access-control-allow-origin': APP_ORIGIN,
      'access-control-allow-credentials': 'true',
      'access-control-allow-headers': '*',
    }),
  ]);
  const f = findingFor(result, 'CM010');
  assert.equal(f.severity, 'low');
  assert.match(f.detail, /literally/);
});

test('CM010: Authorization allowed for an origin that should not have been accepted is medium', () => {
  const result = run([
    echo(APP_ORIGIN, { vary: 'Origin' }),
    raw(EVIL_ORIGIN, {
      'access-control-allow-origin': EVIL_ORIGIN,
      'access-control-allow-credentials': 'true',
      'access-control-allow-headers': 'content-type, authorization',
      vary: 'Origin',
    }),
  ]);
  const f = result.findings.find((x) => x.rule === 'CM010' && x.severity === 'medium');
  assert.ok(f);
  assert.match(f.detail, /never covers/);
});

test('CM010 does not fire when Authorization is allowed only for a trusted origin', () => {
  const result = run([
    raw(APP_ORIGIN, {
      'access-control-allow-origin': APP_ORIGIN,
      'access-control-allow-credentials': 'true',
      'access-control-allow-headers': 'authorization',
      vary: 'Origin',
    }),
  ]);
  assert.equal(hasRule(result, 'CM010'), false);
});

test('CM011: a state-changing method for an unaccepted origin is medium', () => {
  const result = run([
    echo(APP_ORIGIN, { vary: 'Origin' }),
    raw(EVIL_ORIGIN, {
      'access-control-allow-origin': EVIL_ORIGIN,
      'access-control-allow-credentials': 'true',
      'access-control-allow-methods': 'GET, DELETE',
      vary: 'Origin',
    }),
  ]);
  const f = result.findings.find((x) => x.rule === 'CM011' && x.severity === 'medium');
  assert.ok(f);
  assert.equal(f.facts?.['state-changing methods allowed'], 'delete');
});

test('CM011: a wildcard Allow-Methods on a credentialed response is low', () => {
  const result = run([
    raw(APP_ORIGIN, {
      'access-control-allow-origin': APP_ORIGIN,
      'access-control-allow-credentials': 'true',
      'access-control-allow-methods': '*',
    }),
  ]);
  assert.equal(findingFor(result, 'CM011').severity, 'low');
});

/* ---------------- CM012 ---------------- */

test('CM012: a pre-flight that allows an origin the real response refuses is reported', () => {
  const result = run([
    raw(
      EVIL_ORIGIN,
      {
        'access-control-allow-origin': EVIL_ORIGIN,
        'access-control-allow-credentials': 'true',
        'access-control-allow-methods': 'GET, PUT',
        vary: 'Origin',
      },
      'OPTIONS',
    ),
    reject(EVIL_ORIGIN),
  ]);
  const f = findingFor(result, 'CM012');
  assert.equal(f.severity, 'medium');
  assert.match(f.detail, /pre-flight passes the CORS check but the actual response does\s+not/);
});

test('an origin accepted only by the pre-flight is graded low, not critical', () => {
  // The most common false positive in CORS testing: OPTIONS reflects, the real
  // response does not, and the browser discards the response anyway.
  const result = run([
    raw(
      EVIL_ORIGIN,
      { 'access-control-allow-origin': EVIL_ORIGIN, 'access-control-allow-credentials': 'true', vary: 'Origin' },
      'OPTIONS',
    ),
    reject(EVIL_ORIGIN),
  ]);
  const f = findingFor(result, 'CM001');
  assert.equal(f.severity, 'low');
  assert.equal(f.facts?.['seen on a real response'], 'false');
  assert.match(f.detail, /no\s+cross-origin read today/);
});

test('a pre-flight acceptance with no matching real response keeps its severity but adds a dependency', () => {
  const result = run([
    raw(
      EVIL_ORIGIN,
      { 'access-control-allow-origin': EVIL_ORIGIN, 'access-control-allow-credentials': 'true', vary: 'Origin' },
      'OPTIONS',
    ),
  ]);
  const f = findingFor(result, 'CM001');
  assert.equal(f.severity, 'critical');
  assert.match(f.dependency ?? '', /non-OPTIONS/);
});

test('CM012: a real response that allows an origin the pre-flight refuses is reported', () => {
  const result = run([
    raw(EVIL_ORIGIN, { 'content-type': 'application/json', vary: 'Origin' }, 'OPTIONS'),
    echo(EVIL_ORIGIN, { vary: 'Origin' }),
  ]);
  const f = findingFor(result, 'CM012');
  assert.match(f.detail, /Simple requests/);
});

test('CM012: disagreement about the credentials header alone is reported', () => {
  const result = run([
    raw(
      APP_ORIGIN,
      { 'access-control-allow-origin': APP_ORIGIN, 'access-control-allow-credentials': 'true', vary: 'Origin' },
      'OPTIONS',
    ),
    raw(APP_ORIGIN, { 'access-control-allow-origin': APP_ORIGIN, vary: 'Origin' }),
  ]);
  const f = findingFor(result, 'CM012');
  assert.equal(f.facts?.['actual ACAC'], '(absent)');
});

test('CM012: Allow-Methods present only on the real response is informational', () => {
  const result = run([
    raw(APP_ORIGIN, { 'access-control-allow-origin': APP_ORIGIN, vary: 'Origin' }, 'OPTIONS'),
    raw(APP_ORIGIN, {
      'access-control-allow-origin': APP_ORIGIN,
      'access-control-allow-methods': 'GET, PUT',
      vary: 'Origin',
    }),
  ]);
  const f = result.findings.find((x) => x.rule === 'CM012' && x.severity === 'info');
  assert.ok(f);
  assert.match(f.detail, /pre-flight response only/);
});

test('CM012 does not fire when the pre-flight and the real response agree', () => {
  const result = run([
    raw(
      APP_ORIGIN,
      { 'access-control-allow-origin': APP_ORIGIN, 'access-control-allow-credentials': 'true', vary: 'Origin' },
      'OPTIONS',
    ),
    echo(APP_ORIGIN, { vary: 'Origin' }),
  ]);
  assert.equal(hasRule(result, 'CM012'), false);
});

/* ---------------- CM013 / CM014 / CM015 / CM016 ---------------- */

test('CM013: ACAO on a resource with no credentials anywhere is informational only', () => {
  const result = run([{ requestOrigin: EVIL_ORIGIN, responseHeaders: { 'access-control-allow-origin': '*' } }], {
    authenticated: false,
  });
  const f = findingFor(result, 'CM013');
  assert.equal(f.severity, 'info');
  assert.equal(hasRule(result, 'CM016'), false);
});

test('CM013 fires with an unknown auth state and asks for the declaration', () => {
  const result = runUndeclaredAuth([
    { requestOrigin: EVIL_ORIGIN, responseHeaders: { 'access-control-allow-origin': EVIL_ORIGIN } },
  ]);
  assert.match(findingFor(result, 'CM013').detail, /"authenticated": true/);
  // And CM016 fires too, with the uncertainty recorded as a dependency.
  assert.match(findingFor(result, 'CM016').dependency ?? '', /capture does not say/);
});

test('CM014: Access-Control-Allow-Credentials: True is reported as not honoured', () => {
  const result = run([raw(APP_ORIGIN, { 'access-control-allow-origin': APP_ORIGIN, 'access-control-allow-credentials': 'True' })]);
  const f = findingFor(result, 'CM014');
  assert.equal(f.severity, 'info');
  assert.equal(f.facts?.['observed values'], 'True');
  assert.match(f.detail, /byte string/);
});

test('CM014 does not fire for a deliberate false', () => {
  const result = run([raw(APP_ORIGIN, { 'access-control-allow-origin': APP_ORIGIN, 'access-control-allow-credentials': 'false' })]);
  assert.equal(hasRule(result, 'CM014'), false);
});

test('CM015: a duplicated ACAO is reported as malformed', () => {
  const result = run([
    raw(APP_ORIGIN, { 'access-control-allow-origin': [APP_ORIGIN, '*'], 'access-control-allow-credentials': 'true' }),
  ]);
  const f = findingFor(result, 'CM015');
  assert.equal(f.severity, 'low');
  assert.match(f.detail, /comma-separated list/);
});

test('CM015: an ACAO with a path is reported as malformed', () => {
  const result = run([raw(APP_ORIGIN, { 'access-control-allow-origin': `${APP_ORIGIN}/v1/` })]);
  assert.match(findingFor(result, 'CM015').detail, /contains a path/);
});

test('CM015: a trailing slash is reported as non-canonical', () => {
  const result = run([raw(APP_ORIGIN, { 'access-control-allow-origin': `${APP_ORIGIN}/` })]);
  assert.match(findingFor(result, 'CM015').detail, /canonical origin serialisation/);
});

test('CM016: reflection without credentials is low and names the escalation', () => {
  const result = run([echoNoCreds(APP_ORIGIN, { vary: 'Origin' }), echoNoCreds(EVIL_ORIGIN, { vary: 'Origin' })]);
  const f = findingFor(result, 'CM016');
  assert.equal(f.severity, 'low');
  assert.equal(f.origin, EVIL_ORIGIN);
  assert.match(f.detail, /one\s+line of configuration/);
  assert.equal(hasRule(result, 'CM001'), false);
});

/* ---------------- cross-cutting ---------------- */

test('findings are sorted worst-first', () => {
  const result = run([
    echo(APP_ORIGIN),
    echo(EVIL_ORIGIN),
    echo('null'),
    echo(`${APP_ORIGIN}:1337`),
    raw(APP_ORIGIN, { 'access-control-allow-origin': APP_ORIGIN, 'access-control-allow-credentials': 'True' }),
  ]);
  const severities = result.findings.map((f) => f.severity);
  assert.equal(severities[0], 'critical');
  assert.equal(severities[severities.length - 1], 'info');
});

test('an unparseable request origin is recorded as a warning, not a finding', () => {
  const result = run([raw('not-an-origin', { 'access-control-allow-origin': APP_ORIGIN })]);
  assert.equal(result.warnings.length, 1);
  assert.match(result.warnings[0] ?? '', /no browser sends that value/);
});

test('the policy summary separates accepted from rejected origins', () => {
  const result = run([echo(APP_ORIGIN, { vary: 'Origin' }), reject(EVIL_ORIGIN), reject('null')]);
  assert.deepEqual(result.policy.acceptedOrigins, [APP_ORIGIN]);
  assert.deepEqual(result.policy.rejectedOrigins, [EVIL_ORIGIN, 'null']);
  assert.equal(result.policy.credentialsAllowed, true);
});

test('every rule in the table is covered by at least one test in this file', async () => {
  // Guards against adding a rule to the table and forgetting to exercise it.
  const { readFileSync } = await import('node:fs');
  const { fileURLToPath } = await import('node:url');
  const self = readFileSync(fileURLToPath(import.meta.url), 'utf8');
  for (const rule of RULES) {
    assert.ok(self.includes(`'${rule.id}'`), `${rule.id} has no test`);
  }
});
