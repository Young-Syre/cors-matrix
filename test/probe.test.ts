import assert from 'node:assert/strict';
import { test } from 'node:test';

import { ProbeError, buildProbePlan, probeCommandHint } from '../src/probe.js';
import { severityRank } from '../src/types.js';
import { APP_ORIGIN, RESOURCE, echo, run } from './helpers.js';

const PLAN = buildProbePlan({
  resource: 'https://api.acme-widgets.example/v1/me',
  trustedOrigins: ['https://app.acme-widgets.example'],
});

function origins(): string[] {
  return PLAN.probes.map((p) => p.origin);
}

test('the plan derives the base domain from the trusted host', () => {
  assert.deepEqual(PLAN.baseDomains, ['acme-widgets.example']);
  assert.equal(PLAN.resourceOrigin, 'https://api.acme-widgets.example');
});

test('the plan starts from a baseline probe against the trusted origin', () => {
  assert.equal(PLAN.probes[0]?.origin, 'https://app.acme-widgets.example');
  assert.equal(PLAN.probes[0]?.rules.length, 0);
});

test('the plan includes a reflection probe, a null probe and a pre-flight probe', () => {
  assert.ok(origins().includes('https://probe.example'));
  assert.ok(origins().includes('null'));
  assert.ok(PLAN.probes.some((p) => p.methods.includes('OPTIONS')));
});

test('the pre-flight probe carries the Access-Control-Request-* headers', () => {
  const preflight = PLAN.probes.find((p) => p.methods.includes('OPTIONS'));
  assert.equal(preflight?.requestHeaders?.['Access-Control-Request-Method'], 'PUT');
  assert.match(preflight?.requestHeaders?.['Access-Control-Request-Headers'] ?? '', /authorization/);
});

test('the suffix probe ends with the base domain but not on a label boundary', () => {
  const probe = origins().find((o) => o.includes('notacme-widgets.example'));
  assert.equal(probe, 'https://notacme-widgets.example');
  const host = new URL(probe ?? '').hostname;
  assert.ok(host.endsWith('acme-widgets.example'));
  assert.ok(!host.endsWith('.acme-widgets.example'));
});

test('the prefix probe starts with the base domain followed by a dot', () => {
  assert.ok(origins().includes('https://acme-widgets.example.probe.example'));
});

test('the substring probe puts the base domain in the middle of the host', () => {
  const probe = origins().find((o) => o.startsWith('https://x-'));
  assert.ok(probe);
  const host = new URL(probe).hostname;
  assert.ok(host.includes('acme-widgets.example'));
  assert.ok(!host.startsWith('acme-widgets.example'));
  assert.ok(!host.endsWith('acme-widgets.example'));
});

test('the scheme, port and subdomain probes are all present', () => {
  assert.ok(origins().includes('http://app.acme-widgets.example'));
  assert.ok(origins().includes('https://app.acme-widgets.example:1337'));
  assert.ok(origins().includes('https://probe.acme-widgets.example'));
});

test('probes a browser cannot produce are flagged rather than omitted', () => {
  const unreachable = PLAN.probes.filter((p) => !p.browserReachable).map((p) => p.origin);
  // An uppercase host and a userinfo payload are both useful fingerprints and
  // both impossible for a browser to send, so they are kept and labelled.
  assert.ok(unreachable.some((o) => /[A-Z]/.test(o)));
  assert.ok(unreachable.some((o) => o.includes('@')));
  assert.ok(unreachable.length >= 2);
});

test('probes whose exploitation needs a registered domain are flagged', () => {
  const needsDomain = PLAN.probes.filter((p) => p.requiresDomainControl).map((p) => p.origin);
  assert.ok(needsDomain.includes('https://notacme-widgets.example'));
  // Sending the probe never needs domain control, only weaponising it does.
  assert.equal(
    PLAN.probes.find((p) => p.origin === 'null')?.requiresDomainControl,
    false,
  );
});

test('the trailing-dot probe is included and marked as a fingerprint, not a vector', () => {
  const probe = PLAN.probes.find((p) => p.origin.endsWith('.example.'));
  assert.ok(probe);
  assert.equal(probe.browserReachable, true);
  assert.match(probe.resolves, /fingerprint rather than a primitive/);
});

test('no two probes share an Origin value except the deliberate pre-flight pair', () => {
  const gets = PLAN.probes.filter((p) => p.methods.includes('GET')).map((p) => p.origin);
  assert.equal(new Set(gets).size, gets.length);
});

test('every probe either names a rule or explains that it is a fingerprint', () => {
  for (const probe of PLAN.probes) {
    assert.ok(probe.resolves.length > 40, probe.origin);
    if (probe.rules.length === 0) assert.ok(probe.resolves.length > 60, probe.origin);
  }
});

test('the attacker domain is configurable and appears in the attacker-side probes', () => {
  const plan = buildProbePlan({
    resource: 'https://api.acme-widgets.example/v1/me',
    trustedOrigins: ['https://app.acme-widgets.example'],
    attackerDomain: 'owned.test',
  });
  assert.equal(plan.attackerDomain, 'owned.test');
  assert.ok(plan.probes.some((p) => p.origin === 'https://owned.test'));
  assert.ok(plan.probes.some((p) => p.origin === 'https://acme-widgets.example.owned.test'));
});

test('the default attacker domain is a reserved, unregistrable one', () => {
  // probe.example cannot be registered by anyone, so a plan pasted into a
  // report never points at a live third party.
  assert.equal(PLAN.attackerDomain, 'probe.example');
});

test('a plan can be built with no trusted origin, falling back to the resource', () => {
  const plan = buildProbePlan({ resource: 'https://api.acme-widgets.example/v1/me' });
  assert.deepEqual(plan.trustedOrigins, ['https://api.acme-widgets.example']);
  assert.ok(plan.probes.some((p) => p.origin === 'https://notacme-widgets.example'));
});

test('a resource with a two-label host derives no base domain and still plans', () => {
  const plan = buildProbePlan({ resource: 'https://acme-widgets.example/v1/me' });
  assert.deepEqual(plan.baseDomains, []);
  assert.ok(plan.probes.some((p) => p.origin === 'https://notacme-widgets.example'));
});

test('a bad resource or a bad trusted origin is rejected', () => {
  assert.throws(() => buildProbePlan({ resource: 'api.acme.example/v1' }), ProbeError);
  assert.throws(
    () => buildProbePlan({ resource: 'https://api.acme.example/', trustedOrigins: ['not an origin'] }),
    ProbeError,
  );
});

test('the printed curl loop quotes every GET probe origin and the resource', () => {
  const hint = probeCommandHint(PLAN);
  assert.match(hint, /curl -sS -o \/dev\/null -D - -H "Origin: \$origin"/);
  assert.ok(hint.includes('"https://notacme-widgets.example"'));
  assert.ok(hint.includes('"https://api.acme-widgets.example/v1/me"'));
  assert.ok(!hint.includes('OPTIONS'));
});

test('the notes warn about credentials, Vary and authorisation', () => {
  const notes = PLAN.notes.join(' ');
  assert.match(notes, /once with the session cookie/);
  assert.match(notes, /Vary/);
  assert.match(notes, /authorised to test/);
});

test('the plan\'s own trailing-dot probe does not become a finding', () => {
  // probe.ts generates this probe and says in the same file that the host it
  // names is one the defender already controls -- "a fingerprint rather than a
  // primitive". analyse.ts graded it CM005 critical. A passing test sat on
  // each side of that contradiction and none crossed it; this one does.
  const plan = buildProbePlan({ resource: RESOURCE, trustedOrigins: [APP_ORIGIN] });
  const dotted = plan.probes.find((probe) => probe.origin === `${APP_ORIGIN}.`);
  assert.notEqual(dotted, undefined, 'the plan still emits a trailing-dot probe');

  // Vary: Origin on both, so the only thing left to grade is whether echoing
  // the defender's own host back with a root dot is an origin-validation flaw.
  const result = run([
    echo(APP_ORIGIN, { vary: 'Origin' }),
    echo(`${APP_ORIGIN}.`, { vary: 'Origin' }),
  ]);
  const serious = result.findings.filter(
    (finding) => severityRank(finding.severity) > severityRank('low'),
  );
  assert.deepEqual(
    serious.map((finding) => `${finding.rule} ${finding.severity}`),
    [],
    'echoing back the defender\'s own host with a root dot is not an origin-validation flaw',
  );
  // The non-canonical value is still reported, which is the point: the fact is
  // worth knowing, the critical grade was not.
  assert.ok(
    result.findings.some((finding) => finding.rule === 'CM015'),
    'the trailing dot is still reported as a non-canonical value',
  );
});
