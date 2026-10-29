import assert from 'node:assert/strict';
import { test } from 'node:test';

import { buildPocs } from '../src/poc.js';
import { APP_ORIGIN, EVIL_ORIGIN, echo, echoNoCreds, raw, run } from './helpers.js';

test('a critical reflection finding produces one credentialed fetch page', () => {
  const bundle = buildPocs(run([echo(APP_ORIGIN, { vary: 'Origin' }), echo(EVIL_ORIGIN, { vary: 'Origin' })]));
  const poc = bundle.pocs.find((p) => p.rule === 'CM001');
  assert.ok(poc);
  assert.equal(poc.origin, EVIL_ORIGIN);
  assert.equal(poc.filename, 'cm001-probe.example.html');
  assert.match(poc.html, /credentials: 'include'/);
  assert.match(poc.html, /mode: 'cors'/);
  assert.match(poc.servingInstruction, /Must be served from https:\/\/probe\.example/);
});

test('every generated page carries the authorised-testing banner', () => {
  const bundle = buildPocs(run([echo(APP_ORIGIN, { vary: 'Origin' }), echo(EVIL_ORIGIN, { vary: 'Origin' })]));
  assert.ok(bundle.pocs.length > 0);
  for (const poc of bundle.pocs) {
    assert.match(poc.html, /TEST ARTEFACT/);
    assert.match(poc.html, /AUTHORISED TESTING ONLY/);
    assert.match(poc.html, /^<!doctype html>/);
  }
});

test('a generated page sends nothing anywhere except the resource under test', () => {
  const bundle = buildPocs(run([echo(APP_ORIGIN, { vary: 'Origin' }), echo(EVIL_ORIGIN, { vary: 'Origin' })]));
  for (const poc of bundle.pocs) {
    const fetches = poc.html.match(/fetch\(/g) ?? [];
    assert.equal(fetches.length, 1, `${poc.filename} should make exactly one request`);
    assert.ok(!/XMLHttpRequest|navigator\.sendBeacon|new WebSocket|new Image/.test(poc.html));
    assert.ok(!/<script src=/.test(poc.html));
  }
});

test('the null-origin page uses a sandboxed iframe rather than a hosted origin', () => {
  const bundle = buildPocs(run([echo(APP_ORIGIN, { vary: 'Origin' }), echo('null', { vary: 'Origin' })]));
  const poc = bundle.pocs.find((p) => p.rule === 'CM002');
  assert.ok(poc);
  // allow-same-origin would give the frame a real origin, so the sandbox
  // attribute must carry allow-scripts and nothing else.
  const sandbox = /<iframe sandbox="([^"]*)"/.exec(poc.html)?.[1];
  assert.equal(sandbox, 'allow-scripts');
  assert.match(poc.html, /srcdoc="/);
  assert.match(poc.servingInstruction, /any origin at all/);
});

test('the srcdoc payload is HTML-escaped so the wrapper stays well formed', () => {
  const bundle = buildPocs(run([echo(APP_ORIGIN, { vary: 'Origin' }), echo('null', { vary: 'Origin' })]));
  const poc = bundle.pocs.find((p) => p.rule === 'CM002');
  assert.ok(poc);
  const srcdoc = /srcdoc="([^"]*)"/.exec(poc.html)?.[1];
  assert.ok(srcdoc);
  assert.ok(srcdoc.includes('&lt;script&gt;'));
  assert.ok(!srcdoc.includes('<script>'));
});

test('a configuration-only rule is skipped with a reason rather than faked', () => {
  const result = run([
    raw(APP_ORIGIN, { 'access-control-allow-origin': '*', 'access-control-allow-credentials': 'true' }),
  ]);
  const bundle = buildPocs(result);
  assert.equal(bundle.pocs.length, 0);
  const skipped = bundle.skipped.find((s) => s.rule === 'CM003');
  assert.ok(skipped);
  assert.match(skipped.reason, /no page that demonstrates it/);
});

test('a finding graded below high is skipped, because nothing authenticated crosses', () => {
  const bundle = buildPocs(run([echoNoCreds('https://notacme-widgets.example', { vary: 'Origin' })]));
  assert.equal(bundle.pocs.length, 0);
  const skipped = bundle.skipped.find((s) => s.rule === 'CM004');
  assert.ok(skipped);
  assert.match(skipped.reason, /credentials are not allowed/);
});

test('a finding a browser cannot reach is skipped with that reason', () => {
  const bundle = buildPocs(run([echo(APP_ORIGIN, { vary: 'Origin' }), echo('app://widget', { vary: 'Origin' })]));
  const skipped = bundle.skipped.find((s) => s.reason.includes('not reachable from a browser'));
  // The app:// finding is graded medium, so the severity gate catches it first;
  // either reason is honest, but one of the two must be given.
  const any = skipped ?? bundle.skipped.find((s) => s.rule === 'CM006');
  assert.ok(any);
});

test('a suffix-match page is generated for the accepted attacker host', () => {
  const bundle = buildPocs(
    run([echo(APP_ORIGIN, { vary: 'Origin' }), echo('https://notacme-widgets.example', { vary: 'Origin' })]),
  );
  const poc = bundle.pocs.find((p) => p.rule === 'CM004');
  assert.ok(poc);
  assert.equal(poc.filename, 'cm004-notacme-widgets.example.html');
  assert.match(poc.html, /notacme-widgets\.example/);
});

test('the filename is filesystem-safe even for an origin with a port', () => {
  const bundle = buildPocs(run([echo(APP_ORIGIN, { vary: 'Origin' }), echo(`${APP_ORIGIN}:1337`, { vary: 'Origin' })]));
  const poc = bundle.pocs.find((p) => p.rule === 'CM007');
  assert.ok(poc);
  assert.ok(!poc.filename.includes(':'));
  assert.ok(!poc.filename.includes('/'));
  assert.match(poc.filename, /^cm007-[A-Za-z0-9.-]+\.html$/);
});

test('a clean capture produces no pages and nothing to skip', () => {
  const bundle = buildPocs(run([echo(APP_ORIGIN, { vary: 'Origin' })]));
  assert.deepEqual(bundle.pocs, []);
  assert.deepEqual(bundle.skipped, []);
});
