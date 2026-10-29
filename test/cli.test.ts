import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

const ROOT = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
const CLI = join(ROOT, 'dist', 'src', 'cli.js');
const EXAMPLES = join(ROOT, 'examples');

interface Run {
  readonly status: number;
  readonly stdout: string;
  readonly stderr: string;
}

function cli(...args: string[]): Run {
  const result = spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8' });
  return { status: result.status ?? -1, stdout: result.stdout, stderr: result.stderr };
}

function example(name: string): string {
  return join(EXAMPLES, name);
}

test('--help prints the usage and exits 0', () => {
  const run = cli('--help');
  assert.equal(run.status, 0);
  assert.match(run.stdout, /offline CORS policy analyser/);
  assert.match(run.stdout, /Exit codes/);
});

test('--version prints just the version', () => {
  const run = cli('--version');
  assert.equal(run.status, 0);
  assert.match(run.stdout.trim(), /^\d+\.\d+\.\d+$/);
});

test('no arguments prints the usage and exits 2', () => {
  const run = cli();
  assert.equal(run.status, 2);
});

test('an unknown command exits 2', () => {
  const run = cli('inspect', 'x.json');
  assert.equal(run.status, 2);
  assert.match(run.stderr, /unknown command/);
});

test('an unknown option exits 2', () => {
  assert.equal(cli('analyse', example('safe-policy.json'), '--loud').status, 2);
});

test('an option with no value exits 2', () => {
  assert.equal(cli('analyse', example('safe-policy.json'), '--format').status, 2);
});

test('an unknown format or severity exits 2', () => {
  assert.equal(cli('analyse', example('safe-policy.json'), '--format', 'yaml').status, 2);
  assert.equal(cli('analyse', example('safe-policy.json'), '--fail-on', 'urgent').status, 2);
});

test('analyse with no file exits 2', () => {
  assert.equal(cli('analyse').status, 2);
});

test('a missing input file exits 3', () => {
  const run = cli('analyse', join(ROOT, 'does-not-exist.json'));
  assert.equal(run.status, 3);
  assert.match(run.stderr, /cannot read/);
});

test('an unparseable input file exits 3', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cors-matrix-'));
  const path = join(dir, 'broken.json');
  writeFileSync(path, '{not json');
  const run = cli('analyse', path);
  assert.equal(run.status, 3);
  assert.match(run.stderr, /not valid JSON/);
});

test('an invalid resource URL exits 3 with a message naming the field', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cors-matrix-'));
  const path = join(dir, 'bad-resource.json');
  writeFileSync(path, JSON.stringify({ resource: 'api.acme.example', observations: [{ responseHeaders: {} }] }));
  const run = cli('analyse', path);
  assert.equal(run.status, 3);
  assert.match(run.stderr, /"resource"/);
});

test('the correctly configured example comes back clean and exits 0', () => {
  const run = cli('analyse', example('safe-policy.json'));
  assert.equal(run.status, 0);
  assert.match(run.stdout, /No findings\./);
  assert.match(run.stdout, /No network request was made/);
});

test('the deliberately vulnerable example is reported and exits 1', () => {
  const run = cli('analyse', example('reflect-with-credentials.json'));
  assert.equal(run.status, 1);
  assert.match(run.stdout, /CRITICAL\s+CM001/);
  assert.match(run.stdout, /HIGH\s+CM002/);
  assert.match(run.stdout, /HIGH\s+CM006/);
  assert.match(run.stdout, /HIGH\s+CM007/);
  assert.match(run.stdout, /MEDIUM\s+CM009/);
});

test('the subtly-broken suffix example is caught and exits 1', () => {
  const run = cli('analyse', example('suffix-match.json'));
  assert.equal(run.status, 1);
  assert.match(run.stdout, /CRITICAL\s+CM004/);
  assert.match(run.stdout, /notkestrel-pay\.example/);
  // The obvious probes were all rejected, which is what makes it subtle.
  assert.ok(!run.stdout.includes('CM001'));
});

test('the wildcard-with-credentials example is graded low, not critical', () => {
  const run = cli('analyse', example('wildcard-with-credentials.json'));
  assert.match(run.stdout, /LOW\s+CM003/);
  assert.ok(!/CRITICAL/.test(run.stdout));
  // Exit 1 because low is the default threshold.
  assert.equal(run.status, 1);
  assert.equal(cli('analyse', example('wildcard-with-credentials.json'), '--fail-on', 'medium').status, 0);
});

test('the pre-flight-mismatch example grades CM001 low and reports CM012', () => {
  const run = cli('analyse', example('preflight-mismatch.json'));
  assert.equal(run.status, 1);
  assert.match(run.stdout, /MEDIUM\s+CM012/);
  assert.match(run.stdout, /LOW\s+CM001/);
  assert.ok(!/CRITICAL/.test(run.stdout));
});

test('--fail-on never always exits 0', () => {
  assert.equal(cli('analyse', example('reflect-with-credentials.json'), '--fail-on', 'never').status, 0);
});

test('--fail-on critical ignores everything below critical', () => {
  assert.equal(cli('analyse', example('preflight-mismatch.json'), '--fail-on', 'critical').status, 0);
  assert.equal(cli('analyse', example('reflect-with-credentials.json'), '--fail-on', 'critical').status, 1);
});

test('several captures can be analysed in one run and the worst sets the exit code', () => {
  const run = cli('analyse', example('safe-policy.json'), example('reflect-with-credentials.json'));
  assert.equal(run.status, 1);
  assert.match(run.stdout, /api\.northwind-labs\.example/);
  assert.match(run.stdout, /api\.meridian-ledger\.example/);
});

test('JSON output parses and carries the findings', () => {
  const run = cli('analyse', example('suffix-match.json'), '--format', 'json');
  const parsed = JSON.parse(run.stdout) as {
    tool: string;
    results: { findings: { rule: string; severity: string }[] }[];
  };
  assert.equal(parsed.tool, 'cors-matrix');
  assert.equal(parsed.results.length, 1);
  const findings = parsed.results[0]?.findings ?? [];
  assert.ok(findings.some((f) => f.rule === 'CM004' && f.severity === 'critical'));
});

test('markdown output has a findings table', () => {
  const run = cli('analyse', example('suffix-match.json'), '--format', 'markdown');
  assert.match(run.stdout, /\| Severity \| Rule \| Name \| Origin \|/);
  assert.match(run.stdout, /### CM004/);
});

test('output is deterministic across runs', () => {
  // No timestamps and no run ids, so a README excerpt does not go stale and a
  // CI diff means something.
  const a = cli('analyse', example('reflect-with-credentials.json'), '--format', 'json').stdout;
  const b = cli('analyse', example('reflect-with-credentials.json'), '--format', 'json').stdout;
  assert.equal(a, b);
});

test('-o writes the report to a file and nothing to stdout', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cors-matrix-'));
  const out = join(dir, 'report.md');
  const run = cli('analyse', example('suffix-match.json'), '--format', 'markdown', '-o', out);
  assert.equal(run.stdout, '');
  assert.match(readFileSync(out, 'utf8'), /### CM004/);
});

test('--trusted suppresses a first-party origin that the policy allows on purpose', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cors-matrix-'));
  const path = join(dir, 'partner.json');
  writeFileSync(
    path,
    JSON.stringify({
      resource: 'https://api.acme.example/v1/me',
      authenticated: true,
      observations: [
        {
          requestOrigin: 'https://portal.partner.example',
          responseHeaders: {
            'access-control-allow-origin': 'https://portal.partner.example',
            'access-control-allow-credentials': 'true',
            vary: 'Origin',
          },
        },
      ],
    }),
  );
  assert.equal(cli('analyse', path).status, 1);
  assert.equal(cli('analyse', path, '-t', 'https://portal.partner.example').status, 0);
});

test('a HAR file is accepted and analysed per resource', () => {
  const run = cli('analyse', example('browser-capture.har'));
  assert.match(run.stdout, /api\.gorse-analytics\.example\/v1\/reports/);
  assert.match(run.stdout, /CM008/);
  // The stylesheet request carried no Origin, so it is not in the report.
  assert.ok(!run.stdout.includes('app.css'));
});

test('probe prints a plan without sending anything', () => {
  const run = cli('probe', 'https://api.acme.example/v1/me', '-t', 'https://app.acme.example');
  assert.equal(run.status, 0);
  assert.match(run.stdout, /Nothing was sent/);
  assert.match(run.stdout, /Origin: null/);
  assert.match(run.stdout, /Origin: https:\/\/notacme\.example/);
  assert.match(run.stdout, /curl -sS/);
});

test('probe rejects a resource that is not a URL with exit 3', () => {
  const run = cli('probe', 'api.acme.example');
  assert.equal(run.status, 3);
  assert.match(run.stderr, /not a parseable URL/);
});

test('probe needs a resource', () => {
  assert.equal(cli('probe').status, 2);
});

test('probe --format json carries every probe', () => {
  const run = cli('probe', 'https://api.acme.example/v1/me', '--format', 'json');
  const parsed = JSON.parse(run.stdout) as { plan: { probes: { origin: string }[] } };
  assert.ok(parsed.plan.probes.length >= 12);
  assert.ok(parsed.plan.probes.some((p) => p.origin === 'null'));
});

test('poc --out-dir writes one page per demonstrable finding', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cors-matrix-'));
  const out = join(dir, 'poc');
  const run = cli('poc', example('reflect-with-credentials.json'), '--out-dir', out);
  assert.equal(run.status, 0);
  const written = readdirSync(out).sort();
  assert.ok(written.includes('cm002-null-origin.html'));
  assert.ok(written.some((f) => f.startsWith('cm001-')));
  for (const name of written) {
    assert.match(readFileSync(join(out, name), 'utf8'), /AUTHORISED TESTING ONLY/);
  }
});

test('poc on a clean capture writes nothing and says so', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cors-matrix-'));
  const out = join(dir, 'poc');
  const run = cli('poc', example('safe-policy.json'), '--out-dir', out);
  assert.equal(run.status, 0);
  assert.match(run.stderr, /nothing to write/);
});

test('poc without --out-dir prints the pages to stdout', () => {
  const run = cli('poc', example('suffix-match.json'));
  assert.equal(run.status, 0);
  assert.match(run.stdout, /<!doctype html>/);
  assert.match(run.stdout, /credentials: 'include'/);
});

test('rules prints every rule in each format', () => {
  const text = cli('rules');
  assert.equal(text.status, 0);
  assert.match(text.stdout, /CM001/);
  assert.match(text.stdout, /CM016/);
  const json = JSON.parse(cli('rules', '--format', 'json').stdout) as { rules: unknown[] };
  assert.equal(json.rules.length, 16);
  assert.match(cli('rules', '--format', 'markdown').stdout, /\| ID \| Name \| Max severity \|/);
});

test('poc --format json --out-dir writes the pages it prints', () => {
  // The JSON branch used to `continue` before the write loop, so the run
  // printed four PoCs and then said "nothing to write; no demonstrable
  // finding".
  const dir = mkdtempSync(join(tmpdir(), 'cors-poc-json-'));
  const result = cli('poc', join(EXAMPLES, 'reflect-with-credentials.json'), '--format', 'json', '--out-dir', dir);
  assert.equal(result.status, 0, result.stderr);
  const written = readdirSync(dir);
  assert.ok(written.length > 0, 'pages were written');
  assert.doesNotMatch(result.stdout, /nothing to write/);
  const parsed = JSON.parse(result.stdout) as { pocs: unknown[]; files: string[] };
  assert.equal(parsed.files.length, parsed.pocs.length);
  assert.equal(written.length, parsed.pocs.length);
});

test('a value beginning with a hyphen is reachable after --', () => {
  const missing = cli('analyse', '--trusted');
  assert.equal(missing.status, 2);
  assert.match(missing.stderr, /needs a value/);

  const ok = cli('analyse', '--', join(EXAMPLES, 'safe-policy.json'));
  assert.equal(ok.status, 0, ok.stderr);
});

test('--version matches the manifest', () => {
  const manifest = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')) as { version: string };
  assert.equal(cli('--version').stdout.trim(), manifest.version);
});
