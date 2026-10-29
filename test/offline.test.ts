/**
 * Offline by construction.
 *
 * The central claim in the README is that cors-matrix never touches the
 * network. A claim like that is worth nothing unless something enforces it, so
 * this file reads every source file and fails if anything that could open a
 * socket, resolve a name or start a process appears anywhere in `src/`.
 *
 * It is a static check, which is its limitation: it cannot catch a socket
 * opened through a string built at runtime. That is stated in the README
 * rather than papered over. What it does catch is the realistic case — someone
 * adding a "just resolve this subdomain" convenience later.
 */

import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

const SRC = join(dirname(dirname(dirname(fileURLToPath(import.meta.url)))), 'src');

/** Modules that can reach the network, resolve names, or spawn something. */
const FORBIDDEN_MODULES = [
  'http',
  'https',
  'http2',
  'net',
  'tls',
  'dns',
  'dgram',
  'child_process',
  'cluster',
  'worker_threads',
  'inspector',
  'node:http',
  'node:https',
  'node:http2',
  'node:net',
  'node:tls',
  'node:dns',
  'node:dns/promises',
  'node:dgram',
  'node:child_process',
  'node:cluster',
  'node:worker_threads',
  'node:inspector',
  'undici',
  'axios',
  'node-fetch',
  'got',
  'superagent',
  'ws',
];

/** Globals that reach the network without importing anything. */
const FORBIDDEN_GLOBALS = [
  /\bfetch\s*\(/,
  /\bXMLHttpRequest\b/,
  /\bnew\s+WebSocket\b/,
  /\bnavigator\s*\.\s*sendBeacon\b/,
  /\bEventSource\b/,
  /\brequire\s*\(/,
  /\bprocess\s*\.\s*binding\b/,
];

function sourceFiles(): { path: string; text: string }[] {
  return readdirSync(SRC)
    .filter((name) => name.endsWith('.ts'))
    .sort()
    .map((name) => {
      const path = join(SRC, name);
      return { path: name, text: readFileSync(path, 'utf8') };
    });
}

/**
 * Strip comments and string literals before scanning.
 *
 * The source *talks about* `fetch` and HTTP constantly — in doc comments, in
 * finding text, and inside the generated PoC pages — so a naive grep over the
 * raw file would be useless. Only executable code is scanned.
 */
function codeOnly(text: string): string {
  let out = '';
  let i = 0;
  const n = text.length;
  while (i < n) {
    const two = text.slice(i, i + 2);
    if (two === '//') {
      const end = text.indexOf('\n', i);
      i = end === -1 ? n : end;
      continue;
    }
    if (two === '/*') {
      const end = text.indexOf('*/', i + 2);
      i = end === -1 ? n : end + 2;
      continue;
    }
    const ch = text[i] as string;
    if (ch === '"' || ch === "'" || ch === '`') {
      i += 1;
      while (i < n) {
        const c = text[i] as string;
        if (c === '\\') {
          i += 2;
          continue;
        }
        if (c === ch) {
          i += 1;
          break;
        }
        // Keep the contents of a template-literal expression: it is code.
        if (ch === '`' && c === '$' && text[i + 1] === '{') {
          let depth = 1;
          i += 2;
          const start = i;
          while (i < n && depth > 0) {
            if (text[i] === '{') depth += 1;
            else if (text[i] === '}') depth -= 1;
            if (depth > 0) i += 1;
          }
          out += text.slice(start, i);
          continue;
        }
        i += 1;
      }
      out += ' ';
      continue;
    }
    out += ch;
    i += 1;
  }
  return out;
}

test('the comment and string stripper keeps code and drops prose', () => {
  // Guards the guard: if codeOnly were broken, every assertion below would
  // pass vacuously.
  const stripped = codeOnly(`
    // talks about fetch(
    /* and fetch( again */
    const a = "fetch(";
    const b = \`a \${realCode()} b\`;
    actualCall();
  `);
  assert.ok(!stripped.includes('talks about'));
  assert.ok(!stripped.includes('again'));
  assert.ok(stripped.includes('actualCall()'));
  assert.ok(stripped.includes('realCode()'));
  assert.equal((stripped.match(/fetch\(/g) ?? []).length, 0);
});

test('src/ contains the modules this test expects to scan', () => {
  const names = sourceFiles().map((f) => f.path);
  for (const expected of ['analyse.ts', 'capture.ts', 'cli.ts', 'headers.ts', 'origin.ts', 'poc.ts', 'probe.ts']) {
    assert.ok(names.includes(expected), `${expected} is missing; the scan below would not cover it`);
  }
  assert.ok(names.length >= 8);
});

test('no source file imports a module that can reach the network', () => {
  for (const file of sourceFiles()) {
    const code = codeOnly(file.text);
    // Import specifiers are string literals, so they survive stripping as the
    // bare `from ;` skeleton — scan the raw import statements instead.
    const specifiers = [...file.text.matchAll(/(?:from|import)\s*\(?\s*['"]([^'"]+)['"]/g)].map((m) => m[1]);
    for (const specifier of specifiers) {
      assert.ok(
        !FORBIDDEN_MODULES.includes(specifier ?? ''),
        `${file.path} imports ${String(specifier)}, which can reach the network`,
      );
    }
    assert.ok(!/\bimport\s*\(/.test(code), `${file.path} uses a dynamic import, which this test cannot verify`);
  }
});

test('no source file calls a network global', () => {
  for (const file of sourceFiles()) {
    const code = codeOnly(file.text);
    for (const pattern of FORBIDDEN_GLOBALS) {
      assert.ok(!pattern.test(code), `${file.path} matches ${String(pattern)}`);
    }
  }
});

test('the only node builtins imported are the filesystem, path and url', () => {
  const allowed = new Set(['node:fs', 'node:path', 'node:url']);
  for (const file of sourceFiles()) {
    const specifiers = [...file.text.matchAll(/from\s*['"](node:[^'"]+)['"]/g)].map((m) => m[1] ?? '');
    for (const specifier of specifiers) {
      assert.ok(allowed.has(specifier), `${file.path} imports ${specifier}`);
    }
  }
});

test('only the CLI touches the filesystem; the library is pure', () => {
  // A library that cannot read a file cannot be tricked into reading one.
  for (const file of sourceFiles()) {
    if (file.path === 'cli.ts' || file.path === 'capture.ts') continue;
    assert.ok(!/from\s*['"]node:fs['"]/.test(file.text), `${file.path} should not import node:fs`);
  }
});

test('the generated PoC pages are the only place a fetch call is emitted', () => {
  // src/poc.ts writes `fetch(` into the HTML it generates. That is a string in
  // a page the operator serves themselves, not a call this process makes, and
  // the stripper above proves the difference.
  const poc = sourceFiles().find((f) => f.path === 'poc.ts');
  assert.ok(poc);
  assert.ok(poc.text.includes('await fetch('), 'poc.ts should emit a fetch call into its output');
  assert.equal((codeOnly(poc.text).match(/\bfetch\s*\(/g) ?? []).length, 0);
});
