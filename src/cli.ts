#!/usr/bin/env node
/**
 * Command line interface.
 *
 * Exit codes are the contract; see README. In short: 0 clean, 1 findings at or
 * above the threshold, 2 bad usage, 3 unreadable or unparseable input.
 */

import { mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { analyse } from './analyse.js';
import { CaptureError, loadCaptures } from './capture.js';
import { renderAnalysis, renderPlan, renderRules, type Format } from './format.js';
import { buildPocs, type Poc } from './poc.js';
import { ProbeError, buildProbePlan } from './probe.js';
import { SEVERITY_ORDER, severityRank, type AnalysisResult, type Severity } from './types.js';

/** Read from the manifest rather than duplicated here, so it cannot drift. */
const VERSION = ((): string => {
  try {
    const raw = readFileSync(new URL('../../package.json', import.meta.url), 'utf8');
    const parsed = JSON.parse(raw) as { version?: unknown };
    return typeof parsed.version === 'string' ? parsed.version : '0.0.0';
  } catch {
    return '0.0.0';
  }
})();

const EXIT_CLEAN = 0;
const EXIT_FINDINGS = 1;
const EXIT_USAGE = 2;
const EXIT_INPUT = 3;

const USAGE = `cors-matrix ${VERSION} — offline CORS policy analyser

  Decides what a CORS policy actually is from recorded (request origin →
  response headers) observations, and reports what is exploitable. It never
  makes a network request: no DNS, no HTTP, no probing.

Usage
  cors-matrix analyse <capture.json|capture.har> [more...] [options]
  cors-matrix probe <resource-url> [options]
  cors-matrix poc <capture.json|capture.har> [options]
  cors-matrix rules [--format text|json|markdown]

Commands
  analyse   Analyse one or more capture files and report findings.
            "analyze" is accepted too.
  probe     Emit the list of Origin values that resolves a policy
            unambiguously, before you have any captures. Prints a curl loop
            that turns the answers into a capture file.
  poc       Emit a minimal proof-of-concept page for each finding a browser
            can actually demonstrate.
  rules     Print the rule table.

Options
  -f, --format <fmt>      text (default), json or markdown
  -o, --output <path>     write to a file instead of stdout
  -t, --trusted <origin>  an origin that is legitimately allowed; repeatable.
                          Without this, a first-party origin that the policy
                          allows on purpose is reported as a third-party one.
      --fail-on <sev>     lowest severity that sets exit code 1.
                          critical|high|medium|low|info|never. Default: low.
      --attacker-domain <d>  domain to use for attacker-side probe origins
                          (probe command). Default: probe.example
      --out-dir <dir>     write PoC pages into this directory (poc command)
  -h, --help              this text
  -v, --version           print the version

Exit codes
  0  analysis completed; nothing at or above --fail-on
  1  at least one finding at or above --fail-on
  2  invalid usage
  3  an input file could not be read or parsed

Examples
  cors-matrix probe https://api.acme.example/v1/me -t https://app.acme.example
  cors-matrix analyse capture.json -t https://app.acme.example
  cors-matrix analyse capture.json --format markdown -o cors.md
  cors-matrix poc capture.json --out-dir ./poc
`;

interface Args {
  command: string;
  positionals: string[];
  format: Format;
  output: string | null;
  trusted: string[];
  failOn: Severity | 'never';
  attackerDomain: string | null;
  outDir: string | null;
  help: boolean;
  version: boolean;
}

class UsageError extends Error {}

function parseArgs(argv: readonly string[]): Args {
  const args: Args = {
    command: '',
    positionals: [],
    format: 'text',
    output: null,
    trusted: [],
    failOn: 'low',
    attackerDomain: null,
    outDir: null,
    help: false,
    version: false,
  };

  // A value that begins with a hyphen is rejected, because a missing value is
  // far more common than a file called -weird.json -- but it has to be
  // expressible, so everything after `--` is a positional.
  const next = (i: number, flag: string): string => {
    const value = argv[i + 1];
    if (value === undefined || value.startsWith('-')) {
      throw new UsageError(`${flag} needs a value (use \`--\` first if the value begins with a hyphen)`);
    }
    return value;
  };

  let onlyPositionals = false;
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i] as string;
    if (onlyPositionals) {
      args.positionals.push(arg);
      continue;
    }
    if (arg === '--') {
      onlyPositionals = true;
      continue;
    }
    switch (arg) {
      case '-h':
      case '--help':
        args.help = true;
        break;
      case '-v':
      case '--version':
        args.version = true;
        break;
      case '-f':
      case '--format': {
        const value = next(i, arg);
        if (value !== 'text' && value !== 'json' && value !== 'markdown') {
          throw new UsageError(`unknown format ${JSON.stringify(value)}; use text, json or markdown`);
        }
        args.format = value;
        i += 1;
        break;
      }
      case '-o':
      case '--output':
        args.output = next(i, arg);
        i += 1;
        break;
      case '-t':
      case '--trusted':
        args.trusted.push(next(i, arg));
        i += 1;
        break;
      case '--fail-on': {
        const value = next(i, arg);
        if (value !== 'never' && !(SEVERITY_ORDER as readonly string[]).includes(value)) {
          throw new UsageError(
            `unknown severity ${JSON.stringify(value)}; use critical, high, medium, low, info or never`,
          );
        }
        args.failOn = value as Severity | 'never';
        i += 1;
        break;
      }
      case '--attacker-domain':
        args.attackerDomain = next(i, arg);
        i += 1;
        break;
      case '--out-dir':
        args.outDir = next(i, arg);
        i += 1;
        break;
      default:
        if (arg.startsWith('-') && arg !== '-') throw new UsageError(`unknown option ${arg}`);
        if (args.command === '') args.command = arg;
        else args.positionals.push(arg);
    }
  }

  return args;
}

function emit(text: string, output: string | null): void {
  if (output === null) process.stdout.write(text);
  else writeFileSync(output, text, 'utf8');
}

function worstSeverity(results: readonly AnalysisResult[]): Severity | null {
  let worst: Severity | null = null;
  for (const r of results) {
    for (const f of r.findings) {
      if (worst === null || severityRank(f.severity) > severityRank(worst)) worst = f.severity;
    }
  }
  return worst;
}

function runAnalyse(args: Args): number {
  if (args.positionals.length === 0) throw new UsageError('analyse needs at least one capture file');
  const results: AnalysisResult[] = [];
  for (const path of args.positionals) {
    for (const capture of loadCaptures(path, { trustedOrigins: args.trusted })) {
      results.push(analyse(capture));
    }
  }
  emit(renderAnalysis(results, args.format), args.output);

  if (args.failOn === 'never') return EXIT_CLEAN;
  const worst = worstSeverity(results);
  if (worst === null) return EXIT_CLEAN;
  return severityRank(worst) >= severityRank(args.failOn) ? EXIT_FINDINGS : EXIT_CLEAN;
}

function runProbe(args: Args): number {
  const resource = args.positionals[0];
  if (resource === undefined) throw new UsageError('probe needs the URL of the resource under test');
  const plan = buildProbePlan({
    resource,
    trustedOrigins: args.trusted,
    ...(args.attackerDomain === null ? {} : { attackerDomain: args.attackerDomain }),
  });
  emit(renderPlan(plan, args.format), args.output);
  return EXIT_CLEAN;
}

/** Write each proof-of-concept page into `dir`, returning the paths written. */
function writePocs(pocs: readonly Poc[], dir: string): string[] {
  if (pocs.length === 0) return [];
  mkdirSync(dir, { recursive: true });
  return pocs.map((poc) => {
    const target = join(dir, poc.filename);
    writeFileSync(target, poc.html, 'utf8');
    return target;
  });
}

function runPoc(args: Args): number {
  if (args.positionals.length === 0) throw new UsageError('poc needs at least one capture file');
  const parts: string[] = [];
  let written = 0;

  for (const path of args.positionals) {
    for (const capture of loadCaptures(path, { trustedOrigins: args.trusted })) {
      const result = analyse(capture);
      const bundle = buildPocs(result);

      if (args.format === 'json') {
        // --out-dir still writes the pages. This branch used to `continue`
        // before the write loop, so `written` stayed 0 and the run ended with
        // "nothing to write; no demonstrable finding" while printing the
        // demonstrable findings in the JSON directly above it.
        const files = args.outDir === null ? [] : writePocs(bundle.pocs, args.outDir);
        written += files.length;
        parts.push(
          JSON.stringify(
            { tool: 'cors-matrix', resource: result.resource, ...bundle, ...(args.outDir === null ? {} : { files }) },
            null,
            2,
          ),
        );
        continue;
      }

      parts.push(`# ${result.resource}`);
      if (bundle.pocs.length === 0) {
        parts.push('No finding in this capture can be demonstrated by a browser page.');
      }
      for (const poc of bundle.pocs) {
        if (args.outDir !== null) {
          const [target] = writePocs([poc], args.outDir);
          written += 1;
          parts.push(`# wrote ${target}  (${poc.rule}, origin ${poc.origin})`);
          parts.push(`# ${poc.servingInstruction}`);
        } else {
          parts.push(`<!-- ${poc.filename}: ${poc.servingInstruction} -->`);
          parts.push(poc.html);
        }
      }
      for (const s of bundle.skipped) parts.push(`# skipped ${s.rule}: ${s.reason}`);
    }
  }

  emit(`${parts.join('\n')}\n`, args.output);
  if (args.outDir !== null && written === 0) {
    process.stderr.write('cors-matrix: nothing to write; no demonstrable finding\n');
  }
  return EXIT_CLEAN;
}

export function main(argv: readonly string[]): number {
  let args: Args;
  try {
    args = parseArgs(argv);
  } catch (err) {
    process.stderr.write(`cors-matrix: ${(err as Error).message}\n\n${USAGE}`);
    return EXIT_USAGE;
  }

  if (args.version) {
    process.stdout.write(`${VERSION}\n`);
    return EXIT_CLEAN;
  }
  if (args.help || args.command === '') {
    process.stdout.write(USAGE);
    return args.help ? EXIT_CLEAN : EXIT_USAGE;
  }

  try {
    switch (args.command) {
      case 'analyse':
      case 'analyze':
        return runAnalyse(args);
      case 'probe':
        return runProbe(args);
      case 'poc':
        return runPoc(args);
      case 'rules':
        emit(renderRules(args.format), args.output);
        return EXIT_CLEAN;
      default:
        process.stderr.write(`cors-matrix: unknown command ${JSON.stringify(args.command)}\n\n${USAGE}`);
        return EXIT_USAGE;
    }
  } catch (err) {
    if (err instanceof UsageError) {
      process.stderr.write(`cors-matrix: ${err.message}\n\n${USAGE}`);
      return EXIT_USAGE;
    }
    if (err instanceof CaptureError || err instanceof ProbeError) {
      process.stderr.write(`cors-matrix: ${err.message}\n`);
      return EXIT_INPUT;
    }
    throw err;
  }
}

/**
 * Run only when this file is the entry point, so the test suite can import
 * `main` without the module executing itself. `realpathSync` on both sides
 * keeps it correct when the bin is reached through a symlink in node_modules.
 */
function invokedDirectly(): boolean {
  const entry = process.argv[1];
  if (entry === undefined) return false;
  try {
    return realpathSync(fileURLToPath(import.meta.url)) === realpathSync(entry);
  } catch {
    return false;
  }
}

if (invokedDirectly()) {
  process.exitCode = main(process.argv.slice(2));
}
