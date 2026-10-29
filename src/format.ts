/**
 * Report rendering.
 *
 * Output is deterministic: no timestamps, no hostname, no run id. Two runs
 * over the same capture produce byte-identical output, which is what makes it
 * usable in a CI assertion and quotable in a README without going stale.
 */

import { probeCommandHint, type ProbePlan } from './probe.js';
import { RULES } from './rules.js';
import type { AnalysisResult, Finding, Severity } from './types.js';

export type Format = 'text' | 'json' | 'markdown';

const SEVERITY_LABEL: Readonly<Record<Severity, string>> = {
  critical: 'CRITICAL',
  high: 'HIGH    ',
  medium: 'MEDIUM  ',
  low: 'LOW     ',
  info: 'INFO    ',
};

function wrap(text: string, width: number, indent: string): string {
  const words = text.split(/\s+/).filter((w) => w !== '');
  const lines: string[] = [];
  let line = '';
  for (const word of words) {
    if (line === '') line = word;
    else if (`${line} ${word}`.length + indent.length <= width) line += ` ${word}`;
    else {
      lines.push(line);
      line = word;
    }
  }
  if (line !== '') lines.push(line);
  return lines.map((l) => indent + l).join('\n');
}

/* ------------------------------------------------------------------ *
 * Analysis reports
 * ------------------------------------------------------------------ */

export function renderAnalysis(results: readonly AnalysisResult[], format: Format): string {
  switch (format) {
    case 'json':
      return `${JSON.stringify({ tool: 'cors-matrix', results }, null, 2)}\n`;
    case 'markdown':
      return renderAnalysisMarkdown(results);
    case 'text':
      return renderAnalysisText(results);
  }
}

function renderAnalysisText(results: readonly AnalysisResult[]): string {
  const out: string[] = [];
  out.push('cors-matrix — offline analysis. No network request was made.');
  for (const r of results) {
    out.push('');
    out.push('─'.repeat(78));
    out.push(`resource      ${r.resource}`);
    out.push(`capture       ${r.source}`);
    if (r.description !== null) out.push(`description   ${r.description}`);
    out.push(`trusted       ${r.trustedOrigins.join(', ')}`);
    out.push(
      `observations  ${r.observationCount} (${r.policy.preflightCount} pre-flight), ` +
        `${r.policy.acceptedOrigins.length} origin(s) accepted, ` +
        `${r.policy.rejectedOrigins.length} rejected`,
    );
    out.push(
      `policy        credentials ${r.policy.credentialsAllowed ? 'allowed' : 'not allowed'}; ` +
        `${r.policy.distinctAcaoValues.length} distinct ACAO value(s); ` +
        `${r.policy.echoedUntrustedOrigins} untrusted origin(s) echoed back`,
    );
    out.push('─'.repeat(78));

    for (const w of r.warnings) {
      out.push('');
      out.push(wrap(`warning: ${w}`, 78, ''));
    }

    if (r.findings.length === 0) {
      out.push('');
      out.push('No findings. Every origin outside the trusted set was rejected, and the');
      out.push('allowed origins carry no condition this tool knows how to exploit.');
      continue;
    }

    for (const f of r.findings) {
      out.push('');
      out.push(`${SEVERITY_LABEL[f.severity]}  ${f.rule}  ${f.name}`);
      if (f.origin !== undefined) out.push(`          origin: ${f.origin}`);
      out.push('');
      out.push(wrap(f.detail, 78, '          '));
      if (f.facts !== undefined) {
        out.push('');
        for (const [k, v] of Object.entries(f.facts)) out.push(`          ${k}: ${v}`);
      }
      if (f.dependency !== undefined) {
        out.push('');
        out.push(wrap(`depends on: ${f.dependency}`, 78, '          '));
      }
      if (!f.browserReachable) {
        out.push('');
        out.push('          not reachable from a browser — see the detail above');
      }
      out.push('');
      out.push(`          evidence: observation ${f.evidence.join(', ')}`);
    }

    out.push('');
    out.push(summaryLine(r.findings));
  }
  return `${out.join('\n')}\n`;
}

function summaryLine(findings: readonly Finding[]): string {
  const counts = new Map<Severity, number>();
  for (const f of findings) counts.set(f.severity, (counts.get(f.severity) ?? 0) + 1);
  const parts = (['critical', 'high', 'medium', 'low', 'info'] as const)
    .filter((s) => counts.has(s))
    .map((s) => `${String(counts.get(s))} ${s}`);
  return `${findings.length} finding(s): ${parts.join(', ')}`;
}

function renderAnalysisMarkdown(results: readonly AnalysisResult[]): string {
  const out: string[] = ['# CORS policy analysis', '', 'Produced offline by `cors-matrix`. No network request was made.'];
  for (const r of results) {
    out.push('', `## \`${r.resource}\``, '');
    if (r.description !== null) out.push(r.description, '');
    out.push('| | |', '| --- | --- |');
    out.push(`| Capture | \`${r.source}\` |`);
    out.push(`| Trusted origins | ${r.trustedOrigins.map((t) => `\`${t}\``).join(', ')} |`);
    out.push(`| Observations | ${r.observationCount} (${r.policy.preflightCount} pre-flight) |`);
    out.push(`| Credentials allowed | ${r.policy.credentialsAllowed ? 'yes' : 'no'} |`);
    out.push(
      `| Untrusted origins echoed back | ${r.policy.echoedUntrustedOrigins} (reflection ${
        r.policy.reflectsOrigin ? 'confirmed' : 'not confirmed'
      }) |`,
    );
    out.push(`| Accepted origins | ${r.policy.acceptedOrigins.map((o) => `\`${o}\``).join(', ')} |`);

    if (r.findings.length === 0) {
      out.push('', 'No findings.');
      continue;
    }

    out.push('', '| Severity | Rule | Name | Origin |', '| --- | --- | --- | --- |');
    for (const f of r.findings) {
      out.push(`| ${f.severity} | ${f.rule} | ${f.name} | ${f.origin === undefined ? '—' : `\`${f.origin}\``} |`);
    }

    for (const f of r.findings) {
      out.push('', `### ${f.rule} — ${f.name} (${f.severity})`, '');
      if (f.origin !== undefined) out.push(`Origin: \`${f.origin}\``, '');
      out.push(f.detail);
      if (f.facts !== undefined) {
        out.push('');
        for (const [k, v] of Object.entries(f.facts)) out.push(`- ${k}: \`${v}\``);
      }
      if (f.dependency !== undefined) out.push('', `**Depends on:** ${f.dependency}`);
      if (!f.browserReachable) out.push('', '**Not reachable from a browser.**');
      out.push('', `Evidence: observation ${f.evidence.join(', ')} of \`${r.source}\`.`);
    }
  }
  return `${out.join('\n')}\n`;
}

/* ------------------------------------------------------------------ *
 * Probe plans
 * ------------------------------------------------------------------ */

export function renderPlan(plan: ProbePlan, format: Format): string {
  switch (format) {
    case 'json':
      return `${JSON.stringify({ tool: 'cors-matrix', plan }, null, 2)}\n`;
    case 'markdown':
      return renderPlanMarkdown(plan);
    case 'text':
      return renderPlanText(plan);
  }
}

function flags(p: { browserReachable: boolean; requiresDomainControl: boolean }): string {
  const f: string[] = [];
  if (!p.browserReachable) f.push('not browser-reachable');
  if (p.requiresDomainControl) f.push('exploit needs domain control');
  return f.length === 0 ? '' : ` [${f.join('; ')}]`;
}

function renderPlanText(plan: ProbePlan): string {
  const out: string[] = [];
  out.push('cors-matrix probe plan — generated offline. Nothing was sent.');
  out.push('');
  out.push(`resource         ${plan.resource}`);
  out.push(`resource origin  ${plan.resourceOrigin}`);
  out.push(`trusted origins  ${plan.trustedOrigins.join(', ')}`);
  out.push(`base domains     ${plan.baseDomains.length === 0 ? '(none derived)' : plan.baseDomains.join(', ')}`);
  out.push(`attacker domain  ${plan.attackerDomain}`);
  out.push('');
  out.push(`${plan.probes.length} probes`);
  out.push('─'.repeat(78));
  for (const p of plan.probes) {
    out.push('');
    out.push(`${p.methods.join('/')}  Origin: ${p.origin}${flags(p)}`);
    if (p.requestHeaders !== undefined) {
      for (const [k, v] of Object.entries(p.requestHeaders)) out.push(`      ${k}: ${v}`);
    }
    out.push(wrap(p.resolves, 78, '      '));
    if (p.rules.length > 0) out.push(`      rules: ${p.rules.join(', ')}`);
  }
  out.push('');
  out.push('─'.repeat(78));
  out.push('Notes');
  for (const n of plan.notes) {
    out.push('');
    out.push(wrap(`- ${n}`, 78, '  '));
  }
  out.push('');
  out.push('─'.repeat(78));
  out.push('Collect the captures with something like:');
  out.push('');
  out.push(probeCommandHint(plan));
  return `${out.join('\n')}\n`;
}

function renderPlanMarkdown(plan: ProbePlan): string {
  const out: string[] = ['# CORS probe plan', '', 'Generated offline by `cors-matrix`. Nothing was sent.', ''];
  out.push('| | |', '| --- | --- |');
  out.push(`| Resource | \`${plan.resource}\` |`);
  out.push(`| Trusted origins | ${plan.trustedOrigins.map((t) => `\`${t}\``).join(', ')} |`);
  out.push(`| Derived base domains | ${plan.baseDomains.map((d) => `\`${d}\``).join(', ') || '—'} |`);
  out.push(`| Attacker-controlled domain | \`${plan.attackerDomain}\` |`);
  out.push('', '| Method | `Origin` value | Resolves | Rules |', '| --- | --- | --- | --- |');
  for (const p of plan.probes) {
    out.push(
      `| ${p.methods.join('/')} | \`${p.origin}\` | ${p.resolves.replace(/\|/g, '\\|')}${flags(p)} | ${
        p.rules.join(', ') || '—'
      } |`,
    );
  }
  out.push('', '## Notes', '');
  for (const n of plan.notes) out.push(`- ${n}`);
  out.push('', '## Collecting the captures', '', '```bash', probeCommandHint(plan), '```');
  return `${out.join('\n')}\n`;
}

/* ------------------------------------------------------------------ *
 * Rule table
 * ------------------------------------------------------------------ */

export function renderRules(format: Format): string {
  if (format === 'json') return `${JSON.stringify({ tool: 'cors-matrix', rules: RULES }, null, 2)}\n`;
  if (format === 'markdown') {
    const out = ['| ID | Name | Max severity | What it means |', '| --- | --- | --- | --- |'];
    for (const r of RULES) {
      out.push(`| ${r.id} | ${r.name} | ${r.maxSeverity} | ${r.summary.replace(/\|/g, '\\|')} |`);
    }
    return `${out.join('\n')}\n`;
  }
  const out: string[] = [];
  for (const r of RULES) {
    out.push(`${r.id}  ${r.name}  [max ${r.maxSeverity}]`);
    out.push(wrap(r.summary, 78, '      '));
    out.push('');
  }
  return out.join('\n');
}
