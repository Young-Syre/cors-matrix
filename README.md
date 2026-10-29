# cors-matrix

[![tests](https://github.com/Young-Syre/cors-matrix/actions/workflows/tests.yml/badge.svg)](https://github.com/Young-Syre/cors-matrix/actions/workflows/tests.yml)
[![Node](https://img.shields.io/badge/node-20%20%7C%2022%20%7C%2024-blue.svg)](package.json)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)](package.json)
[![offline](https://img.shields.io/badge/network%20access-none-informational.svg)](#offline-by-construction)

**Decide what a CORS policy actually is from recorded observations, then report what is exploitable. Offline: no DNS, no HTTP, no probing.**

---

## A CORS policy is a function, not a config file

A server does not have a CORS policy in any form you can read off a config
file. What it has is a function. For each request it decides, from the `Origin`
header it was sent, whether to put something in `Access-Control-Allow-Origin`
and whether to add `Access-Control-Allow-Credentials: true`. The policy is
whatever that function does across the whole space of origins, and you only
ever see one point of it at a time.

That is the whole problem. The function is usually a string comparison, because
the value arrives as a string and comparing strings is the obvious thing to do.
So it is written as `origin.endsWith(".acme.example")`, or
`origin.startsWith("https://acme.example")`, or `origin.includes("acme.example")`,
or `new URL(origin).hostname === trusted` — and each of those has a different
set of origins it wrongly accepts:

- `endsWith("acme.example")` accepts `https://notacme.example`.
- `startsWith("https://acme.example")` accepts `https://acme.example.attacker.invalid`.
- `includes("acme.example")` accepts both, and more.
- Comparing `hostname` drops the port, so `https://app.acme.example:1337` passes.
- Comparing the host but not the scheme lets `http://app.acme.example` through.
- An allowlist containing the string `null` is satisfied by any sandboxed iframe.

None of this is visible from reading the code unless you already know to look
for it, and none of it is visible from sending the three or four origins a
tester sends by hand. The usual manual probe is: the app's own origin, one
attacker domain, and sometimes `null`. That resolves "is it wide open", which
is the one case that is already well known and mostly already fixed. It does
not resolve any of the six above.

And when the answer *is* found, it is routinely misgraded in both directions.
`Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`
gets filed as critical; it is not exploitable at all, because step 3 of the
Fetch standard's CORS check requires the header to equal the serialised request
origin once credentials are included, and `*` never does. In the other
direction, an `OPTIONS` response that reflects any origin gets filed as a
critical read primitive when the real response reflects nothing, so the browser
discards the body regardless — the most common false positive in this class.

`cors-matrix` takes the observations you have recorded, applies the CORS check
from the standard rather than an approximation of it, works out which of those
string comparisons explains the answers, and grades the result. Before you have
any observations, it will tell you which origins to send.

## What it does

- **Decides the policy** from a set of recorded `(request origin → response headers)`
  observations, supplied either in a small JSON format or as a HAR file.
- **Applies the Fetch CORS check** step for step, including the three
  consequences people get wrong: `*` never satisfies a credentialed request;
  `Access-Control-Allow-Credentials` is compared against the byte string
  `true`, so `True` does nothing and a header sent twice does nothing either,
  because Fetch combines it into `true, false`; and step 3 is a *byte*
  comparison, so `https://evil.invalid:443` does not match the origin
  `https://evil.invalid` and the endpoint is closed. CM015 reports the value;
  it is not graded as an accepted origin, and no proof-of-concept page is
  generated for it, because none would work.
- **Parses origins rather than pattern-matching them** when deciding what a host
  *is*. Scheme, host and port come through the WHATWG `URL` parser, so the tool
  does not reproduce the bug it is looking for: a single trailing root dot is
  normalised away, because `app.acme.example.` and `app.acme.example` are the
  same host and treating them as different ones made the defender's own host
  read as a prefix of itself. Where the standard says to compare bytes — step 3
  — bytes are compared.
- **Grades on credentials.** Almost every CORS misconfiguration is harmless
  without them, and the difference between a report that lands and one that gets
  closed is usually this distinction.
- **Generates the probe plan** — the exact `Origin` values that resolve a policy
  unambiguously — so it is useful before any capture exists.
- **Generates a minimal proof-of-concept page** for each finding a browser can
  actually demonstrate, including the sandboxed-iframe wrapper needed for the
  null origin.
- **Never makes a network request.** Enforced by a test, not by a promise. See
  [Offline by construction](#offline-by-construction).

## Install

```bash
npm install -g cors-matrix     # once published
# or, from a clone:
npm install && npm run build   # then: node dist/src/cli.js --help
```

Node 20 or newer. **No runtime dependencies** — TypeScript and `@types/node`
are the only `devDependencies`, and CI asserts the `dependencies` object is
empty.

## Quickstart

```bash
# 1. Before you have anything: what should I send?
cors-matrix probe https://api.acme.example/v1/me -t https://app.acme.example

# 2. Send it (the plan prints this loop for you), transcribe into a capture file.

# 3. What is the policy, and what is exploitable?
cors-matrix analyse capture.json -t https://app.acme.example

# 4. Evidence for the report.
cors-matrix poc capture.json --out-dir ./poc
cors-matrix analyse capture.json --format markdown -o cors.md
```

## Worked example: the subtle one

`examples/suffix-match.json` is the capture a careful tester would come back
with and read as clean. The unrelated origin is rejected. The null origin is
rejected. The prefix probe is rejected. `Vary: Origin` is set. The scheme is
checked. Four of the seven probes in the capture come back negative.

```
$ cors-matrix analyse examples/suffix-match.json
cors-matrix — offline analysis. No network request was made.

──────────────────────────────────────────────────────────────────────────────
resource      https://api.kestrel-pay.example/v1/balance
capture       suffix-match.json
description   The subtle case. This policy looks correct: it rejects an unrelated origin, rejects the null origin, rejects the prefix probe, and sets Vary: Origin. The check behind it is hostname.endsWith('kestrel-pay.example'), so it also accepts notkestrel-pay.example — a domain anyone can register.
trusted       https://api.kestrel-pay.example, https://app.kestrel-pay.example
observations  8 (0 pre-flight), 4 origin(s) accepted, 4 rejected
policy        credentials allowed; 4 distinct ACAO value(s); 3 untrusted origin(s) echoed back
──────────────────────────────────────────────────────────────────────────────

CRITICAL  CM004  Suffix-match origin validation
          origin: https://notkestrel-pay.example

          https://notkestrel-pay.example was accepted. Its host ends with
          kestrel-pay.example but not on a label boundary: the host is
          notkestrel-pay.example, and the character before kestrel-pay.example
          is not a dot. That is the signature of a check written as
          origin.endsWith("kestrel-pay.example") or a regular expression with
          an unanchored, undotted suffix. The attacker registers a domain
          ending in kestrel-pay.example, which costs the price of a domain and
          nothing else, and then reads the authenticated response from a page
          they control. The domain kestrel-pay.example was derived by
          stripping labels from a trusted host rather than declared, so
          confirm it is the string the server actually compares against.

          host: notkestrel-pay.example
          matched against: kestrel-pay.example
          derived domain: true

          depends on: the attacker must be able to register a domain whose
          host ends in kestrel-pay.example

          evidence: observation 5

HIGH      CM007  Port-blind origin matching
          origin: https://app.kestrel-pay.example:1337

          https://app.kestrel-pay.example:1337 was accepted although it
          differs from a trusted origin only in its port. The check compared
          hostnames and discarded the port, which is what happens when the
          comparison is written against new URL(origin).hostname. An origin is
          a (scheme, host, port) triple, so this widens the policy to every
          port on that host: a forgotten dev server, a debug listener, a
          container that binds a high port, or an XSS in any application on a
          non-standard port now inherits the trusted origin and reads the
          authenticated response.

          host: app.kestrel-pay.example
          port: 1337

          depends on: the attacker must be able to serve content from some
          port on that host

          evidence: observation 7

MEDIUM    CM008  Subdomain wildcarding with credentials
          origin: https://checkout.kestrel-pay.example

          https://checkout.kestrel-pay.example was accepted as a subdomain of
          kestrel-pay.example with credentials. This is frequently deliberate,
          so it is reported as a dependency rather than a bug: the policy is
          now exactly as strong as the weakest host under kestrel-pay.example.
          That includes subdomains that are dangling — a CNAME to a
          deprovisioned bucket, app or CDN tenancy that someone else can claim
          — and subdomains that merely have an XSS. This tool is offline and
          resolves nothing, so it cannot tell you whether such a subdomain
          exists; that enumeration is the next step, and it is the step that
          decides whether this is a note or a critical.

          wildcarded domain: kestrel-pay.example
          derived domain: true

          depends on: the existence of a claimable, dangling or XSS-prone host
          under kestrel-pay.example; resolve this separately, as cors-matrix
          makes no network requests

          evidence: observation 6

3 finding(s): 1 critical, 1 high, 1 medium
$ echo $?
1
```

The underlying check is `new URL(origin).hostname.endsWith('kestrel-pay.example')`
plus an explicit scheme test. None of its three defects is reachable by the
three origins a tester usually sends by hand — the app's own origin, one
attacker domain, and `null` — because all three of those are answered
correctly.

And a correctly configured policy comes back with nothing, which is the other
half of being useful:

```
$ cors-matrix analyse examples/safe-policy.json
cors-matrix — offline analysis. No network request was made.

──────────────────────────────────────────────────────────────────────────────
resource      https://api.northwind-labs.example/v1/account
capture       safe-policy.json
description   A correctly configured policy: an exact allowlist of one origin, credentials allowed for it only, Vary: Origin set, and every probe outside the allowlist answered with no CORS headers at all.
trusted       https://api.northwind-labs.example, https://app.northwind-labs.example
observations  9 (1 pre-flight), 1 origin(s) accepted, 7 rejected
policy        credentials allowed; 1 distinct ACAO value(s); 0 untrusted origin(s) echoed back
──────────────────────────────────────────────────────────────────────────────

No findings. Every origin outside the trusted set was rejected, and the
allowed origins carry no condition this tool knows how to exploit.
$ echo $?
0
```

## The probe plan

With no capture at all, `probe` emits the origins that resolve the policy. Each
one targets a specific hypothesis about how the check is written, and no two
probes resolve the same hypothesis.

```
$ cors-matrix probe https://api.kestrel-pay.example/v1/balance -t https://app.kestrel-pay.example
cors-matrix probe plan — generated offline. Nothing was sent.

resource         https://api.kestrel-pay.example/v1/balance
resource origin  https://api.kestrel-pay.example
trusted origins  https://api.kestrel-pay.example, https://app.kestrel-pay.example
base domains     kestrel-pay.example
attacker domain  probe.example

13 probes
──────────────────────────────────────────────────────────────────────────────

GET  Origin: https://app.kestrel-pay.example
      the baseline. Establishes what an allowed origin looks like, and whether
      credentials are allowed at all. Every other probe is read against this
      one.

GET  Origin: https://probe.example [exploit needs domain control]
      wholesale reflection. An echo here means there is no origin validation;
      a fixed value or an absent header means there is some. This is the
      single highest-value probe.
      rules: CM001, CM016

GET  Origin: null
      whether the null origin is allowed. Reachable from an iframe with
      sandbox="allow-scripts", so an acceptance needs no domain at all.
      rules: CM002

GET  Origin: https://notkestrel-pay.example [exploit needs domain control]
      an endsWith("kestrel-pay.example") check. This host ends with the
      trusted domain but not on a label boundary, so a parsed comparison
      rejects it and a string comparison does not.
      rules: CM004

GET  Origin: https://kestrel-pay.example.probe.example [exploit needs domain control]
      a startsWith("kestrel-pay.example") check, and any unanchored regular
      expression. Cheapest of the string bugs to exploit: one domain plus a
      wildcard DNS record.
      rules: CM005

GET  Origin: https://x-kestrel-pay.example-x.probe.example [exploit needs domain control]
      an includes("kestrel-pay.example") check that the two probes above miss,
      because the trusted domain sits in the middle of the host rather than at
      either end.
      rules: CM005

GET  Origin: https://probe.kestrel-pay.example
      whether any subdomain of kestrel-pay.example is allowed. An acceptance
      makes the policy only as strong as the weakest host under that domain,
      so the follow-up is subdomain enumeration for dangling or XSS-prone
      hosts.
      rules: CM008

GET  Origin: http://app.kestrel-pay.example
      whether the scheme is compared at all. An acceptance is exploitable from
      a network position rather than from a registered domain, so check for
      preloaded HSTS before grading it.
      rules: CM006

GET  Origin: https://app.kestrel-pay.example:1337
      whether the port is compared. A check written against new
      URL(origin).hostname drops the port, which widens the policy to every
      port on that host.
      rules: CM007

GET  Origin: https://app.kestrel-pay.example.
      whether the check is string-based or parsed. A trailing root dot is a
      different byte string but resolves to the same host in DNS, and a
      browser will send it if the victim reaches the site by that name. It is
      a fingerprint rather than a primitive: the host it names is one the
      defender already controls.

GET  Origin: https://APP.KESTREL-PAY.EXAMPLE [not browser-reachable]
      whether the comparison is case-sensitive. Informational only: a browser
      serialises the origin from a parsed URL, so it always sends a lowercase
      host and can never produce this value. An acceptance tells you the check
      is loose; it does not give you a vector.

GET  Origin: https://app.kestrel-pay.example@probe.example [not browser-reachable; exploit needs domain control]
      whether the check parses the value at all. The origin of that URL is
      https://probe.example, so a browser sends that and never the whole
      string. Relevant only where the Origin value reaches the check from
      somewhere other than a browser — a proxy that rewrites headers, or an
      allowlist shared with redirect validation, which is where this payload
      shape actually pays off.

OPTIONS  Origin: https://probe.example [exploit needs domain control]
      Access-Control-Request-Method: PUT
      Access-Control-Request-Headers: authorization,content-type
      the pre-flight half of the policy: which methods and headers are
      allowed, and whether the OPTIONS handler reaches the same verdict as the
      real handler. Compare it against the GET probe for the same origin.
      rules: CM010, CM011, CM012

──────────────────────────────────────────────────────────────────────────────
Notes

  - Sending a probe requires no control of the domain in the Origin header. It
  is one header on one request. Domain control only matters at the
  exploitation step, and the plan marks which probes need it.

  - Send every probe twice: once with the session cookie or bearer token and
  once without. Access-Control-Allow-Credentials is sometimes emitted only for
  authenticated requests, and a capture taken without credentials will
  under-report.

  - Record the full response header block for each probe, including Vary and
  Set-Cookie. cors-matrix needs Vary to decide CM009 and Set-Cookie to decide
  whether the resource is authenticated.

  - Only probe hosts you are authorised to test, and check the programme scope
  before registering anything the plan marks as requiring domain control.

──────────────────────────────────────────────────────────────────────────────
Collect the captures with something like:

# One request per probe. -D - dumps response headers; -o /dev/null drops the body.
for origin in \
  "https://app.kestrel-pay.example" \
  "https://probe.example" \
  "null" \
  "https://notkestrel-pay.example" \
  "https://kestrel-pay.example.probe.example" \
  "https://x-kestrel-pay.example-x.probe.example" \
  "https://probe.kestrel-pay.example" \
  "http://app.kestrel-pay.example" \
  "https://app.kestrel-pay.example:1337" \
  "https://app.kestrel-pay.example." \
  "https://APP.KESTREL-PAY.EXAMPLE" \
  "https://app.kestrel-pay.example@probe.example" \
; do
  printf '\n=== %s\n' "$origin"
  curl -sS -o /dev/null -D - -H "Origin: $origin" "https://api.kestrel-pay.example/v1/balance"
done
```

Two distinctions in that output are worth pulling out, because they are the
ones that get muddled in practice:

- **`exploit needs domain control`** marks probes whose *exploitation* requires
  registering a domain. *Sending* the probe never does — it is one header on one
  request, and no DNS is involved. Check the programme scope before registering
  anything.
- **`not browser-reachable`** marks values no browser can produce. A browser
  serialises the `Origin` header from a parsed URL, so it always sends a
  lowercase host and never sends userinfo. If the server accepts
  `https://APP.KESTREL-PAY.EXAMPLE`, that tells you the comparison is loose; it
  does not give you a vector. The probes are kept because the first fact is
  worth knowing, and labelled because the second fact gets forgotten.

## Grading: the wildcard case

```
$ cors-matrix analyse examples/wildcard-with-credentials.json
LOW       CM003  Wildcard ACAO with credentials (not honoured)
          origin: *

          The response set Access-Control-Allow-Origin: * together with
          Access-Control-Allow-Credentials: true. This is not exploitable.
          Step 3 of the Fetch standard's CORS check requires
          Access-Control-Allow-Origin to equal the serialised request origin
          when the credentials mode is include, and * never does, so every
          conforming browser fails the credentialed read. It is reported at
          low rather than dismissed for two reasons: it proves the
          credentialed path has never been exercised, and the instinctive fix
          — echo the request origin so the wildcard restriction goes away —
          converts it directly into CM001. Grade it as a configuration defect,
          not a data exposure, and say so in the report.

          evidence: observation 1, 2

1 finding(s): 1 low
```

`ACAO: *` with `ACAC: true` is a configuration defect and not a data exposure,
and a report that calls it critical gets closed. It is still worth reporting at
low: it proves the credentialed path has never been exercised, and the fix
someone reaches for — echo the request origin so the combination becomes legal
— converts it directly into CM001.

The same logic applies to `Access-Control-Allow-Headers: *` and
`Access-Control-Allow-Methods: *` on a credentialed response. Fetch treats the
wildcard literally there, as a header or method literally named `*`, so the
endpoint is more closed than its author intended, not more open.

## Grading: pre-flight versus actual

`examples/preflight-mismatch.json` is a gateway that answers `OPTIONS`
permissively in front of an application that answers `GET` correctly. An origin
that only the pre-flight accepts is not readable, so CM001 is graded **low**
here rather than critical, and the mismatch itself is reported as CM012:

```
$ cors-matrix analyse examples/preflight-mismatch.json --format markdown | head -20
# CORS policy analysis

Produced offline by `cors-matrix`. No network request was made.

## `https://api.saltmarsh-cdn.example/v1/session`

A gateway answers OPTIONS and the application answers GET, and the two disagree. The pre-flight reflects any origin with credentials; the real response does not. A tester who probed with OPTIONS alone would report a critical that does not reproduce.

| | |
| --- | --- |
| Capture | `preflight-mismatch.json` |
| Trusted origins | `https://api.saltmarsh-cdn.example`, `https://console.saltmarsh-cdn.example` |
| Observations | 4 (2 pre-flight) |
| Credentials allowed | yes |
| Untrusted origins echoed back | 1 (reflection not confirmed) |
| Accepted origins | `https://console.saltmarsh-cdn.example`, `https://probe.example` |

| Severity | Rule | Name | Origin |
| --- | --- | --- | --- |
| medium | CM010 | Over-permissive Access-Control-Allow-Headers | — |
```

## Rules

| ID | Name | Max severity | What it means |
| --- | --- | --- | --- |
| CM001 | Arbitrary origin accepted with credentials | critical | An origin unrelated to the resource was echoed into Access-Control-Allow-Origin with Access-Control-Allow-Credentials: true. Any page on the internet can read the authenticated response, so this is account takeover reduced to one victim's page visit. |
| CM002 | null origin allowed with credentials | high | Access-Control-Allow-Origin was null alongside credentials. The null origin is not an unreachable sentinel: an attacker gets it from an iframe with sandbox="allow-scripts" (no allow-same-origin), or from a data: document, both of which they can embed anywhere. |
| CM003 | Wildcard ACAO with credentials (not honoured) | low | Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. No browser honours this combination, so it is not exploitable. It is graded low because it means nobody has tested the credentialed path, and the usual fix — reflecting the origin so the combination becomes legal — turns it straight into CM001. |
| CM004 | Suffix-match origin validation | critical | An origin was accepted whose host ends with a trusted domain but not on a label boundary, e.g. notacme.example for acme.example. The check was endsWith() on a string rather than a comparison of parsed hosts. The attacker registers the domain. |
| CM005 | Prefix or substring origin validation | critical | An origin was accepted whose host merely starts with or contains a trusted domain, e.g. acme.example.attacker.invalid. The check was startsWith() or includes(). The attacker needs one domain and a wildcard DNS record. |
| CM006 | Insecure-scheme origin accepted | high | An http:// origin was accepted for an https:// resource, or an origin with a scheme that has no tuple origin (file:, a WebView scheme) was accepted. A network attacker who can inject into any plaintext page on the host then reads the authenticated response. |
| CM007 | Port-blind origin matching | high | An origin was accepted that differs from a trusted origin only in its port. The check compared hostnames and dropped the port, so an XSS or an attacker-controlled service on any port of the same host — a dev server, a debug listener — becomes a CORS bypass. |
| CM008 | Subdomain wildcarding with credentials | medium | Any subdomain of a trusted domain is accepted with credentials. This is often deliberate, so it is graded medium and reported as a dependency: the policy is only as strong as the weakest subdomain, including ones that are dangling or claimable. |
| CM009 | Vary: Origin missing while ACAO varies | medium | The ACAO value depends on the request origin but the response does not vary on Origin. Any shared cache in front of the resource may store one origin’s ACAO and serve it to another, which either breaks a legitimate origin or hands a third party a cached allow it was never granted. |
| CM010 | Over-permissive Access-Control-Allow-Headers | medium | Access-Control-Allow-Headers is * on a credentialed response — where Fetch treats it as the literal header name "*", not a wildcard — or Authorization is allowed alongside an origin that should not have been accepted. |
| CM011 | Over-permissive Access-Control-Allow-Methods | medium | Access-Control-Allow-Methods is * on a credentialed response (again literal, not a wildcard), or a state-changing method is allowed for an origin that should not have been accepted, turning a read bug into a write bug. |
| CM012 | Pre-flight and actual response disagree | medium | The OPTIONS response and the real response reach different CORS verdicts for the same origin. Whichever way round it is, a tester who probed only one of the two drew the wrong conclusion, and that is the most common source of both false positives and missed findings in CORS testing. |
| CM013 | CORS headers on an unauthenticated resource | info | ACAO is present on a resource that shows no sign of carrying credentials. Nothing is leaked that an attacker could not fetch from their own server. Reported so that it is not re-triaged as a finding. |
| CM014 | Access-Control-Allow-Credentials not exactly "true" | info | The header is present with a value such as True or 1. The Fetch standard compares it against the byte string true, so the value is not honoured and the credentialed path is closed — almost certainly by accident. Verify against a real browser before relying on it. |
| CM015 | Malformed or non-canonical ACAO value | low | ACAO was sent twice, carried a comma-separated list, or was not a canonical origin serialisation (a trailing slash, a path, an explicit default port). Browsers reject all of these, so the policy is closed by accident; it means the header is assembled by string concatenation, which is where the other rules in this table come from. |
| CM016 | Origin reflected without credentials | low | An unrelated origin was echoed into ACAO but credentials are not allowed, so no authenticated data crosses. Origin validation is nonetheless absent: the finding is the one line of configuration between here and CM001, and it already matters for a resource reachable only from inside a network the victim's browser sits in. |

`cors-matrix rules --format json` prints the same table for tooling.

Severities are the worst a rule can reach. Most of them step down when
credentials are not allowed, and down again when the acceptance was observed
only on a pre-flight response. The report states which.

## Capture format

```json
{
  "version": 1,
  "resource": "https://api.acme.example/v1/me",
  "trustedOrigins": ["https://app.acme.example"],
  "authenticated": true,
  "observations": [
    {
      "requestOrigin": "https://probe.example",
      "method": "GET",
      "status": 200,
      "requestHeaders": { "Cookie": "sid=..." },
      "responseHeaders": {
        "access-control-allow-origin": "https://probe.example",
        "access-control-allow-credentials": "true"
      }
    }
  ]
}
```

| Field | Meaning |
| --- | --- |
| `resource` | Absolute URL under test. Its origin is always trusted. |
| `trustedOrigins` | Origins you assert are legitimately allowed. Also settable with `-t`. Without it, a first-party origin the policy allows on purpose is reported as a third-party one. |
| `authenticated` | Whether the resource carries anything worth stealing. Omit it and the analyser infers it from `Cookie`/`Authorization` request headers, `Set-Cookie`, and `Access-Control-Allow-Credentials`. |
| `requestOrigin` | The value sent in `Origin`. **Omit the field** for a request that sent no `Origin` header; use the string `"null"` for the null origin. JSON `null` is rejected, because it reads as both. |
| `method` | Defaults to `GET`. `OPTIONS` marks the observation as a pre-flight. |
| `responseHeaders` | Case-insensitive. A repeated header may be given as an array, which is how a duplicated `Access-Control-Allow-Origin` is recorded. |

A HAR file works too, and yields one analysis per distinct request URL that
carried an `Origin` header. Entries without one are skipped: with no origin
there is no policy decision to observe.

## Proof-of-concept pages

```bash
$ cors-matrix poc examples/reflect-with-credentials.json --out-dir ./poc
```

One page per finding a browser can actually demonstrate, each with a banner
stating it is a test artefact for authorised testing only. The pages make
exactly one request — a `fetch` with `credentials: 'include'` to the resource —
and print the response into the page. Nothing is sent anywhere else, there are
no external scripts, and a test asserts all of that.

The null-origin page is the interesting one. It cannot be served from the
accepted origin, because `null` is not an origin anything can be served from.
Instead it wraps the payload in an iframe with `sandbox="allow-scripts"` and
deliberately *without* `allow-same-origin`, which gives the inner document an
opaque origin, so it sends `Origin: null`. That is why `ACAO: null` is not a
safe value: the attacker needs no domain, only a page the victim will open.

Findings that are configuration defects rather than cross-origin reads get no
page, and the command says which and why instead of generating something that
would not demonstrate anything.

## Offline by construction

The tool never makes a network request. No DNS resolution, no HTTP, no probing,
no telemetry. `test/offline.test.ts` enforces it: it strips comments and string
literals from every file in `src/`, then fails if the remaining executable code
imports `http`, `https`, `http2`, `net`, `tls`, `dns`, `dgram`, `child_process`,
`worker_threads`, any HTTP client package, or calls `fetch`, `XMLHttpRequest`,
`WebSocket`, `sendBeacon` or `require`. It also asserts that the only Node
built-ins imported anywhere are `node:fs`, `node:path` and `node:url`, and that
nothing outside the CLI and the capture reader touches the filesystem at all.

The comment and string stripping matters: `src/poc.ts` writes `fetch(` into the
HTML it generates, and the finding text discusses HTTP constantly, so a plain
grep over the raw files would be useless. A further test exercises the stripper
itself, so the guard cannot pass vacuously.

**The limitation:** this is a static check over `src/`. It cannot catch a socket
opened through a module name assembled at runtime. It is a guard against the
realistic failure — someone adding a "just resolve this subdomain" convenience
later — not a sandbox.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Analysis completed; nothing at or above `--fail-on`. |
| `1` | At least one finding at or above `--fail-on`. |
| `2` | Invalid usage: unknown command, unknown option, missing value, bad format or severity. |
| `3` | An input file could not be read or parsed, or a resource URL was not a URL. |

`--fail-on` defaults to `low`, so anything that is not purely informational
exits 1. `--fail-on never` always exits 0. `probe`, `poc` and `rules` exit 0 on
success.

## Output formats

`--format text` (default), `json` or `markdown`, on every subcommand, with
`-o <path>` to write to a file.

Output is deterministic. There are no timestamps, no hostnames and no run ids,
so two runs over the same capture are byte-identical. That is what makes it
quotable in a report, diffable in CI, and safe to paste into a README without
going stale — every block of output above was produced by the command printed
above it.

## What this tool does not do

- **It does not test anything.** It reads observations you collected. If your
  capture is wrong, incomplete, or taken without a session cookie, the analysis
  is wrong in the same way. `probe` exists to make the capture complete.
- **It does not resolve DNS**, so it cannot tell you whether a wildcarded
  subdomain is dangling or claimable. CM008 reports that as a dependency and
  names it as the next step; the tool will not guess.
- **It bundles no Public Suffix List.** Base domains are derived by stripping
  labels, with a floor of two. For a host under a multi-label public suffix
  (`shop.acme.co.uk`) the derived set therefore includes `co.uk`, which could in
  principle produce an odd `matched against` value. Declaring `trustedOrigins`
  makes the more specific host win, since candidates are tried longest-first.
- **It does not read a browser's mind.** The CORS check implemented here is the
  one in the Fetch standard. Implementations can be more lenient — notably
  around the `Access-Control-Allow-Credentials` casing in CM014 — so confirm
  anything that turns on a spec subtlety against the browser you care about,
  which is also why CM014 is graded `info` and not `low`.
- **It does not parse server configuration.** It cannot tell you *where* the
  broken comparison lives, only what shape it has. The finding text names the
  likely expression; grep for that.
- **It does not handle `Access-Control-Allow-Private-Network` / Local Network
  Access**, or `Timing-Allow-Origin`. Both are adjacent and neither is covered.
- **It writes no PoC for a finding it cannot demonstrate**, and says so rather
  than generating a page that proves nothing.

## Development

```bash
npm install
npm run typecheck     # tsc --noEmit, strict
npm run build
npm test              # builds, then runs node --test over dist/test
```

The test suite is 190 tests in eight files, run with `node --test`. CI runs it
on Node 20, 22 and 24, then asserts the exit codes and the example captures
from the command line — including that the vulnerable example is reported and
the correctly configured one comes back clean.

`tsconfig.json` is `strict` with `noUncheckedIndexedAccess`,
`exactOptionalPropertyTypes`, `noUnusedLocals` and `noImplicitReturns` on.

| File | Responsibility |
| --- | --- |
| `src/origin.ts` | Origin parsing, canonicalisation, and the host-relation classifier. |
| `src/headers.ts` | Case-insensitive header handling and the Fetch CORS check. |
| `src/capture.ts` | Capture and HAR loading, with validation. |
| `src/analyse.ts` | The sixteen rules and the grading logic. |
| `src/probe.ts` | Probe-plan generation. |
| `src/poc.ts` | Proof-of-concept page generation. |
| `src/format.ts` | Text, JSON and Markdown rendering. |
| `src/cli.ts` | Argument parsing and exit codes. |

## Licence

MIT. See [LICENSE](LICENSE).

Use it only against systems you own or have written permission to test.
