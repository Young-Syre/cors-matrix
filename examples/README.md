# Example captures

Every value in this directory is fabricated. The hostnames use the reserved
`.example` and `.invalid` top-level domains, which cannot be registered, so
nothing here points at a real service. The cookie values are the literal
string `sid=synthetic`.

| File | What it is | Worst finding |
| --- | --- | --- |
| `safe-policy.json` | An exact allowlist of one origin, credentials for that origin only, `Vary: Origin` set, and every probe outside the allowlist answered with no CORS headers at all. | none |
| `reflect-with-credentials.json` | The critical case: the server echoes whatever arrives in `Origin` and sets `Access-Control-Allow-Credentials: true`. | CM001 (critical) |
| `suffix-match.json` | The subtle case. Rejects the unrelated origin, the null origin and the prefix probe, and sets `Vary: Origin` — but the check is `hostname.endsWith('kestrel-pay.example')`. | CM004 (critical) |
| `wildcard-with-credentials.json` | `ACAO: *` with `ACAC: true`. Not exploitable; here so that the grading can be checked. | CM003 (low) |
| `preflight-mismatch.json` | A gateway answers `OPTIONS` permissively and the application answers `GET` correctly. A tester who probed only with `OPTIONS` would file a critical that does not reproduce. | CM012 (medium) |
| `browser-capture.har` | A three-entry HAR, to exercise the HAR reader. Two requests to one API from two different origins, and one request that sent no `Origin` header and is therefore skipped. | CM008 (medium) |

Reproduce the table:

```bash
for f in examples/*.json examples/*.har; do
  echo "== $f"
  node dist/src/cli.js analyse "$f" --fail-on never | tail -1
done
```

## Writing your own

Generate the probe list, answer it with `curl`, and transcribe the response
headers:

```bash
cors-matrix probe https://api.your-target.example/v1/me \
  -t https://app.your-target.example
```

The capture format is one object per observation. `requestOrigin` is the value
sent in the `Origin` header; omit the field to record a request that sent no
`Origin` header, and use the string `"null"` for the null origin. `trustedOrigins`
is the list you assert is legitimately allowed — without it, a first-party
origin the policy allows on purpose is reported as a third-party one.
