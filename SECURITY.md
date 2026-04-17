# Security Review

This document summarises the security scan performed on this repository and
records the fixes applied in this PR. Findings are grouped by severity. Items
marked **FIXED** are addressed by this PR; items marked **OPEN** are tracked
here for follow-up.

## Threat model

Telegraph-Image-hosting is deployed as a Cloudflare Pages Functions
application. The interesting attack surface is:

- `/upload` — **unauthenticated** public upload endpoint (by design).
- `/file/:id` — public proxy that serves files by ID, including an image
  moderation path that calls `moderatecontent.com`.
- `/api/manage/*` — **admin** endpoints protected (optionally) by HTTP
  Basic auth, using the `BASIC_USER` / `BASIC_PASS` environment variables.
- `functions/utils/middleware.js` — a telemetry wrapper that forwards request
  metadata to a Sentry project.

There is no SQL database in this project (state is stored in a Cloudflare KV
namespace called `img_url`), so classical SQL injection does not apply. The
scan therefore focused on injection into KV/URLs, unvalidated input, CORS,
debug endpoints, authentication, dependencies, and secret leakage.

---

## Critical

### C-1. Request metadata (including `Authorization`) forwarded to a hard-coded third-party Sentry project — **FIXED (telemetry removed entirely)**

`functions/utils/middleware.js` unconditionally (unless `disable_telemetry`
was explicitly set) wrapped every request with a Sentry plugin whose DSN
pointed at a third-party Sentry organisation:

```
https://219f636ac7bde5edab2c3e16885cb535@o4507041519108096.ingest.us.sentry.io/4507541492727808
```

Inside `telemetryData()`, every incoming request header was copied into
Sentry as a *tag*. That includes the `Authorization` header, which on the
`/api/manage/*` routes carries the operator's Basic-auth credentials
(`BASIC_USER:BASIC_PASS`). `Cookie` and other sensitive headers were also
forwarded verbatim.

Additionally, the telemetry sample rate was fetched from a third-party URL
(`https://frozen-sentinel.pages.dev/signal/sampleRate.json`), meaning the
owner of that domain could at any time dial the rate up to 1.0 and receive
100% of the telemetry (and therefore 100% of the admin credentials of every
Basic-auth-protected deployment of this project).

**Fix:** telemetry has been **removed entirely**. `functions/utils/middleware.js`,
`functions/api/_middleware.js`, and `functions/file/_middleware.js` have
been deleted, the `errorHandling` / `telemetryData` calls removed from
`functions/upload.js`, and the `@cloudflare/pages-plugin-sentry` and
`@sentry/tracing` dependencies dropped from `package.json`. No request
metadata is forwarded to any third party.

---

## High

### H-1. `_middleware.js` returned full error message + stack trace to the client — **FIXED**

`functions/api/manage/_middleware.js` previously caught errors and returned
`` `${err.message}\n${err.stack}` `` as the 500 response body. This leaks
source paths, env variable names, and Cloudflare internals to anyone who
triggers an error (including by crafting a bad `Authorization` header,
since the auth helpers threw exceptions).

Made worse by a latent bug: `basicAuthentication()` used
`throw new BadRequestException(...)`, but `BadRequestException` is a plain
function that returns a `Response` object. `new SomeFn()` returns the
object `SomeFn` explicitly returned, so this threw a `Response` as if it
were an error, which the outer `errorHandling` then stringified — yielding
a 500 (not 400) containing a stack trace.

**Fix:** errors are now logged server-side and the client receives a
generic `500 Internal Server Error`. The auth helpers return
`Response(400)` / `Response(401)` directly instead of abusing
`throw new`. A proper `WWW-Authenticate` header is now also returned on
401 responses so browsers prompt for credentials.

### H-2. Destructive admin endpoints accepted any HTTP method, including `GET` — **FIXED**

`delete`, `block`, `white`, `toggleLike` and `editName` all used
`onRequest` (matches every method) with no method guard. State-changing
endpoints that accept `GET` are trivially reachable from
`<img src>`/`<link rel=prefetch>`/`<iframe>` on any attacker-controlled
page the admin visits. Browsers generally don't auto-replay Basic-auth
credentials cross-origin, but the endpoints are same-origin reachable from
any XSS foothold or user-supplied HTML, and the pattern is simply
dangerous.

**Fix:** `block`, `white`, `toggleLike`, `editName` now require `POST`;
`delete` accepts `POST` or `DELETE`. The admin UI (`admin.html`,
`admin-imgtc.html`) has been updated to send `POST`.

### H-3. Admin endpoints logged the full `env` (including secrets) to Cloudflare logs — **FIXED**

`block/[id].js`, `white/[id].js`, and `delete/[id].js` contained
`console.log(env)` at the top. `env` holds `TG_Bot_Token`, `BASIC_PASS`,
`ModerateContentApiKey`, etc. Those end up in Cloudflare's Workers logs,
which can be tailed by any account member and are surfaced in
`wrangler tail`.

**Fix:** removed the `console.log(env)` / `console.log(params.id)` debug
statements.

---

## Medium

### M-1. Optional Basic auth is unauthenticated when `BASIC_USER` is unset

When `BASIC_USER` is empty / unset, the middleware allows the admin
dashboard (`/api/manage/*`) through without any authentication. This is
explicit project behaviour (the `check.js` endpoint returns
`"Not using basic auth."` in that case). It is not a bug, but operators
must understand that **any deployment without `BASIC_USER`/`BASIC_PASS`
exposes delete/block/whitelist/list APIs to the public internet**.

**Status:** OPEN (documented). We kept the historical behaviour to avoid
breaking existing deployments. Mitigations in this PR: the auth check
is now constant-time, and destructive endpoints require `POST`.

Operators are strongly encouraged to set `BASIC_USER` and `BASIC_PASS` in
production.

### M-2. Timing-unsafe credential comparison — **FIXED**

Credentials were compared with `!==`, which short-circuits on the first
differing byte. In the Cloudflare Workers runtime, network-observable
timing differences are small, but constant-time comparison is trivial and
good practice.

**Fix:** `_middleware.js` now uses a byte-wise XOR compare.

### M-3. Weak default local-dev credentials — **FIXED**

`package.json`'s `start` script baked `BASIC_USER=admin` /
`BASIC_PASS=123` into the local-dev command. Local dev over
`localhost:8080` is low-risk, but the string `BASIC_PASS=123` is the kind
of thing that gets copy-pasted into a deployment shell.

**Fix:** the script now reads from `$BASIC_USER` / `$BASIC_PASS` and falls
back to a clearly-marked `change-me-local-dev-only` placeholder.

### M-4. `npm audit` reports 21 transitive dev-dep vulnerabilities — **OPEN**

All are in `wrangler`'s transitive tree (miniflare → undici, axios,
brace-expansion, etc.). These are **devDependencies only** — they do not
ship in the deployed Worker — but they still affect contributors running
`npm start` / `wrangler pages dev` locally.

`npm audit fix` clears 15/21 by updating the lockfile. The remaining 6 (3
high, 3 moderate) require `wrangler@4`, a breaking major bump. This PR
keeps the lockfile untouched (to stay scoped to source-code security
fixes); the recommended follow-up is to run `npm audit fix` and then
upgrade `wrangler` to v4 in a separate PR and re-test `npm start` /
`npm run ci-test`.

---

## Low / informational

### L-1. `upload` endpoint is unauthenticated, unthrottled, unvalidated

`functions/upload.js` is a public endpoint with no file-size cap,
content-type allowlist, or rate limit. This is **by design** (public image
host), but means a deployment can be trivially used to stash arbitrary
files of any size on the operator's Telegram channel and served from the
operator's domain (malware, phishing kits, etc.). Cloudflare's free tier
caps mitigate cost but not abuse.

**Status:** OPEN (product decision). Recommended follow-up: add a
content-type allowlist, per-IP rate limit (via Turnstile / KV counter),
and an optional size cap.

### L-2. `file/[id].js` proxies arbitrary Telegram file IDs

The proxy fetches `https://telegra.ph/<pathname>` for short IDs and
`https://api.telegram.org/file/bot<TOKEN>/<filePath>` for long IDs. Since
the file path is constant-prefixed to those two hosts, open-proxy/SSRF
risk is limited. The main concern is that the endpoint forwards the
*original* request headers and body to Telegra.ph / Telegram unmodified.

**Status:** OPEN. Recommended follow-up: strip `Authorization`, `Cookie`,
and `Host` from the outgoing request to the upstream.

### L-3. `check.js` discloses whether Basic auth is enabled

`GET /api/manage/check` returns `"Not using basic auth."` verbatim when
auth is disabled, which tells an attacker whether to bother trying to
brute-force.

**Status:** OPEN. Low impact — this is already observable by fetching any
admin route and seeing whether a 401 comes back.

### L-4. No CORS headers set anywhere

No route sets `Access-Control-Allow-*`, so browsers treat all routes as
same-origin-only. This is the safe default; no action needed.

### L-5. No SQL injection vectors

The project does not use SQL. All persistence goes through Cloudflare KV,
which takes string keys — confirmed no `.list({prefix})` / `.get(key)`
calls pass unsanitised input in a way that could escape KV semantics.

### L-6. User input in KV keys

`editName` / `toggleLike` / etc. use `params.id` directly as a KV key.
Cloudflare KV keys are opaque strings (no path semantics), so this is
safe.

---

## Summary

| ID  | Severity | Status             |
| --- | -------- | ------------------ |
| C-1 | Critical | **FIXED**          |
| H-1 | High     | **FIXED**          |
| H-2 | High     | **FIXED**          |
| H-3 | High     | **FIXED**          |
| M-1 | Medium   | Documented (open)  |
| M-2 | Medium   | **FIXED**          |
| M-3 | Medium   | **FIXED**          |
| M-4 | Medium   | Partially fixed    |
| L-1 | Low      | Open (design)      |
| L-2 | Low      | Open               |
| L-3 | Low      | Open               |
| L-4 | Info     | No action          |
| L-5 | Info     | No action          |
| L-6 | Info     | No action          |
