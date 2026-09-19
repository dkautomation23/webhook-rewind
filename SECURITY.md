# Security Policy

## Reporting a vulnerability

Please do not open a public issue for a security problem.

- GitHub: use "Report a vulnerability" under this repository's Security tab
  (Private vulnerability reporting) —
  https://github.com/dkautomation23/webhook-rewind/security/advisories/new
- Email: hello@dkautomation.dev

Include what you ran, what you expected, what happened instead, and the
smallest capture file or command that reproduces it (with real secrets
removed).

We aim to send a first response within 3 business days.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x (latest release) | yes |
| anything older | no |

webhook-rewind has not reached 1.0. Only the latest published release is
supported — update before reporting.

## Scope

webhook-rewind writes every captured request to a plain JSON-lines file
that is meant to be attached to a ticket or checked into a repo, and it
holds a signing secret in memory to re-sign requests on replay. What
matters here is that a credential never lands in that file, and that a
replayed request can't be forged or leaked.

In scope:

- A request header that carries a credential and is *not* in the fixed
  redaction list (`SECRET_HEADERS` in `src/store.ts`) reaching the capture
  file unredacted. The list is deliberately explicit (`authorization`,
  `cookie`, `x-api-key`, and similar) — a common credential header missing
  from it is a real gap, and reporting it is welcome even without a full
  exploit.
- The `--secret` value or `WEBHOOK_REWIND_SECRET` leaking into the capture
  file, stdout, or an error message. It is used in-memory by `sign()`
  (`src/sign.ts`) and is never part of a stored `Event`; a path that
  changes that is in scope.
- A way to make `verify()` (`src/sign.ts`) accept a signature without the
  real secret — a non-constant-time comparison, or a scheme mix-up. Note
  that `verify()` already uses `timingSafeEqual`; a bypass of it is what's
  in scope, not its existence.
- `replay` forwarding the literal `[redacted]` placeholder to the target as
  if it were a real header value.
- A captured request body that exceeds the documented 25 MB cap
  (`BODY_LIMIT` in `src/capture.ts`) without being rejected.

Out of scope:

- The capture server (`webhook-rewind capture`) accepting any
  unauthenticated HTTP request and answering 200. That is the documented,
  intended behavior of a local recorder you put behind your own tunnel
  (ngrok/cloudflared) — it is not meant to be exposed as a production
  endpoint.
- The security of the target service you replay against, or of the tunnel
  in front of capture.
