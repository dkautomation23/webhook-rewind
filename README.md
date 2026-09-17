# webhook-replay

[![CI](https://github.com/dkautomation23/webhook-replay/actions/workflows/ci.yml/badge.svg)](https://github.com/dkautomation23/webhook-replay/actions/workflows/ci.yml)

Record the webhooks a provider sends you once, then replay them at your own code
as often as you need — **re-signed, so the receiver accepts them**.

```bash
webhook-replay capture --port 3111 --file hooks.jsonl
webhook-replay replay --file hooks.jsonl --target http://localhost:8080/webhook \
    --scheme shopify --secret "$SHOPIFY_SECRET"
```

No runtime dependencies. TypeScript, Node's own test runner, 30 tests.

## Why this exists

A webhook handler breaks in production. To fix it you need the payload that broke
it, and you need to send it again — which is where every obvious approach fails:

- **Asking the provider to resend** gives you the *next* event, not the one that
  broke. Meta and Shopify will not replay on demand at all.
- **Copying the JSON out of a log and curling it back** fails signature
  verification. Every provider signs the *raw bytes*; pretty-printing the payload
  or re-serialising it through `JSON.parse` changes those bytes, and the receiver
  rejects a body that is semantically identical.
- **Turning verification off while you debug** is how a verification bug ships:
  the code path you are testing is not the code path that runs.

`webhook-replay` keeps the body as bytes from the moment it arrives, and signs
the same bytes with your own secret before sending them on. Your receiver runs
its real verification, against a real signature, on the real payload.

## What it does

**capture** — an HTTP server that answers `200` immediately (a provider that
does not get a fast 2xx retries, backs off, and eventually disables your
subscription) and writes every request to a JSON Lines file: method, path,
headers, body, timestamp.

**list / show** — read the file back, filter on anything in the path, headers or
body, print one event in full.

**replay** — send them to any target, in the order they arrived, with a fresh
signature. Exit code is `1` if anything came back `4xx`/`5xx`, so it works in a
script or a CI job.

```console
$ webhook-replay replay --file hooks.jsonl --target http://localhost:8080/webhook --scheme meta --secret s3cr3t

replaying 3 event(s) to http://localhost:8080/webhook (re-signed for meta)

  200     31 ms  POST http://localhost:8080/webhook  {"object":"whatsapp_business_account","entry":…
  200     12 ms  POST http://localhost:8080/webhook  {"object":"whatsapp_business_account","entry":…
  500     18 ms  POST http://localhost:8080/webhook  {"object":"whatsapp_business_account","entry":…

2 delivered, 1 failed  (2 x 200, 1 x 500)
```

## Signing schemes

| `--scheme` | Header it writes | Construction |
| --- | --- | --- |
| `meta` | `X-Hub-Signature-256` | `sha256=` + HMAC-SHA256 hex of the body — WhatsApp, Instagram, Messenger |
| `github` | `X-Hub-Signature-256` | same construction, listed separately so the intent reads correctly |
| `shopify` | `X-Shopify-Hmac-Sha256` | HMAC-SHA256 of the body, **base64** |
| `stripe` | `Stripe-Signature` | `t=<now>,v1=` + HMAC-SHA256 of `<timestamp>.<body>` |
| `none` | – | forwards the recorded headers untouched |

Stripe gets a **fresh** timestamp on every replay, not the recorded one: Stripe's
own tolerance window rejects an old timestamp, so a faithful copy would always
fail. The stale signature header from the recording is removed before the new one
is written — sending both is how you get a receiver that validates the wrong one.

The test suite proves the signing side against an independent implementation of
the verifying side, for every scheme, rather than against a hard-coded digest
that would only prove the code still does what it did yesterday.

## Your secrets do not end up in the capture file

`Authorization`, `Cookie`, `X-API-Key` and their relatives are replaced with
`[redacted]` before anything is written, and the placeholder is never sent on.
Signature headers are kept — they are the point of the recording, and they are
useless to anyone without the secret.

That matters because a capture file is exactly the kind of thing that gets
pasted into a ticket.

## Install

```bash
git clone https://github.com/dkautomation23/webhook-replay.git
cd webhook-replay
npm install
npm test          # 30 tests, no network
npm run build
node dist/src/cli.js --help
```

Node 22+. Nothing is installed at runtime — the `devDependencies` are TypeScript
and its Node types, and neither ships in the published files.

To receive real webhooks, put any tunnel in front of the capture port:

```bash
webhook-replay capture --port 3111 --file hooks.jsonl
cloudflared tunnel --url http://localhost:3111      # or ngrok http 3111
```

| Flag | Command | Meaning |
| --- | --- | --- |
| `--file` | all | capture file, JSON Lines (default `hooks.jsonl`) |
| `--port` | capture | port to listen on (default 3111) |
| `--status` / `--reply` | capture | what to answer with, for testing a provider's retry behaviour |
| `--target` | replay | where to send them |
| `--scheme` / `--secret` | replay | re-sign; `--secret` also reads `WEBHOOK_REPLAY_SECRET` |
| `--filter` | list, replay | substring of the path, headers or body |
| `--limit` | replay | at most N events |
| `--keep-path` | replay | append the recorded path to the target path |
| `--dry-run` | replay | print what would be sent, send nothing |

## Honest limits

- **It does not decide what a "duplicate" is.** Replaying the same event twice
  sends it twice; whether that creates a second order is your idempotency
  question, and the `X-Replayed-From` header is there so you can answer it.
- **No TLS of its own.** Run it behind a tunnel, not on a public interface.
- **The capture file is plain text on disk.** Credentials are redacted, but the
  payload is not: if the body itself carries personal data, the file inherits it.
- **Bodies are capped at 25 MB** and a larger request is answered `413` rather
  than filling a disk.
- **Replay is sequential** and stays that way — order is part of what makes a
  webhook bug reproducible.
- **Four signing schemes.** A provider that signs differently needs a new case in
  `src/sign.ts`; it is about ten lines, and the test suite is written so that
  adding the scheme to one array covers it.

## License

MIT
