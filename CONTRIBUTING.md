# Contributing

## Setup

    npm ci

Node.js 22 or later (see `engines` in package.json; CI runs 22.x and 24.x).
The tool has no runtime dependencies by design (see the comment at the top
of `src/cli.ts`) — keep it that way unless there's a strong reason not to.

## Build

    npm run build

Runs `tsc`, compiling `src/**/*.ts` and `test/**/*.ts` (see tsconfig.json)
to `dist/`.

## Test

    npm test

Runs `npm run build` and then `node --test "dist/test/**/*.test.js"` — the
compiled tests, via Node's own test runner. There is no separate lint or
format command; `tsc --strict` is what catches type errors.

## What CI checks

`.github/workflows/ci.yml` runs on every push to `main` and on every pull
request, on a Node.js 22.x / 24.x matrix:

    npm ci
    npm run build
    node --test "dist/test/**/*.test.js"

A pull request has to pass on both Node versions.

## Adding a new check

New behavior here is usually a signing scheme (`src/sign.ts`) or a
redaction/forwarding rule (`SECRET_HEADERS` / `NOT_FORWARDED` in
`src/store.ts`). Add the failing case to `test/unit.test.ts` first — for a
scheme, a `sign()`/`verify()` round trip against a fixed body and secret;
for a redaction rule, a header that must come back as `REDACTED`. Then make
it pass.

## Commit messages

One line, sentence case, no trailing period, says what the commit does for
the tool rather than how it does it — for example, from this repo's own
history:

    Answer --help with the usage text
    Exit without crashing on Windows
    README: show the output before explaining it

## Scope

`dist/` is build output, not source — don't edit it or include it in a diff.
