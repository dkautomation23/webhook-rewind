#!/usr/bin/env node
/**
 * webhook-rewind - record webhooks once, replay them as often as you like.
 *
 * Hand-rolled argument parsing: this is a four-command CLI, and a dependency
 * that has to be audited, updated and trusted is a poor trade for the ~60 lines
 * below. The whole tool has no runtime dependencies for the same reason.
 */

import { bodyOf, matches, read } from "./store.js";
import { startCapture } from "./capture.js";
import { replayAll, summarise, type ReplayOptions } from "./replay.js";
import { isScheme, SCHEMES, type Scheme } from "./sign.js";

const USAGE = `webhook-rewind - record webhooks once, replay them as often as you like.

  webhook-rewind capture --port 3111 --file hooks.jsonl
  webhook-rewind list --file hooks.jsonl [--filter TEXT]
  webhook-rewind show --file hooks.jsonl --id ID
  webhook-rewind replay --file hooks.jsonl --target http://localhost:8080/webhook \\
      [--scheme meta|github|shopify|stripe|none] [--secret S] [--filter TEXT] [--dry-run]

capture
  --port N          port to listen on (default 3111)
  --file PATH       capture file, JSON lines (default hooks.jsonl)
  --status N        status code to answer with (default 200)
  --reply TEXT      body to answer with (default "ok")

replay
  --target URL      where to send them
  --scheme NAME     re-sign for this provider: ${SCHEMES.join(", ")}
  --secret VALUE    signing secret; or set WEBHOOK_REWIND_SECRET
  --keep-path       append the recorded path to the target path
  --filter TEXT     only events whose path, headers or body contain TEXT
  --limit N         at most N events
  --timeout MS      per request (default 15000)
  --dry-run         print what would be sent, send nothing

Exit code is 1 when any replayed request fails, so it fits in a script.
`;

interface Args {
  command: string;
  flags: Map<string, string>;
  bools: Set<string>;
}

function parse(argv: string[]): Args {
  const flags = new Map<string, string>();
  const bools = new Set<string>();

  // `webhook-rewind --help` puts a flag where a command goes. Someone typing
  // that wants the usage text, not a complaint about an unknown command.
  const leading = argv[0] ?? "";
  const isFlag = leading.startsWith("-");
  const command = isFlag ? "" : leading;
  if (leading === "-h") bools.add("help");

  for (let i = isFlag ? 0 : 1; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith("--")) continue;
    const name = token.slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith("--")) {
      bools.add(name);
    } else {
      flags.set(name, next);
      i += 1;
    }
  }
  return { command, flags, bools };
}

function number(args: Args, name: string, fallback: number): number {
  const raw = args.flags.get(name);
  if (raw === undefined) return fallback;
  const value = Number(raw);
  if (!Number.isFinite(value)) fail(`--${name} must be a number, got ${raw}`);
  return value;
}

function fail(message: string): never {
  process.stderr.write(`${message}\n`);
  process.exit(2);
}

function short(body: Buffer, width = 72): string {
  const text = body.toString("utf8").replace(/\s+/g, " ").trim();
  return text.length > width ? `${text.slice(0, width - 1)}…` : text;
}

async function main(): Promise<number> {
  const args = parse(process.argv.slice(2));

  // Asking for help is not a mistake; typing nothing at all is.
  const askedForHelp = args.command === "help" || args.bools.has("help");
  if (!args.command || askedForHelp) {
    process.stdout.write(USAGE);
    return askedForHelp ? 0 : 2;
  }

  const file = args.flags.get("file") ?? "hooks.jsonl";

  if (args.command === "capture") {
    const port = number(args, "port", 3111);
    await startCapture({
      port,
      file,
      status: number(args, "status", 200),
      body: args.flags.get("reply") ?? "ok",
      onEvent: (event, bytes) =>
        process.stdout.write(
          `${event.at}  ${event.method} ${event.path}  ${bytes} B  ${event.id}\n`,
        ),
    });
    process.stdout.write(`listening on http://localhost:${port} - writing to ${file}\n`);
    process.stdout.write("point the provider here (ngrok/cloudflared in front) and press Ctrl+C when done\n");
    return new Promise(() => 0); // runs until interrupted
  }

  const { events, skipped } = await read(file);
  if (skipped > 0) process.stderr.write(`warning: skipped ${skipped} unreadable line(s) in ${file}\n`);

  if (args.command === "list") {
    const needle = args.flags.get("filter") ?? "";
    const shown = events.filter((event) => matches(event, needle));
    for (const event of shown) {
      process.stdout.write(
        `${event.at}  ${event.method.padEnd(6)} ${event.path.padEnd(28)} ${String(bodyOf(event).length).padStart(7)} B  ${event.id}\n`,
      );
    }
    process.stdout.write(`\n${shown.length} of ${events.length} event(s)\n`);
    return 0;
  }

  if (args.command === "show") {
    const id = args.flags.get("id") ?? fail("show needs --id");
    const event = events.find((candidate) => candidate.id === id || candidate.id.startsWith(id));
    if (!event) fail(`no event with id ${id}`);
    process.stdout.write(`${event.method} ${event.path}\n${event.at}\n\n`);
    for (const [name, value] of Object.entries(event.headers)) {
      process.stdout.write(`${name}: ${value}\n`);
    }
    process.stdout.write(`\n${bodyOf(event).toString("utf8")}\n`);
    return 0;
  }

  if (args.command === "replay") {
    const target = args.flags.get("target") ?? fail("replay needs --target");
    const schemeName = args.flags.get("scheme") ?? "none";
    if (!isScheme(schemeName)) fail(`unknown --scheme ${schemeName}; one of ${SCHEMES.join(", ")}`);
    const scheme: Scheme = schemeName;

    const secret = args.flags.get("secret") ?? process.env.WEBHOOK_REWIND_SECRET ?? "";
    if (scheme !== "none" && !secret) {
      fail(`--scheme ${scheme} needs --secret or WEBHOOK_REWIND_SECRET`);
    }

    const needle = args.flags.get("filter") ?? "";
    const limit = number(args, "limit", Number.POSITIVE_INFINITY);
    const selected = events.filter((event) => matches(event, needle)).slice(0, limit);

    if (selected.length === 0) {
      process.stdout.write("nothing to replay\n");
      return 0;
    }

    const options: ReplayOptions = {
      target,
      scheme,
      secret,
      timeoutMs: number(args, "timeout", 15_000),
      dryRun: args.bools.has("dry-run"),
      keepPath: args.bools.has("keep-path"),
    };

    process.stdout.write(
      `${options.dryRun ? "would replay" : "replaying"} ${selected.length} event(s) to ${target}` +
        `${scheme === "none" ? "" : ` (re-signed for ${scheme})`}\n\n`,
    );

    const attempts = await replayAll(selected, options, (attempt) => {
      const status = attempt.status === null ? (attempt.error ? "ERR" : "dry") : String(attempt.status);
      process.stdout.write(
        `  ${status.padStart(3)}  ${String(attempt.ms).padStart(5)} ms  ${attempt.event.method} ${attempt.url}  ${short(bodyOf(attempt.event), 48)}\n`,
      );
      if (attempt.error) process.stdout.write(`       ${attempt.error}\n`);
    });

    const { ok, failed, byStatus } = summarise(attempts);
    const breakdown = [...byStatus.entries()].map(([key, count]) => `${count} x ${key}`).join(", ");
    process.stdout.write(`\n${ok} delivered, ${failed} failed  (${breakdown})\n`);
    return failed > 0 ? 1 : 0;
  }

  fail(`unknown command ${args.command}\n\n${USAGE}`);
}

// `process.exitCode` rather than `process.exit()`: ending the process while a
// keep-alive socket from `fetch` is still open makes libuv assert on Windows and
// the shell sees 127 instead of the code this tool meant to return.
main().then(
  (code) => {
    process.exitCode = code;
  },
  (error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  },
);
