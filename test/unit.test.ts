import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, describe, it } from "node:test";

import { append, bodyOf, forwardableHeaders, matches, read, redact, REDACTED, type Event } from "../src/store.js";
import { sign, verify, type Scheme } from "../src/sign.js";
import { headersFor, replayAll, summarise, targetUrlFor, type ReplayOptions } from "../src/replay.js";
import { startCapture } from "../src/capture.js";

const work = mkdtempSync(join(tmpdir(), "webhook-rewind-"));
after(() => rmSync(work, { recursive: true, force: true }));

function event(overrides: Partial<Event> = {}): Event {
  return {
    id: "11111111-2222-3333-4444-555555555555",
    at: "2026-09-17T10:00:00.000Z",
    method: "POST",
    path: "/hooks/orders?shop=demo",
    headers: { "content-type": "application/json", "x-hub-signature-256": "sha256=stale" },
    bodyBase64: Buffer.from('{"id":4711,"total":"19.99"}').toString("base64"),
    ...overrides,
  };
}

function options(overrides: Partial<ReplayOptions> = {}): ReplayOptions {
  return {
    target: "http://localhost:9/webhook",
    scheme: "none",
    secret: "",
    timeoutMs: 2000,
    dryRun: false,
    keepPath: false,
    ...overrides,
  };
}

describe("signing", () => {
  const secret = "s3cr3t";
  const body = Buffer.from('{"hello":"world"}');

  for (const scheme of ["meta", "github", "shopify", "stripe"] as Scheme[]) {
    it(`${scheme}: what we sign is what a receiver verifies`, () => {
      const signature = sign(scheme, secret, body);
      assert.ok(signature, "a signature should be produced");
      assert.equal(verify(scheme, secret, body, signature.value), true);
    });

    it(`${scheme}: the wrong secret is rejected`, () => {
      const signature = sign(scheme, secret, body)!;
      assert.equal(verify(scheme, "wrong", body, signature.value), false);
    });

    it(`${scheme}: one changed byte breaks it`, () => {
      const signature = sign(scheme, secret, body)!;
      assert.equal(verify(scheme, secret, Buffer.from('{"hello":"worlD"}'), signature.value), false);
    });
  }

  it("meta and github agree on the value, which is why both exist", () => {
    assert.equal(sign("meta", secret, body)!.value, sign("github", secret, body)!.value);
  });

  it("shopify signs base64, not hex", () => {
    const value = sign("shopify", secret, body)!.value;
    assert.match(value, /^[A-Za-z0-9+/]+=*$/);
    assert.doesNotMatch(value, /^[0-9a-f]{64}$/);
  });

  it("stripe carries its timestamp and signs it with the body", () => {
    const signature = sign("stripe", secret, body, 1_800_000_000)!;
    assert.match(signature.value, /^t=1800000000,v1=[0-9a-f]{64}$/);
    // The timestamp is part of what is signed: claiming a different one fails.
    const forged = signature.value.replace("t=1800000000", "t=1800000001");
    assert.equal(verify("stripe", secret, body, forged), false);
  });

  it("a body that is not valid UTF-8 still signs and verifies", () => {
    const raw = Buffer.from([0x7b, 0x22, 0x61, 0x22, 0x3a, 0x22, 0xff, 0xfe, 0x22, 0x7d]);
    const signature = sign("meta", secret, raw)!;
    assert.equal(verify("meta", secret, raw, signature.value), true);
    // and the round trip through the store keeps it byte-identical
    assert.deepEqual(bodyOf(event({ bodyBase64: raw.toString("base64") })), raw);
  });

  it("scheme none signs nothing", () => {
    assert.equal(sign("none", secret, body), null);
  });
});

describe("the capture file", () => {
  it("redacts credentials but keeps signatures", () => {
    const headers = redact({
      Authorization: "Bearer real-token",
      "X-API-Key": "key-123",
      Cookie: "session=abc",
      "X-Hub-Signature-256": "sha256=keepme",
      "Content-Type": "application/json",
    });
    assert.equal(headers.authorization, REDACTED);
    assert.equal(headers["x-api-key"], REDACTED);
    assert.equal(headers.cookie, REDACTED);
    assert.equal(headers["x-hub-signature-256"], "sha256=keepme");
    assert.equal(headers["content-type"], "application/json");
  });

  it("round-trips through JSON lines", async () => {
    const file = join(work, "round-trip.jsonl");
    append(file, event({ id: "a" }));
    append(file, event({ id: "b", method: "PUT" }));
    const { events, skipped } = await read(file);
    assert.equal(skipped, 0);
    assert.deepEqual(events.map((e) => e.id), ["a", "b"]);
    assert.equal(events[1].method, "PUT");
  });

  it("survives a half-written last line instead of failing", async () => {
    const file = join(work, "truncated.jsonl");
    append(file, event({ id: "good" }));
    // What a file being appended to while it is read looks like:
    const { appendFileSync } = await import("node:fs");
    appendFileSync(file, '{"id":"half","method":"PO', "utf8");
    const { events, skipped } = await read(file);
    assert.deepEqual(events.map((e) => e.id), ["good"]);
    assert.equal(skipped, 1);
  });

  it("reports an empty result for a file that does not exist", async () => {
    assert.deepEqual(await read(join(work, "nope.jsonl")), { events: [], skipped: 0 });
  });

  it("filters on path, headers and body alike", () => {
    const one = event();
    assert.equal(matches(one, "orders"), true, "path");
    assert.equal(matches(one, "application/json"), true, "headers");
    assert.equal(matches(one, "19.99"), true, "body");
    assert.equal(matches(one, "REFUND"), false);
    assert.equal(matches(one, ""), true, "empty filter matches everything");
  });

  it("does not forward hop-by-hop headers or redacted placeholders", () => {
    const headers = forwardableHeaders({
      host: "capture.example.com",
      "content-length": "17",
      connection: "keep-alive",
      authorization: REDACTED,
      "content-type": "application/json",
    });
    assert.deepEqual(headers, { "content-type": "application/json" });
  });
});

describe("replay", () => {
  it("replaces a stale signature rather than sending both", () => {
    const headers = headersFor(event(), options({ scheme: "meta", secret: "s3cr3t" }));
    assert.notEqual(headers["x-hub-signature-256"], "sha256=stale");
    assert.equal(
      verify("meta", "s3cr3t", bodyOf(event()), headers["x-hub-signature-256"]),
      true,
    );
  });

  it("marks every replayed request so a receiver can tell", () => {
    const headers = headersFor(event(), options());
    assert.equal(headers["x-replayed-from"], event().id);
    assert.ok(headers["x-replayed-at"]);
  });

  it("sends to the target path, and to the recorded one only when asked", () => {
    assert.equal(targetUrlFor(event(), options()), "http://localhost:9/webhook");
    const kept = targetUrlFor(event(), options({ keepPath: true }));
    assert.equal(kept, "http://localhost:9/webhook/hooks/orders?shop=demo");
  });

  it("delivers to a real server, signed, and summarises what came back", async () => {
    const seen: { signature: string; body: string; replayed: string }[] = [];
    const server = createServer((request, response) => {
      const chunks: Buffer[] = [];
      request.on("data", (chunk: Buffer) => chunks.push(chunk));
      request.on("end", () => {
        seen.push({
          signature: String(request.headers["x-hub-signature-256"] ?? ""),
          body: Buffer.concat(chunks).toString("utf8"),
          replayed: String(request.headers["x-replayed-from"] ?? ""),
        });
        response.writeHead(seen.length === 1 ? 200 : 500).end();
      });
    });
    await new Promise<void>((resolve) => server.listen(0, resolve));
    const port = (server.address() as { port: number }).port;

    const attempts = await replayAll(
      [event({ id: "one" }), event({ id: "two" })],
      options({ target: `http://localhost:${port}/hook`, scheme: "meta", secret: "s3cr3t" }),
    );
    server.close();

    assert.equal(seen.length, 2);
    assert.equal(verify("meta", "s3cr3t", Buffer.from(seen[0].body), seen[0].signature), true);
    assert.deepEqual(seen.map((s) => s.replayed), ["one", "two"]);

    const { ok, failed } = summarise(attempts);
    assert.equal(ok, 1);
    assert.equal(failed, 1, "a 500 counts as failed, which is what sets the exit code");
  });

  it("a dry run sends nothing and reports nothing as delivered", async () => {
    const attempts = await replayAll([event()], options({ dryRun: true }));
    assert.equal(attempts[0].status, null);
    assert.equal(summarise(attempts).ok, 0);
  });

  it("an unreachable target is an error, not a crash", async () => {
    const attempts = await replayAll(
      [event()],
      options({ target: "http://127.0.0.1:1/none", timeoutMs: 1500 }),
    );
    assert.equal(attempts[0].status, null);
    assert.ok(attempts[0].error);
    assert.equal(summarise(attempts).failed, 1);
  });
});

describe("capture server", () => {
  it("answers immediately and writes what it was sent", async () => {
    const file = join(work, "captured.jsonl");
    const server = await startCapture({ port: 0, file, status: 202, body: "queued" });
    const port = (server.address() as { port: number }).port;

    const response = await fetch(`http://localhost:${port}/hooks/test?a=1`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: "Bearer leak-me" },
      body: '{"ping":true}',
    });
    assert.equal(response.status, 202);
    assert.equal(await response.text(), "queued");
    server.close();

    const { events } = await read(file);
    assert.equal(events.length, 1);
    assert.equal(events[0].path, "/hooks/test?a=1");
    assert.equal(bodyOf(events[0]).toString("utf8"), '{"ping":true}');
    assert.equal(events[0].headers.authorization, REDACTED, "the token must not reach disk");
  });
});

describe("the first thing a stranger types", () => {
  const cli = fileURLToPath(new URL("../src/cli.js", import.meta.url));

  function runCli(args: string[]): { status: number | null; out: string } {
    const result = spawnSync(process.execPath, [cli, ...args], { encoding: "utf8" });
    return { status: result.status, out: `${result.stdout}${result.stderr}` };
  }

  for (const flag of ["--help", "-h", "help"]) {
    it(`answers \`${flag}\` with the usage text`, () => {
      const { status, out } = runCli([flag]);
      assert.equal(status, 0, `${flag} should not look like a failure`);
      assert.doesNotMatch(out, /unknown command/, "a flag in place of a command is not an unknown command");
      assert.match(out, /webhook-rewind - /);
    });
  }

  it("still says so when the command really is unknown", () => {
    const { status, out } = runCli(["frobnicate"]);
    assert.notEqual(status, 0);
    assert.match(out, /unknown command frobnicate/);
  });
});
