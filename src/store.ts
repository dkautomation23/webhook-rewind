/**
 * How a captured request is written down and read back.
 *
 * One JSON object per line, body base64-encoded. JSONL because a capture file
 * grows while something else is reading it, and because `grep`, `wc -l` and
 * `head` all work on it without a tool.
 *
 * Base64 rather than a string: a webhook body is bytes. A payload with a lone
 * surrogate or a latin-1 accent survives base64 and does not survive a UTF-8
 * round trip - and a body that changed by one byte is a body whose signature no
 * longer verifies.
 */

import { appendFileSync, createReadStream, existsSync } from "node:fs";
import { createInterface } from "node:readline";

export interface Event {
  id: string;
  at: string;
  method: string;
  path: string;
  headers: Record<string, string>;
  bodyBase64: string;
  remote?: string;
}

/**
 * Headers that must never reach disk.
 *
 * A capture file ends up in a bug report, a ticket or a repository. The signature
 * headers stay - they are the point of the recording and are useless without the
 * secret - but anything that *is* a credential is replaced.
 */
const SECRET_HEADERS = new Set([
  "authorization",
  "proxy-authorization",
  "cookie",
  "set-cookie",
  "x-api-key",
  "api-key",
  "x-auth-token",
  "x-access-token",
]);

export const REDACTED = "[redacted]";

export function redact(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) {
    out[name.toLowerCase()] = SECRET_HEADERS.has(name.toLowerCase()) ? REDACTED : value;
  }
  return out;
}

/** Hop-by-hop headers plus the ones the sending side must compute itself. */
const NOT_FORWARDED = new Set([
  "host",
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "content-length",
]);

export function forwardableHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) {
    if (NOT_FORWARDED.has(name.toLowerCase())) continue;
    if (value === REDACTED) continue; // never send the literal placeholder
    out[name] = value;
  }
  return out;
}

export function append(path: string, event: Event): void {
  appendFileSync(path, `${JSON.stringify(event)}\n`, "utf8");
}

/**
 * Read a capture file.
 *
 * A truncated last line is normal - the file may be written to while it is read
 * - so a line that does not parse is skipped rather than fatal, and the count of
 * skipped lines is returned so the caller can say so out loud.
 */
export async function read(path: string): Promise<{ events: Event[]; skipped: number }> {
  if (!existsSync(path)) return { events: [], skipped: 0 };

  const events: Event[] = [];
  let skipped = 0;

  const lines = createInterface({ input: createReadStream(path, "utf8"), crlfDelay: Infinity });
  for await (const line of lines) {
    if (!line.trim()) continue;
    try {
      const parsed = JSON.parse(line) as Event;
      if (typeof parsed.bodyBase64 === "string" && typeof parsed.method === "string") {
        events.push(parsed);
      } else {
        skipped += 1;
      }
    } catch {
      skipped += 1;
    }
  }
  return { events, skipped };
}

export function bodyOf(event: Event): Buffer {
  return Buffer.from(event.bodyBase64, "base64");
}

/** Substring match over path, headers and the decoded body. */
export function matches(event: Event, needle: string): boolean {
  if (!needle) return true;
  const haystack = [
    event.path,
    JSON.stringify(event.headers),
    bodyOf(event).toString("utf8"),
  ].join("\n");
  return haystack.toLowerCase().includes(needle.toLowerCase());
}
