/**
 * The sending side: push recorded events at a target and report what came back.
 *
 * Sequential on purpose. Webhooks from one provider arrive in an order that
 * often matters (created before updated, order before refund), and a receiver
 * that de-duplicates by id will behave differently if the same three events
 * land in a different order. Concurrency here would make the tool non-
 * deterministic in exactly the situation it exists to debug.
 */

import { bodyOf, forwardableHeaders, type Event } from "./store.js";
import { sign, type Scheme } from "./sign.js";

export interface ReplayOptions {
  target: string;
  scheme: Scheme;
  secret: string;
  timeoutMs: number;
  dryRun: boolean;
  /** Keep the recorded path and append it to the target's path. */
  keepPath: boolean;
}

export interface Attempt {
  event: Event;
  url: string;
  status: number | null;
  ms: number;
  error?: string;
}

export function targetUrlFor(event: Event, options: ReplayOptions): string {
  const target = new URL(options.target);
  if (options.keepPath) {
    const recorded = new URL(event.path, "http://placeholder.invalid");
    const base = target.pathname.endsWith("/") ? target.pathname.slice(0, -1) : target.pathname;
    target.pathname = `${base}${recorded.pathname}`;
    for (const [key, value] of recorded.searchParams) target.searchParams.append(key, value);
  }
  return target.toString();
}

export function headersFor(event: Event, options: ReplayOptions): Record<string, string> {
  const body = bodyOf(event);
  const headers = forwardableHeaders(event.headers);

  const signature = sign(options.scheme, options.secret, body);
  if (signature) {
    // Drop whatever the original signature header was before writing the new
    // one: a receiver that reads a different header name than we write would
    // otherwise validate the stale signature and reject a perfectly good replay.
    for (const name of Object.keys(headers)) {
      const lower = name.toLowerCase();
      if (lower.includes("signature") || lower.includes("hmac")) delete headers[name];
    }
    headers[signature.header] = signature.value;
  }

  headers["x-replayed-from"] = event.id;
  headers["x-replayed-at"] = new Date().toISOString();
  return headers;
}

export async function replayOne(event: Event, options: ReplayOptions): Promise<Attempt> {
  const url = targetUrlFor(event, options);
  const started = Date.now();

  if (options.dryRun) {
    return { event, url, status: null, ms: 0 };
  }

  try {
    const response = await fetch(url, {
      method: event.method,
      headers: headersFor(event, options),
      // As a Uint8Array view, not a Buffer: fetch takes BodyInit, and this
      // passes the same bytes through without a copy or an encoding step.
      body:
        event.method === "GET" || event.method === "HEAD"
          ? undefined
          : new Uint8Array(bodyOf(event)),
      signal: AbortSignal.timeout(options.timeoutMs),
    });
    return { event, url, status: response.status, ms: Date.now() - started };
  } catch (error) {
    return {
      event,
      url,
      status: null,
      ms: Date.now() - started,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

export async function replayAll(
  events: Event[],
  options: ReplayOptions,
  onAttempt?: (attempt: Attempt, index: number) => void,
): Promise<Attempt[]> {
  const attempts: Attempt[] = [];
  for (const [index, event] of events.entries()) {
    const attempt = await replayOne(event, options);
    attempts.push(attempt);
    onAttempt?.(attempt, index);
  }
  return attempts;
}

export function summarise(attempts: Attempt[]): { ok: number; failed: number; byStatus: Map<number | string, number> } {
  const byStatus = new Map<number | string, number>();
  let ok = 0;
  let failed = 0;
  for (const attempt of attempts) {
    const key = attempt.status ?? (attempt.error ? "error" : "dry-run");
    byStatus.set(key, (byStatus.get(key) ?? 0) + 1);
    if (typeof attempt.status === "number" && attempt.status < 400) ok += 1;
    else if (attempt.error || (attempt.status ?? 0) >= 400) failed += 1;
  }
  return { ok, failed, byStatus };
}
