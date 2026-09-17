/**
 * The recording side: an HTTP server that answers everything and writes down
 * what it was asked.
 *
 * It answers 200 immediately and by default. That is not laziness - a provider
 * that does not get a fast 2xx retries, backs off, and eventually disables the
 * subscription, so a capture endpoint that thinks about the payload before
 * answering will change the very traffic it is trying to record.
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { randomUUID } from "node:crypto";

import { append, redact, type Event } from "./store.js";

export interface CaptureOptions {
  port: number;
  file: string;
  status: number;
  body: string;
  /** Called after each captured request, for the console line. */
  onEvent?: (event: Event, bytes: number) => void;
}

function readBody(request: IncomingMessage, limitBytes: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    request.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > limitBytes) {
        reject(new Error(`body larger than ${limitBytes} bytes`));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => resolve(Buffer.concat(chunks)));
    request.on("error", reject);
  });
}

/** 25 MB: larger than any real webhook, small enough not to fill a disk by accident. */
export const BODY_LIMIT = 25 * 1024 * 1024;

export function startCapture(options: CaptureOptions): Promise<Server> {
  const handler = async (request: IncomingMessage, response: ServerResponse): Promise<void> => {
    let body: Buffer;
    try {
      body = await readBody(request, BODY_LIMIT);
    } catch {
      response.writeHead(413).end("payload too large");
      return;
    }

    const headers: Record<string, string> = {};
    for (const [name, value] of Object.entries(request.headers)) {
      headers[name] = Array.isArray(value) ? value.join(", ") : (value ?? "");
    }

    const event: Event = {
      id: randomUUID(),
      at: new Date().toISOString(),
      method: request.method ?? "POST",
      path: request.url ?? "/",
      headers: redact(headers),
      bodyBase64: body.toString("base64"),
      remote: request.socket.remoteAddress ?? undefined,
    };

    append(options.file, event);
    options.onEvent?.(event, body.length);

    response.writeHead(options.status, { "content-type": "text/plain" }).end(options.body);
  };

  const server = createServer((request, response) => {
    void handler(request, response);
  });

  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(options.port, () => resolve(server));
  });
}
