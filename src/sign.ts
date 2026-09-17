/**
 * Re-signing a recorded webhook so the receiver accepts it.
 *
 * This is the part that makes replay actually work. Every provider worth
 * integrating signs its payloads, and every one of them signs the *raw bytes*:
 * parse the JSON and re-serialise it and the signature no longer matches, even
 * though the data is identical. So the body travels as a Buffer from the moment
 * it is captured until the moment it is sent, and is never round-tripped
 * through an object.
 */

import { createHmac, timingSafeEqual } from "node:crypto";

export type Scheme = "none" | "meta" | "github" | "shopify" | "stripe";

export const SCHEMES: Scheme[] = ["none", "meta", "github", "shopify", "stripe"];

export interface Signature {
  header: string;
  value: string;
}

/**
 * Produce the signature header a provider would have sent for this body.
 *
 * `timestamp` only matters for Stripe, which signs `<timestamp>.<body>` and
 * rejects anything older than its tolerance - which is exactly why a replayed
 * Stripe event needs a *fresh* timestamp rather than the recorded one.
 */
export function sign(
  scheme: Scheme,
  secret: string,
  body: Buffer,
  timestamp: number = Math.floor(Date.now() / 1000),
): Signature | null {
  switch (scheme) {
    case "none":
      return null;

    // Meta (WhatsApp, Instagram, Messenger) and GitHub use the same
    // construction and differ only in the header they read it from.
    case "meta":
      return {
        header: "x-hub-signature-256",
        value: `sha256=${createHmac("sha256", secret).update(body).digest("hex")}`,
      };
    case "github":
      return {
        header: "x-hub-signature-256",
        value: `sha256=${createHmac("sha256", secret).update(body).digest("hex")}`,
      };

    case "shopify":
      return {
        header: "x-shopify-hmac-sha256",
        value: createHmac("sha256", secret).update(body).digest("base64"),
      };

    case "stripe": {
      const payload = Buffer.concat([Buffer.from(`${timestamp}.`), body]);
      const v1 = createHmac("sha256", secret).update(payload).digest("hex");
      return { header: "stripe-signature", value: `t=${timestamp},v1=${v1}` };
    }
  }
}

/**
 * Verify a signature the way a receiver would.
 *
 * Exists so the test suite can prove the signing side is right by checking it
 * against an independent implementation of the reading side, rather than
 * against a hard-coded digest that only proves the code still does what it did.
 */
export function verify(scheme: Scheme, secret: string, body: Buffer, headerValue: string): boolean {
  if (scheme === "none") return true;

  let expected: string;
  let received: string;

  if (scheme === "stripe") {
    const parts = new Map(
      headerValue.split(",").map((part) => {
        const index = part.indexOf("=");
        return [part.slice(0, index).trim(), part.slice(index + 1).trim()] as const;
      }),
    );
    const timestamp = parts.get("t");
    received = parts.get("v1") ?? "";
    if (!timestamp || !received) return false;
    expected = createHmac("sha256", secret)
      .update(Buffer.concat([Buffer.from(`${timestamp}.`), body]))
      .digest("hex");
  } else if (scheme === "shopify") {
    expected = createHmac("sha256", secret).update(body).digest("base64");
    received = headerValue;
  } else {
    expected = createHmac("sha256", secret).update(body).digest("hex");
    received = headerValue.startsWith("sha256=") ? headerValue.slice(7) : headerValue;
  }

  // Length check first: timingSafeEqual throws on a length mismatch, and a
  // wrong length is not a secret worth protecting anyway.
  const a = Buffer.from(expected);
  const b = Buffer.from(received);
  return a.length === b.length && timingSafeEqual(a, b);
}

export function isScheme(value: string): value is Scheme {
  return (SCHEMES as string[]).includes(value);
}
