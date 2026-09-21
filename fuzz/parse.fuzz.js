/**
 * `verify` is handed a signature header by whoever sent the request. That is
 * the one input in this tool an attacker chooses outright, and the only
 * acceptable answers are true and false - never an exception, which in a
 * receiver means a 500 where a 401 belonged, and never a true it did not earn.
 *
 * The rest is the on-disk format: a recorded event is a line of JSON that a
 * previous run wrote and this run trusts.
 */
import { isScheme, sign, verify } from "../dist/src/sign.js";
import { bodyOf, forwardableHeaders, matches, redact } from "../dist/src/store.js";

const SCHEMES = ["none", "stripe", "shopify", "github", "meta"];
const SECRET = "s3cr3t";

export function fuzz(data) {
  const text = data.toString("utf8");
  const body = Buffer.from(text);

  for (const scheme of SCHEMES) {
    if (!isScheme(scheme)) continue;
    // Any header at all: the answer must be a boolean, never a throw.
    const answer = verify(scheme, SECRET, body, text.slice(0, 400));
    if (typeof answer !== "boolean") {
      throw new Error(`verify(${scheme}) answered ${typeof answer}`);
    }
    if (scheme !== "none" && answer && text.length > 80) {
      throw new Error(`verify(${scheme}) accepted a signature it never issued`);
    }
    // What the tool itself signs must verify against the same secret. `none`
    // signs nothing and says so by returning null, which is the contract.
    const signature = sign(scheme, SECRET, body);
    if (signature === null) {
      if (scheme !== "none") throw new Error(`${scheme} signed nothing`);
    } else if (!verify(scheme, SECRET, body, signature.value)) {
      throw new Error(`${scheme}: this tool signed something it cannot verify`);
    }
  }

  let event;
  try {
    event = JSON.parse(text);
  } catch {
    return;
  }
  if (!event || typeof event !== "object" || Array.isArray(event)) return;
  if (typeof event.bodyBase64 !== "string" || typeof event.method !== "string") return;

  // These three run over an event that came off disk, so every field is
  // whatever a previous run happened to write.
  const decoded = bodyOf(event);
  if (!Buffer.isBuffer(decoded)) throw new Error("bodyOf must return a Buffer");
  matches(event, "needle");
  if (event.headers && typeof event.headers === "object" && !Array.isArray(event.headers)) {
    redact(event.headers);
    forwardableHeaders(event.headers);
  }
}
