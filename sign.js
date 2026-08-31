'use strict';
/**
 * The signing half of the Pylot messaging surface — how an external system
 * authenticates to `POST /rooms/messages` with NO api key and NO token.
 *
 * The scheme is symmetric HMAC-SHA256 over `${timestamp}.${rawBody}`, the exact
 * inverse of what `verify()` in index.js does to inbound event deliveries. Two
 * different secrets though, and confusing them is a classic:
 *
 *   - the TEAM SIGNING KEY  → authenticates calls we make INTO Pylot   (this file)
 *   - a SUBSCRIPTION SECRET → signs events Pylot POSTs OUT to us       (index.js)
 *
 * Both are `pwhsec_…`. Both HMAC the same way. Neither verifies the other.
 *
 * Shared by `send.js` (CLI) and the "Send a message" panel on the receiver's
 * status page, so there is exactly one implementation to trust.
 */

const crypto = require('crypto');

/** Replay window the platform enforces on `x-pylot-timestamp`, in seconds. */
const TOLERANCE_SECONDS = 300;

/**
 * Build the signature headers for a send-to-room request.
 *
 * Takes `rawBody` as a STRING, deliberately — not an object to serialize here.
 * The signature covers the exact bytes on the wire, so the caller must hold one
 * string and both hash it and send it. Accepting an object would let this
 * function serialize one way and the HTTP client another (key order, spacing,
 * unicode escaping), which is the single most common cause of a mystery 403.
 *
 * @param {string} rawBody   the exact request body, already serialized
 * @param {string} secret    the team signing key (`pwhsec_…`, prefix included)
 * @param {number} [nowSeconds] injectable clock, for tests and stale-timestamp demos
 * @returns {{timestamp: string, signature: string, signedContent: string, digest: string}}
 */
function signRequest(rawBody, secret, nowSeconds = Math.floor(Date.now() / 1000)) {
  const timestamp = String(nowSeconds);
  // The literal dot between timestamp and body is part of the scheme.
  const signedContent = `${timestamp}.${rawBody}`;
  const digest = crypto.createHmac('sha256', secret).update(signedContent).digest('hex');
  return {
    timestamp,
    // The `sha256=` prefix is optional on the way in (the verifier strips
    // anything before the first `=`) but it matches the outbound scheme and
    // makes a log line unambiguous, so always send it.
    signature: `sha256=${digest}`,
    signedContent,
    digest,
  };
}

/**
 * The full header set for a signed send. `Content-Type: application/json` is
 * not decoration: without it express never parses the body, `req.rawBody` is
 * empty, and the verifier refuses rather than verify against nothing.
 */
function signedHeaders(rawBody, secret, nowSeconds) {
  const { timestamp, signature, signedContent, digest } = signRequest(rawBody, secret, nowSeconds);
  return {
    headers: {
      'Content-Type': 'application/json',
      'x-pylot-timestamp': timestamp,
      'x-pylot-signature': signature,
    },
    signedContent,
    digest,
    timestamp,
  };
}

/**
 * The platform mints `pwhsec_` + 32 random bytes as hex. Anything else is
 * almost certainly a placeholder copied out of `.env.example`, which otherwise
 * presents as "configured" and then fails every signature with a digest
 * mismatch the server refuses to explain.
 */
function looksLikeSecret(secret) {
  return /^pwhsec_[a-f0-9]{64}$/i.test(String(secret || ''));
}

module.exports = { signRequest, signedHeaders, looksLikeSecret, TOLERANCE_SECONDS };
