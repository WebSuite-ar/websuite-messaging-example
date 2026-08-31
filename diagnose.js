'use strict';
/**
 * Turn a rejected send back into a short list of things to check.
 *
 * The platform answers every signature failure with a bare `403 E_UNAUTHORIZED`
 * and deliberately will not say which half was wrong — an unauthenticated
 * caller has no business learning that. The real reason goes to the server-side
 * AUTH_REJECT log, which the caller usually cannot read. So the causes have to
 * be reconstructed from what the CLIENT can see, which is what this does.
 *
 * Returns plain strings, no colour codes: the same notes are printed by the CLI
 * and rendered into the receiver's web UI, and there is only one list to keep
 * honest.
 */

const { looksLikeSecret, TOLERANCE_SECONDS } = require('./sign');

/**
 * @param {object}  o
 * @param {number}  o.status         HTTP status the platform returned
 * @param {string}  o.secret         the signing key that was used
 * @param {?number} o.skew           this host's clock minus the server's, seconds
 * @param {?number} o.requestAge     how old the signed timestamp looked TO THE SERVER
 * @param {string}  o.signedContent  the exact bytes that were hashed
 * @param {string}  o.rawBody        the exact bytes that were sent
 * @param {string}  o.timestamp      the `x-pylot-timestamp` that was sent
 * @param {boolean} o.unsigned       true when a Bearer token was used instead
 * @param {object}  o.payload        the parsed request body
 * @returns {string[]} ordered by how often each is the actual cause
 */
function diagnose({
  status,
  secret,
  skew = null,
  requestAge = null,
  signedContent = '',
  rawBody = '',
  timestamp = '',
  unsigned = false,
  payload = null,
}) {
  const notes = [];

  if (status === 403) {
    if (unsigned) {
      notes.push(
        'PYLOT_TOKEN was used instead of a signature — the token is missing, expired, or its role lacks the POST rooms/messages permission.',
      );
      return notes;
    }

    // First, because when the bytes differ the digest cannot match and every
    // other explanation is a red herring.
    if (signedContent && signedContent !== `${timestamp}.${rawBody}`) {
      notes.push(
        'the bytes signed are not the bytes sent — the body changed after signing. Serialize once, hash that string, send that string.',
      );
    }
    if (!secret) {
      notes.push('no signing key was configured — nothing was signed with. Provision one first.');
    } else if (!looksLikeSecret(secret)) {
      notes.push(
        'the signing key does not look real — expected `pwhsec_` + 64 hex chars. Looks like a placeholder copied from .env.example.',
      );
    }
    // The age the SERVER saw, not this host's drift — they differ when the
    // timestamp was back-dated, and it is the server's view the window applies to.
    if (requestAge !== null && Math.abs(requestAge) > TOLERANCE_SECONDS) {
      notes.push(
        `the timestamp was ${requestAge}s old when it reached the server, outside the ±${TOLERANCE_SECONDS}s replay window — rejected regardless of how correct the digest is.` +
          (skew !== null && Math.abs(skew) > TOLERANCE_SECONDS
            ? ` This host's clock is ${skew}s off; sync it (NTP).`
            : ''),
      );
    } else if (skew !== null && Math.abs(skew) > 60) {
      notes.push(`clock skew is ${skew}s — inside the window, but drifting. Worth fixing before it isn't.`);
    }
    if (payload && !payload.roomId && !payload.userConnectionId) {
      notes.push(
        'no `roomId` and no `userConnectionId` — with no target there is no team, so there is no key to verify against.',
      );
    }
    notes.push('the key may have been rotated since it was cached — rotation takes effect immediately, with no grace window.');
    notes.push(
      'a webhook *subscription* secret is not a *signing key*: both are `pwhsec_…`, both HMAC the same way, neither verifies the other.',
    );
    notes.push('a stray Authorization / x-api-key header outranks the signature — send neither.');
  }

  if (status === 404) {
    notes.push('unknown room, or a room owned by another team. Check the id against the team the key belongs to.');
  }
  if (status === 400) {
    notes.push('`message` must be the canonical `{ type, [type]: { … } }` shape, e.g. `{"type":"text","text":{"value":"hi"}}`.');
  }
  return notes;
}

module.exports = { diagnose };
