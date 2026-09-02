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
 *
 * `locale` defaults to English so the CLI is unaffected — only the HTTP paths,
 * which know the browser's language, pass one.
 */

const { looksLikeSecret, TOLERANCE_SECONDS } = require('./sign');
const { translator, DEFAULT_LOCALE } = require('./i18n');

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
 * @param {string}  o.locale         'en' | 'es' — CLI leaves it at 'en'
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
  locale = DEFAULT_LOCALE,
}) {
  const tt = translator(locale);
  const notes = [];

  if (status === 403) {
    if (unsigned) {
      notes.push(tt('diag.unsignedToken'));
      return notes;
    }

    // First, because when the bytes differ the digest cannot match and every
    // other explanation is a red herring.
    if (signedContent && signedContent !== `${timestamp}.${rawBody}`) {
      notes.push(tt('diag.bytesDiffer'));
    }
    if (!secret) {
      notes.push(tt('diag.noKey'));
    } else if (!looksLikeSecret(secret)) {
      notes.push(tt('diag.keyNotReal'));
    }
    // The age the SERVER saw, not this host's drift — they differ when the
    // timestamp was back-dated, and it is the server's view the window applies to.
    if (requestAge !== null && Math.abs(requestAge) > TOLERANCE_SECONDS) {
      notes.push(
        tt('diag.staleTimestamp', { age: requestAge, tolerance: TOLERANCE_SECONDS }) +
          (skew !== null && Math.abs(skew) > TOLERANCE_SECONDS
            ? tt('diag.clockAlsoOff', { skew })
            : ''),
      );
    } else if (skew !== null && Math.abs(skew) > 60) {
      notes.push(tt('diag.clockSkew', { skew }));
    }
    if (payload && !payload.roomId && !payload.userConnectionId) {
      notes.push(tt('diag.noTarget'));
    }
    notes.push(tt('diag.rotated'));
    notes.push(tt('diag.subscriptionVsSigning'));
    notes.push(tt('diag.strayAuth'));
  }

  if (status === 404) {
    notes.push(tt('diag.unknownRoom'));
  }
  if (status === 400) {
    notes.push(tt('diag.badMessageShape'));
  }
  return notes;
}

module.exports = { diagnose };
