'use strict';
/**
 * Bilingual copy for the receiver's web UI (English / Spanish).
 *
 * One flat dictionary per locale, keyed by dotted strings, with `{name}`
 * placeholders. Values may contain HTML — the page interpolates them raw, the
 * same way the hard-coded English did, so anything caller-supplied still has to
 * go through `esc()` at the call site.
 *
 * Why the locale is resolved server-side rather than in the browser: most of
 * this page is server-rendered (the next-steps list, the delivery rows, the
 * stats, the diagnostic notes from `/_send` and `/_sign`). Translating in the
 * browser would mean shipping every one of those strings twice and re-rendering
 * them client-side. Reading `Accept-Language` on the server gets the browser's
 * language for free, correct on first paint, with no flash of the wrong
 * language and no JS required.
 *
 * The CLI keeps English regardless: `diagnose()` defaults to `en` and only the
 * HTTP paths pass a locale, so `node send.js` output is unchanged.
 */

const SUPPORTED = ['en', 'es'];
const DEFAULT_LOCALE = 'en';

/** Cookie the language toggle writes, so a choice survives a reload. */
const LOCALE_COOKIE = 'pylot.lang';

const MESSAGES = {
  en: {
    // ── chrome ──────────────────────────────────────────────────────────────
    'page.title': 'Pylot messaging playground',
    'page.subtitle': 'Send a signed message, watch the deliveries it causes arrive.',
    'page.copy': 'Copy',
    'page.pasteInto': '← paste into <em>Create subscription</em>',
    'page.localOnly': 'local only — not reachable from the platform',
    'page.nextSteps': 'Next steps',
    'lang.switchTo': 'Español',

    // ── next steps ──────────────────────────────────────────────────────────
    'todo.noToken':
      'Set <code>NGROK_AUTHTOKEN</code> in <code>.env</code> and restart, to get a public URL the platform can reach. <a href="https://dashboard.ngrok.com/get-started/your-authtoken">Get a free token</a>.',
    'todo.tunnelDisabled':
      "Tunnel is off (<code>NO_TUNNEL=1</code>). Point the collection's <em>Simulate a signed delivery</em> at the local URL, or restart without the flag for a public one.",
    'todo.tunnelFailed': 'ngrok failed to start — check the console output, then restart.',
    'todo.noSecret':
      "Set <code>WEBSUITE_WEBHOOK_SECRET</code> in <code>.env</code> and restart. It's the <code>pwhsec_…</code> value returned <strong>once</strong> by <em>Create subscription</em>. Until then payloads are shown but not verified.",
    'todo.secretSuspect':
      "<strong class=\"bad\">Your <code>WEBSUITE_WEBHOOK_SECRET</code> doesn't look like a real one.</strong> It should be <code>pwhsec_</code> followed by 64 hex characters — yours looks like the <code>.env.example</code> placeholder. Every signature will fail with a digest mismatch until you paste the value from <em>Create subscription</em> (or <em>Rotate subscription secret</em>).",
    'todo.noEnvFile':
      'No <code>.env</code> found in <code>{dir}</code> — copy <code>.env.example</code> to <code>.env</code>. Exported shell vars work too. Sending works without it: paste the key into the <em>Send</em> tab.',
    'todo.ready':
      'Ready. Create a subscription pointing at the URL above, then fire <em>Send test event</em> from the Postman collection.',

    // ── tabs ────────────────────────────────────────────────────────────────
    'tab.send': 'Send a message',
    'tab.sign': 'Signature',
    'tab.deliveries': 'Deliveries',
    'tab.setup': 'Setup',

    // ── shared fields ───────────────────────────────────────────────────────
    'field.signingKey': 'signing key',
    'field.signingKeyEnv':
      '<span class="dim">— blank uses <code>PYLOT_SIGNING_SECRET</code> from <code>.env</code> (<code>{hint}</code>)</span>',
    'field.signingKeyRequired':
      '<span class="warn">— required: there is none in <code>.env</code></span>',
    'field.show': 'show',
    'field.hide': 'hide',
    'field.forget': 'forget',
    'field.apiBase': 'API base',
    'field.apiBaseHint': '<span class="dim">— <code>/rooms/messages</code> is appended</span>',

    // ── send tab ────────────────────────────────────────────────────────────
    'send.suspectKey':
      "<strong>The <code>PYLOT_SIGNING_SECRET</code> in <code>.env</code> doesn't look like a real key</strong> — expected <code>pwhsec_</code> + 64 hex. Paste a real one below; it wins over <code>.env</code>.",
    'send.blurb':
      'Signed with the team key — no api key, no token. The key is used to sign this one request and then forgotten: nothing is written to <code>.env</code>, and it goes no further than this process. The browser only ever sees the signature.',
    'send.roomId': 'roomId',
    'send.message': 'message',
    'send.defaultText': 'Hello from the receiver 👋',
    'send.rawBody': 'Raw body (overrides the fields above)',
    'send.button': 'Send signed',
    'send.buttonHint':
      'the resulting <code>message.sent</code> delivery lands under <em>Deliveries</em>',
    'send.pending': 'Signing and sending…',
    'send.queued': '✔ {status} queued — room {roomId}, message {messageId}',
    'send.queuedHint': 'Accepted by the room pipeline — not yet delivered to the customer.',
    'send.failed403Hint':
      'The platform will not say which half of the signature was wrong. Likely causes:',
    'send.trace': 'Signature trace',
    'send.url': 'url',
    'send.clockSkew': 'clock skew',
    'send.ageAtServer': 'age at server',
    'send.bodySent': 'body sent',
    'send.curlRepro': 'curl repro',
    'send.response': 'response',

    // ── signature tab ───────────────────────────────────────────────────────
    'sign.blurb':
      'Body + signing key → signature. <strong>Nothing is sent.</strong> Use this to check a signature your own code produced, or to get a <code>curl</code> that reproduces the request byte for byte.',
    'sign.body': 'body',
    'sign.bodyHint':
      '<span class="dim">— hashed exactly as typed, whitespace and key order included</span>',
    'sign.timestamp': 'timestamp',
    'sign.timestampHint':
      '<span class="dim">— unix seconds; blank means now. Back-date it past ±{tolerance}s to see the replay window bite.</span>',
    'sign.now': 'now',
    'sign.stale': '−10 min',
    'sign.button': 'Compute signature',
    'sign.buttonHint': 'no request is made — this only does the arithmetic',
    'sign.pending': 'Hashing…',
    'sign.ok': '✔ signature computed',
    'sign.okCaveats': '⚠ signature computed, with caveats',
    'sign.age': 'age',
    'sign.ageExpired': '{age}s — expired (±{tolerance}s)',
    'sign.ageInside': '{age}s — inside the ±{tolerance}s window',
    'sign.bodyBytes': '{bytes} bytes',
    'sign.bodyLabel': 'body',
    'sign.signedLabel': 'signed',
    'sign.target': 'target',
    'sign.signedBytesCaption': 'signed bytes — HMAC-SHA256 over exactly this',
    'sign.compactDiffers':
      'the same body, compact — different bytes, so a different digest ({compactDigest}… vs {digest}…)',
    'sign.alreadyCompact':
      'already compact — re-serializing it changes nothing, so any client sends the bytes this digest covers.',
    'sign.curlReproSigned': 'curl repro — sends the bytes that were hashed',

    // ── deliveries tab ──────────────────────────────────────────────────────
    'deliveries.received': 'received',
    'deliveries.verification': 'verification',
    'deliveries.verificationBadKey': 'bad key',
    'deliveries.verificationOn': 'on',
    'deliveries.verificationOff': 'off',
    'deliveries.tolerance': 'tolerance',
    'deliveries.replyOnBadSig': 'reply on bad sig',
    'deliveries.recent': 'Recent deliveries',
    'deliveries.empty': 'Nothing yet — deliveries appear here and in the console.',
    'deliveries.verified': '✔ verified',
    'deliveries.unchecked': '… unchecked',
    'deliveries.invalid': '✘ invalid',
    'deliveries.retry': '↻ retry',
    'deliveries.truncated': '… truncated',

    // ── setup tab ───────────────────────────────────────────────────────────
    'setup.configLoaded': 'config: <code>.env</code> loaded from <code>{dir}</code>',
    'setup.configNone': 'config: no <code>.env</code> from <code>{dir}</code>',
    'setup.subscriptionSecret': ' · subscription secret <code>{hint}</code>',
    'setup.signingKey': ' · signing key <code>{hint}</code>',
    'setup.noSigningKey': ' · no signing key in <code>.env</code>',
    'setup.sendingTo': ' · sending to <code>{url}</code>',
    'setup.editEnv': 'Edit <code>.env</code> in <code>{dir}</code>, then restart:',
    'setup.envSecret': 'from Create subscription, shown once',
    'setup.envNgrokToken': 'free, for a public URL',
    'setup.envNgrokDomain': 'optional: stable URL across restarts',
    'setup.envSigningKey': 'optional here — the Send tab takes one too',
    'setup.envRejectInvalid': 'reply 401 on a bad signature, to see retries',
    'setup.restartNote':
      'Only <code>WEBSUITE_WEBHOOK_SECRET</code> needs a restart to take effect — it verifies inbound deliveries. The signing key and the API base can be typed into the send-side tabs instead, which is the faster loop when you are testing against more than one team or environment.',

    // ── key attribution line ────────────────────────────────────────────────
    'key.signedWithTyped': 'signed with {hint} (typed above)',
    'key.signedWithEnv': 'signed with {hint} (PYLOT_SIGNING_SECRET)',

    // ── server-side errors ──────────────────────────────────────────────────
    'err.noSigningKeySend':
      'No signing key. Paste one into the Signing key field, or set PYLOT_SIGNING_SECRET in .env — get it from GET /rooms/signing-key or `node send.js --provision`.',
    'err.rawBodyInvalidJson': 'raw body is not valid JSON: {message}',
    'err.noTarget': 'No target — give a roomId, or a userConnectionId (+ transportId).',
    'err.unreachable': 'could not reach {url} — {message}',
    'err.nothingToSign': 'Nothing to sign — paste the request body you intend to send.',
    'err.noSigningKeySign': 'No signing key. Paste one above, or set PYLOT_SIGNING_SECRET in .env.',
    'err.notUnixSeconds': '`{value}` is not unix seconds. Leave it blank for now.',

    // ── signature warnings ──────────────────────────────────────────────────
    'warn.keyNotReal':
      'That key does not look real — expected `pwhsec_` + 64 hex chars. The digest below is still arithmetically correct; the platform will simply 403 it.',
    'warn.bodyNotJson':
      'The body is not valid JSON ({error}). It was signed anyway, byte for byte — but POST /rooms/messages answers 400 before the signature matters.',
    'warn.notCompact':
      'This body is not compact, so any client that re-serializes it (a JSON.parse → JSON.stringify round trip, most HTTP libraries given an object) puts different bytes on the wire than the ones hashed here. Send exactly these bytes, or sign the compact form shown below.',
    'warn.expired':
      'The timestamp is {age}s old, outside the ±{tolerance}s replay window — this signature is already expired and gets a 403 however correct the digest is.',

    // ── diagnostics (shared with the CLI, which always uses `en`) ───────────
    'diag.unsignedToken':
      'PYLOT_TOKEN was used instead of a signature — the token is missing, expired, or its role lacks the POST rooms/messages permission.',
    'diag.bytesDiffer':
      'the bytes signed are not the bytes sent — the body changed after signing. Serialize once, hash that string, send that string.',
    'diag.noKey': 'no signing key was configured — nothing was signed with. Provision one first.',
    'diag.keyNotReal':
      'the signing key does not look real — expected `pwhsec_` + 64 hex chars. Looks like a placeholder copied from .env.example.',
    'diag.staleTimestamp':
      'the timestamp was {age}s old when it reached the server, outside the ±{tolerance}s replay window — rejected regardless of how correct the digest is.',
    'diag.clockAlsoOff': " This host's clock is {skew}s off; sync it (NTP).",
    'diag.clockSkew':
      "clock skew is {skew}s — inside the window, but drifting. Worth fixing before it isn't.",
    'diag.noTarget':
      'no `roomId` and no `userConnectionId` — with no target there is no team, so there is no key to verify against.',
    'diag.rotated':
      'the key may have been rotated since it was cached — rotation takes effect immediately, with no grace window.',
    'diag.subscriptionVsSigning':
      'a webhook *subscription* secret is not a *signing key*: both are `pwhsec_…`, both HMAC the same way, neither verifies the other.',
    'diag.strayAuth':
      'a stray Authorization / x-api-key header outranks the signature — send neither.',
    'diag.unknownRoom':
      'unknown room, or a room owned by another team. Check the id against the team the key belongs to.',
    'diag.badMessageShape':
      '`message` must be the canonical `{ type, [type]: { … } }` shape, e.g. `{"type":"text","text":{"value":"hi"}}`.',
  },

  es: {
    // ── chrome ──────────────────────────────────────────────────────────────
    'page.title': 'Playground de mensajería de Pylot',
    'page.subtitle': 'Enviá un mensaje firmado y mirá llegar las entregas que provoca.',
    'page.copy': 'Copiar',
    'page.pasteInto': '← pegala en <em>Create subscription</em>',
    'page.localOnly': 'solo local — la plataforma no puede alcanzarla',
    'page.nextSteps': 'Próximos pasos',
    'lang.switchTo': 'English',

    // ── next steps ──────────────────────────────────────────────────────────
    'todo.noToken':
      'Configurá <code>NGROK_AUTHTOKEN</code> en <code>.env</code> y reiniciá, para tener una URL pública que la plataforma pueda alcanzar. <a href="https://dashboard.ngrok.com/get-started/your-authtoken">Conseguí un token gratis</a>.',
    'todo.tunnelDisabled':
      'El túnel está apagado (<code>NO_TUNNEL=1</code>). Apuntá <em>Simulate a signed delivery</em> de la colección a la URL local, o reiniciá sin el flag para tener una pública.',
    'todo.tunnelFailed': 'ngrok no pudo arrancar — revisá la salida de la consola y reiniciá.',
    'todo.noSecret':
      'Configurá <code>WEBSUITE_WEBHOOK_SECRET</code> en <code>.env</code> y reiniciá. Es el valor <code>pwhsec_…</code> que <em>Create subscription</em> devuelve <strong>una sola vez</strong>. Hasta entonces los payloads se muestran pero no se verifican.',
    'todo.secretSuspect':
      '<strong class="bad">Tu <code>WEBSUITE_WEBHOOK_SECRET</code> no parece uno real.</strong> Debería ser <code>pwhsec_</code> seguido de 64 caracteres hex — el tuyo parece el placeholder de <code>.env.example</code>. Todas las firmas van a fallar por digest que no coincide hasta que pegues el valor de <em>Create subscription</em> (o de <em>Rotate subscription secret</em>).',
    'todo.noEnvFile':
      'No hay <code>.env</code> en <code>{dir}</code> — copiá <code>.env.example</code> a <code>.env</code>. Las variables exportadas en la shell también sirven. Enviar funciona igual: pegá la clave en la pestaña <em>Enviar</em>.',
    'todo.ready':
      'Listo. Creá una suscripción apuntando a la URL de arriba y dispará <em>Send test event</em> desde la colección de Postman.',

    // ── tabs ────────────────────────────────────────────────────────────────
    'tab.send': 'Enviar un mensaje',
    'tab.sign': 'Firma',
    'tab.deliveries': 'Entregas',
    'tab.setup': 'Configuración',

    // ── shared fields ───────────────────────────────────────────────────────
    'field.signingKey': 'clave de firma',
    'field.signingKeyEnv':
      '<span class="dim">— en blanco usa <code>PYLOT_SIGNING_SECRET</code> de <code>.env</code> (<code>{hint}</code>)</span>',
    'field.signingKeyRequired':
      '<span class="warn">— obligatoria: no hay ninguna en <code>.env</code></span>',
    'field.show': 'mostrar',
    'field.hide': 'ocultar',
    'field.forget': 'olvidar',
    'field.apiBase': 'base de la API',
    'field.apiBaseHint': '<span class="dim">— se le agrega <code>/rooms/messages</code></span>',

    // ── send tab ────────────────────────────────────────────────────────────
    'send.suspectKey':
      '<strong>El <code>PYLOT_SIGNING_SECRET</code> de <code>.env</code> no parece una clave real</strong> — se esperaba <code>pwhsec_</code> + 64 hex. Pegá una real acá abajo; tiene prioridad sobre <code>.env</code>.',
    'send.blurb':
      'Firmado con la clave del equipo — sin api key, sin token. La clave se usa para firmar esta única solicitud y después se olvida: no se escribe nada en <code>.env</code> y no sale de este proceso. El navegador solo ve la firma.',
    'send.roomId': 'roomId',
    'send.message': 'mensaje',
    'send.defaultText': 'Hola desde el receptor 👋',
    'send.rawBody': 'Body crudo (tiene prioridad sobre los campos de arriba)',
    'send.button': 'Enviar firmado',
    'send.buttonHint':
      'la entrega <code>message.sent</code> resultante aparece en <em>Entregas</em>',
    'send.pending': 'Firmando y enviando…',
    'send.queued': '✔ {status} encolado — sala {roomId}, mensaje {messageId}',
    'send.queuedHint': 'Aceptado por el pipeline de la sala — todavía no entregado al cliente.',
    'send.failed403Hint':
      'La plataforma no va a decir cuál de las dos mitades de la firma estaba mal. Causas probables:',
    'send.trace': 'Traza de la firma',
    'send.url': 'url',
    'send.clockSkew': 'desfase de reloj',
    'send.ageAtServer': 'antigüedad en el servidor',
    'send.bodySent': 'body enviado',
    'send.curlRepro': 'curl para reproducirlo',
    'send.response': 'respuesta',

    // ── signature tab ───────────────────────────────────────────────────────
    'sign.blurb':
      'Body + clave de firma → firma. <strong>No se envía nada.</strong> Usalo para chequear una firma que produjo tu propio código, o para obtener un <code>curl</code> que reproduce la solicitud byte por byte.',
    'sign.body': 'body',
    'sign.bodyHint':
      '<span class="dim">— se hashea exactamente como está escrito, espacios y orden de claves incluidos</span>',
    'sign.timestamp': 'timestamp',
    'sign.timestampHint':
      '<span class="dim">— segundos unix; en blanco significa ahora. Atrasalo más de ±{tolerance}s para ver actuar la ventana de replay.</span>',
    'sign.now': 'ahora',
    'sign.stale': '−10 min',
    'sign.button': 'Calcular firma',
    'sign.buttonHint': 'no se hace ninguna solicitud — esto solo hace la cuenta',
    'sign.pending': 'Hasheando…',
    'sign.ok': '✔ firma calculada',
    'sign.okCaveats': '⚠ firma calculada, con salvedades',
    'sign.age': 'antigüedad',
    'sign.ageExpired': '{age}s — vencida (±{tolerance}s)',
    'sign.ageInside': '{age}s — dentro de la ventana de ±{tolerance}s',
    'sign.bodyBytes': '{bytes} bytes',
    'sign.bodyLabel': 'body',
    'sign.signedLabel': 'firmado',
    'sign.target': 'destino',
    'sign.signedBytesCaption': 'bytes firmados — HMAC-SHA256 sobre exactamente esto',
    'sign.compactDiffers':
      'el mismo body, compacto — bytes distintos, así que un digest distinto ({compactDigest}… vs {digest}…)',
    'sign.alreadyCompact':
      'ya está compacto — volver a serializarlo no cambia nada, así que cualquier cliente envía los bytes que cubre este digest.',
    'sign.curlReproSigned': 'curl para reproducirlo — envía los bytes que se hashearon',

    // ── deliveries tab ──────────────────────────────────────────────────────
    'deliveries.received': 'recibidas',
    'deliveries.verification': 'verificación',
    'deliveries.verificationBadKey': 'clave mala',
    'deliveries.verificationOn': 'activada',
    'deliveries.verificationOff': 'desactivada',
    'deliveries.tolerance': 'tolerancia',
    'deliveries.replyOnBadSig': 'respuesta con firma inválida',
    'deliveries.recent': 'Entregas recientes',
    'deliveries.empty': 'Nada todavía — las entregas aparecen acá y en la consola.',
    'deliveries.verified': '✔ verificada',
    'deliveries.unchecked': '… sin verificar',
    'deliveries.invalid': '✘ inválida',
    'deliveries.retry': '↻ reintento',
    'deliveries.truncated': '… truncado',

    // ── setup tab ───────────────────────────────────────────────────────────
    'setup.configLoaded': 'config: <code>.env</code> cargado desde <code>{dir}</code>',
    'setup.configNone': 'config: sin <code>.env</code> en <code>{dir}</code>',
    'setup.subscriptionSecret': ' · secreto de suscripción <code>{hint}</code>',
    'setup.signingKey': ' · clave de firma <code>{hint}</code>',
    'setup.noSigningKey': ' · sin clave de firma en <code>.env</code>',
    'setup.sendingTo': ' · enviando a <code>{url}</code>',
    'setup.editEnv': 'Editá <code>.env</code> en <code>{dir}</code> y reiniciá:',
    'setup.envSecret': 'de Create subscription, se muestra una sola vez',
    'setup.envNgrokToken': 'gratis, para tener una URL pública',
    'setup.envNgrokDomain': 'opcional: URL estable entre reinicios',
    'setup.envSigningKey': 'opcional acá — la pestaña Enviar también acepta una',
    'setup.envRejectInvalid': 'responder 401 ante una firma inválida, para ver los reintentos',
    'setup.restartNote':
      'Solo <code>WEBSUITE_WEBHOOK_SECRET</code> necesita reiniciar para tomar efecto — es el que verifica las entregas entrantes. La clave de firma y la base de la API se pueden escribir en las pestañas de envío, que es el loop más rápido cuando probás contra más de un equipo o entorno.',

    // ── key attribution line ────────────────────────────────────────────────
    'key.signedWithTyped': 'firmado con {hint} (escrita arriba)',
    'key.signedWithEnv': 'firmado con {hint} (PYLOT_SIGNING_SECRET)',

    // ── server-side errors ──────────────────────────────────────────────────
    'err.noSigningKeySend':
      'No hay clave de firma. Pegá una en el campo Clave de firma, o configurá PYLOT_SIGNING_SECRET en .env — la obtenés de GET /rooms/signing-key o con `node send.js --provision`.',
    'err.rawBodyInvalidJson': 'el body crudo no es JSON válido: {message}',
    'err.noTarget': 'Sin destino — pasá un roomId, o un userConnectionId (+ transportId).',
    'err.unreachable': 'no se pudo alcanzar {url} — {message}',
    'err.nothingToSign': 'No hay nada para firmar — pegá el body de la solicitud que vas a enviar.',
    'err.noSigningKeySign':
      'No hay clave de firma. Pegá una arriba, o configurá PYLOT_SIGNING_SECRET en .env.',
    'err.notUnixSeconds': '`{value}` no son segundos unix. Dejalo en blanco para usar ahora.',

    // ── signature warnings ──────────────────────────────────────────────────
    'warn.keyNotReal':
      'Esa clave no parece real — se esperaba `pwhsec_` + 64 caracteres hex. El digest de abajo igual es aritméticamente correcto; la plataforma simplemente lo va a rechazar con 403.',
    'warn.bodyNotJson':
      'El body no es JSON válido ({error}). Se firmó igual, byte por byte — pero POST /rooms/messages responde 400 antes de que la firma importe.',
    'warn.notCompact':
      'Este body no está compacto, así que cualquier cliente que lo vuelva a serializar (un ida y vuelta JSON.parse → JSON.stringify, la mayoría de las librerías HTTP si les pasás un objeto) pone en el cable bytes distintos de los que se hashearon acá. Enviá exactamente estos bytes, o firmá la forma compacta que se muestra abajo.',
    'warn.expired':
      'El timestamp tiene {age}s, fuera de la ventana de replay de ±{tolerance}s — esta firma ya está vencida y recibe un 403 por más correcto que sea el digest.',

    // ── diagnostics ─────────────────────────────────────────────────────────
    'diag.unsignedToken':
      'Se usó PYLOT_TOKEN en lugar de una firma — el token falta, está vencido, o su rol no tiene el permiso POST rooms/messages.',
    'diag.bytesDiffer':
      'los bytes firmados no son los bytes enviados — el body cambió después de firmar. Serializá una vez, hasheá esa cadena, enviá esa cadena.',
    'diag.noKey':
      'no había ninguna clave de firma configurada — no se firmó con nada. Provisioná una primero.',
    'diag.keyNotReal':
      'la clave de firma no parece real — se esperaba `pwhsec_` + 64 caracteres hex. Parece un placeholder copiado de .env.example.',
    'diag.staleTimestamp':
      'el timestamp tenía {age}s cuando llegó al servidor, fuera de la ventana de replay de ±{tolerance}s — rechazado por más correcto que sea el digest.',
    'diag.clockAlsoOff': ' El reloj de este host está {skew}s corrido; sincronizalo (NTP).',
    'diag.clockSkew':
      'el desfase de reloj es de {skew}s — dentro de la ventana, pero derivando. Conviene arreglarlo antes de que deje de estarlo.',
    'diag.noTarget':
      'sin `roomId` ni `userConnectionId` — sin destino no hay equipo, así que no hay clave contra la cual verificar.',
    'diag.rotated':
      'puede que la clave se haya rotado desde que la cacheaste — la rotación toma efecto de inmediato, sin período de gracia.',
    'diag.subscriptionVsSigning':
      'el secreto de una *suscripción* de webhook no es una *clave de firma*: ambos son `pwhsec_…`, ambos hacen HMAC igual, ninguno verifica al otro.',
    'diag.strayAuth':
      'una cabecera Authorization / x-api-key de más tiene prioridad sobre la firma — no mandes ninguna de las dos.',
    'diag.unknownRoom':
      'sala desconocida, o una sala de otro equipo. Verificá el id contra el equipo al que pertenece la clave.',
    'diag.badMessageShape':
      '`message` tiene que tener la forma canónica `{ type, [type]: { … } }`, por ejemplo `{"type":"text","text":{"value":"hi"}}`.',
  },
};

/** Narrow anything to a supported locale. */
function normalize(value) {
  const lower = String(value || '').toLowerCase();
  // Match the primary subtag, so `es-AR`, `es_419` and `es` all land on `es`.
  const primary = lower.split(/[-_]/)[0];
  return SUPPORTED.includes(primary) ? primary : null;
}

/**
 * Parse a `Cookie` header without pulling in cookie-parser — one cookie is not
 * worth a dependency in a throwaway playground.
 */
function readCookie(header, name) {
  return (
    String(header || '')
      .split(';')
      .map((part) => part.trim())
      .filter(Boolean)
      .map((part) => {
        const eq = part.indexOf('=');
        return eq === -1 ? [part, ''] : [part.slice(0, eq), part.slice(eq + 1)];
      })
      .find(([key]) => key === name)?.[1] ?? null
  );
}

/**
 * Pick the locale for a request, most explicit signal first:
 *
 *   1. `?lang=` — what the toggle links to, and what makes a language
 *      shareable in a URL.
 *   2. the `pylot.lang` cookie — a previous toggle click, so the choice sticks.
 *   3. `Accept-Language` — the browser's own setting, which is the default the
 *      page is asked to honour.
 *   4. English.
 *
 * `Accept-Language` is parsed by q-value so a browser configured
 * `en;q=0.8, es` gets Spanish, not the first one listed.
 */
function resolveLocale(req) {
  const fromQuery = normalize(req.query && req.query.lang);
  if (fromQuery) {
    return fromQuery;
  }
  const fromCookie = normalize(readCookie(req.headers && req.headers.cookie, LOCALE_COOKIE));
  if (fromCookie) {
    return fromCookie;
  }
  const header = (req.headers && req.headers['accept-language']) || '';
  const ranked = String(header)
    .split(',')
    .map((part) => {
      const [tag, ...params] = part.trim().split(';');
      const q = params
        .map((p) => p.trim())
        .filter((p) => p.startsWith('q='))
        .map((p) => Number(p.slice(2)))
        .find((n) => Number.isFinite(n));
      return { tag, q: q === undefined ? 1 : q };
    })
    .filter((entry) => entry.tag)
    .sort((a, b) => b.q - a.q);
  for (const entry of ranked) {
    const match = normalize(entry.tag);
    if (match) {
      return match;
    }
  }
  return DEFAULT_LOCALE;
}

/**
 * Look up `key` in `locale`, falling back to English and then to the key
 * itself — a missing translation should degrade to readable English, never to
 * a blank space in the page.
 */
function t(locale, key, params) {
  const table = MESSAGES[locale] || MESSAGES[DEFAULT_LOCALE];
  const raw = table[key] ?? MESSAGES[DEFAULT_LOCALE][key] ?? key;
  if (!params) {
    return raw;
  }
  return raw.replace(/\{(\w+)\}/g, (whole, name) =>
    Object.prototype.hasOwnProperty.call(params, name) ? String(params[name]) : whole,
  );
}

/** Bind a locale once so call sites read `tt('key')`. */
function translator(locale) {
  return (key, params) => t(locale, key, params);
}

module.exports = {
  SUPPORTED,
  DEFAULT_LOCALE,
  LOCALE_COOKIE,
  MESSAGES,
  normalize,
  resolveLocale,
  t,
  translator,
};
