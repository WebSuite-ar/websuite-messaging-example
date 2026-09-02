#!/usr/bin/env node
/**
 * WebSuite webhook receiver — a throwaway endpoint for watching event deliveries.
 *
 * Opens an ngrok tunnel, prints the public URL to paste into a subscription, and
 * logs every delivery it receives: headers, signature verdict, and payload.
 *
 * The status page also SENDS: a signed `POST /rooms/messages` (no api key, no
 * token) with the full byte-level trace, so one page closes the loop — send a
 * message, watch the `message.sent` delivery it causes arrive below it. The CLI
 * equivalent is `send.js`; both share sign.js / diagnose.js.
 *
 * Run `node index.js`. See README.md.
 */
'use strict';

const crypto = require('crypto');
const path = require('path');
const express = require('express');

const { diagnose } = require('./diagnose');
const {
  signRequest,
  signedHeaders,
  looksLikeSecret,
  // The window the platform enforces on OUTBOUND signatures. Distinct from
  // `TOLERANCE_SECONDS` below, which is this receiver's own leniency for
  // inbound deliveries and is configurable.
  TOLERANCE_SECONDS: SEND_TOLERANCE,
} = require('./sign');
const { bold, dim, red, green, yellow, cyan, magenta, line } = require('./tty');

// Load `.env` from THIS directory (not the cwd) before anything reads
// process.env. Built into Node ≥20.12, so no dotenv dependency. Absent file,
// unreadable file, or an older Node all fall through to exported vars.
let envFileLoaded = false;
try {
  process.loadEnvFile(path.join(__dirname, '.env'));
  envFileLoaded = true;
} catch {
  envFileLoaded = false;
}

// ---------------------------------------------------------------- config
const PORT = Number(process.env.PORT || 2000);
const PATH = process.env.WEBHOOK_PATH || '/webhook';
const SECRET = process.env.WEBSUITE_WEBHOOK_SECRET || '';
const TOLERANCE_SECONDS = Number(process.env.TOLERANCE_SECONDS || 300);
const NGROK_AUTHTOKEN = process.env.NGROK_AUTHTOKEN || '';
const NGROK_DOMAIN = process.env.NGROK_DOMAIN || '';
const NO_TUNNEL = process.env.NO_TUNNEL === '1';
// Default is to ack everything with 200 so you always see the payload, even when
// verification fails — this is an inspection tool first. Flip this on to behave
// like a real receiver (401 on a bad signature) and watch the retry schedule fire.
const REJECT_INVALID = process.env.REJECT_INVALID === '1';
// The platform always mints `pwhsec_` + 32 random bytes as hex. Anything else is
// almost certainly the `.env.example` placeholder copied across unedited — which
// otherwise presents as "verification on" and then fails every signature with a
// digest mismatch.
const SECRET_SUSPECT = Boolean(SECRET) && !looksLikeSecret(SECRET);

// ── Sender config (the other direction) ──────────────────────────────────────
// SEPARATE secret from the one above, on purpose. `WEBSUITE_WEBHOOK_SECRET` is a
// SUBSCRIPTION secret and verifies what Pylot sends us; `PYLOT_SIGNING_SECRET`
// is the TEAM SIGNING KEY and authenticates what we send Pylot. Both are
// `pwhsec_…`, neither verifies the other, and conflating them is the classic
// way to spend an afternoon on an unexplained 403.
// The platform, unless `.env` or the UI says otherwise. `/api/v2` is part of it:
// the endpoint is POST /api/v2/rooms/messages, and the code appends the rest.
const DEFAULT_API_URL = 'https://api.websuite.ar/api/v2';
const API_URL = (process.env.PYLOT_API_URL || DEFAULT_API_URL).replace(/\/+$/, '');
const SIGNING_SECRET = process.env.PYLOT_SIGNING_SECRET || '';
const ROOM_ID = process.env.PYLOT_ROOM_ID || '';

/** First 11 chars — `pwhsec_` plus a little — enough to tell two keys apart. */
const keyHint = (secret) => (secret ? String(secret).slice(0, 11) + '\u2026' : null);

/**
 * Which key signs this request: whatever the UI pasted in, else `.env`.
 *
 * A pasted key is used for the one request and then forgotten — not written to
 * `.env`, not kept in module state — so the CLI and the next request still see
 * the environment's key. That keeps `.env` optional without making the browser
 * the source of truth for a credential that can send as the whole team.
 */
function resolveSigningKey(supplied) {
  const fromUi = typeof supplied === 'string' ? supplied.trim() : '';
  if (fromUi) {
    return { secret: fromUi, source: 'ui' };
  }
  return { secret: SIGNING_SECRET, source: SIGNING_SECRET ? 'env' : 'none' };
}

/** Same deal for the target: whatever the UI typed, else `.env`, else the default. */
function resolveApiUrl(supplied) {
  const fromUi = typeof supplied === 'string' ? supplied.trim() : '';
  return (fromUi || API_URL).replace(/\/+$/, '');
}

/** A copy-pasteable curl that reproduces a request byte for byte. */
function asCurl(url, headers, rawBody) {
  const h = Object.entries(headers)
    .map(([k, v]) => `  -H ${JSON.stringify(`${k}: ${v}`)}`)
    .join(' \\\n');
  return `curl -sS -X POST ${JSON.stringify(url)} \\\n${h} \\\n  --data-raw ${JSON.stringify(rawBody)}`;
}

/** Colour an event type by family so the stream is skimmable. */
function paintEvent(type) {
  if (type.startsWith('message.')) {
    if (type.endsWith('.failed')) {
      return red(bold(type));
    }
    if (type.endsWith('.received')) {
      return green(bold(type));
    }
    return cyan(bold(type));
  }
  if (type.startsWith('room.')) {
    return magenta(bold(type));
  }
  return bold(type);
}

// --------------------------------------------------------- verification
/**
 * Verify the delivery signature. Mirrors the platform's scheme exactly:
 * hex(HMAC_SHA256(secret, `${timestamp}.${rawBody}`)), with the `sha256=`
 * prefix optional and a replay window on the timestamp.
 *
 * Returns a verdict object rather than a boolean so the console can explain
 * *why* something failed — that is the whole point of this tool.
 */
function verify(rawBody, headers) {
  const timestamp = headers['x-pylot-timestamp'];
  const header = headers['x-pylot-signature'] || '';

  if (!SECRET) {
    return { status: 'skipped', reason: 'no WEBSUITE_WEBHOOK_SECRET set' };
  }
  if (!timestamp || !header) {
    return { status: 'fail', reason: 'missing signature or timestamp header' };
  }
  if (!rawBody || rawBody.length === 0) {
    return { status: 'fail', reason: 'empty raw body' };
  }

  const ts = Number(timestamp);
  if (!Number.isFinite(ts)) {
    return { status: 'fail', reason: 'malformed timestamp' };
  }
  const skew = Math.floor(Date.now() / 1000) - ts;
  if (Math.abs(skew) > TOLERANCE_SECONDS) {
    return {
      status: 'fail',
      reason: `timestamp outside ±${TOLERANCE_SECONDS}s window (skew ${skew}s)`,
    };
  }

  const providedHex = header.includes('=')
    ? header.slice(header.indexOf('=') + 1).trim()
    : header.trim();
  const expected = crypto.createHmac('sha256', SECRET).update(`${timestamp}.${rawBody}`).digest();

  let provided;
  try {
    provided = Buffer.from(providedHex, 'hex');
  } catch {
    return { status: 'fail', reason: 'signature is not valid hex' };
  }
  if (provided.length !== expected.length) {
    return { status: 'fail', reason: 'signature length mismatch' };
  }
  if (!crypto.timingSafeEqual(provided, expected)) {
    return {
      status: 'fail',
      reason: 'digest mismatch — wrong secret, or the body was altered in transit',
    };
  }
  return { status: 'ok', skew };
}

// -------------------------------------------------------------- tracking
const seenEvents = new Map(); // eventId  -> count (fan-out duplicates)
const seenDeliveries = new Map(); // deliveryId -> count (retries)
let total = 0;
/** Ring buffer of the most recent deliveries, newest first, for the status page. */
const recent = [];
const RECENT_MAX = 25;
/** Set once the tunnel is up, so the page can show the URL to paste. */
let publicUrl = null;

// ----------------------------------------------------------------- app
const app = express();

// The signature covers the EXACT bytes on the wire, so stash them before the
// JSON parser re-serialises anything. Verifying a re-encoded body is the
// classic way to get mystery 401s.
app.use(
  express.json({
    limit: '5mb',
    verify: (req, _res, buf) => {
      req.rawBody = buf.toString('utf8');
    },
  }),
);

// ------------------------------------------------------------ status page
const esc = (s) =>
  String(s).replace(/[&<>"']/g, (ch) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[ch]);

/** Everything the status page needs, also served as JSON for live refresh. */
function snapshot() {
  return {
    total,
    endpoint: publicUrl ? publicUrl + PATH : null,
    localEndpoint: `http://localhost:${PORT}${PATH}`,
    hasSecret: Boolean(SECRET),
    secretSuspect: SECRET_SUSPECT,
    secretHint: SECRET ? SECRET.slice(0, 11) + '…' : null,
    envFileLoaded,
    envDir: __dirname,
    tunnel: publicUrl ? 'up' : NO_TUNNEL ? 'disabled' : NGROK_AUTHTOKEN ? 'failed' : 'no-token',
    rejectInvalid: REJECT_INVALID,
    tolerance: TOLERANCE_SECONDS,
    recent,
    sender: {
      apiUrl: API_URL,
      hasSigningKey: Boolean(SIGNING_SECRET),
      signingKeySuspect: Boolean(SIGNING_SECRET) && !looksLikeSecret(SIGNING_SECRET),
      signingKeyHint: keyHint(SIGNING_SECRET),
      roomId: ROOM_ID,
      sendTolerance: SEND_TOLERANCE,
    },
  };
}

// ---------------------------------------------------------------- sender
/**
 * Sign and forward a message to `POST /rooms/messages`, and hand back the whole
 * trace: the exact bytes signed, the exact bytes sent, the headers, the
 * platform's answer, and — when it refuses — the likely causes.
 *
 * This proxies rather than letting the browser call the platform directly, and
 * that is the point: the signing key must never leave the server. A signature
 * computed in a browser means the key is in the browser, which means anyone
 * with devtools can send as the team.
 */
app.post('/_send', async (req, res) => {
  const { roomId, userConnectionId, transportId, text, body: overrideBody } = req.body || {};

  // The key can come from the panel instead of `.env` — see resolveSigningKey.
  const { secret, source: keySource } = resolveSigningKey(req.body && req.body.signingKey);
  const apiUrl = resolveApiUrl(req.body && req.body.apiUrl);
  if (!secret) {
    res.status(400).json({
      error:
        'No signing key. Paste one into the Signing key field, or set PYLOT_SIGNING_SECRET in .env — get it from GET /rooms/signing-key or `node send.js --provision`.',
    });
    return;
  }

  let payload;
  if (typeof overrideBody === 'string' && overrideBody.trim()) {
    try {
      payload = JSON.parse(overrideBody);
    } catch (err) {
      res.status(400).json({ error: `raw body is not valid JSON: ${err.message}` });
      return;
    }
  } else {
    const message = { type: 'text', text: { value: String(text || '').trim() || 'Hello 👋' } };
    payload = roomId
      ? { roomId: String(roomId), message }
      : {
          userConnectionId: String(userConnectionId || ''),
          ...(transportId ? { transportId: String(transportId) } : {}),
          message,
        };
  }

  if (!payload.roomId && !payload.userConnectionId) {
    res.status(400).json({ error: 'No target — give a roomId, or a userConnectionId (+ transportId).' });
    return;
  }

  // Serialize ONCE. This exact string is hashed and then sent; the scheme rests
  // on those being the same bytes.
  const rawBody = JSON.stringify(payload);
  const { headers, signedContent, timestamp } = signedHeaders(rawBody, secret);
  const url = `${apiUrl}/rooms/messages`;

  let upstream;
  let responseText = '';
  try {
    upstream = await fetch(url, { method: 'POST', headers, body: rawBody });
    responseText = await upstream.text();
  } catch (err) {
    res.status(502).json({
      error: `could not reach ${url} — ${err.message}`,
      request: { url, headers, rawBody, signedContent, curl: asCurl(url, headers, rawBody) },
      keySource,
      keyHint: keyHint(secret),
    });
    return;
  }

  let parsed = null;
  try {
    parsed = JSON.parse(responseText);
  } catch {
    /* non-JSON — returned raw below */
  }

  // Measured against the SERVER's clock, which is the one the ±300s window is
  // enforced against. Local drift is invisible until it isn't.
  const serverDateHeader = upstream.headers.get('date');
  const serverSeconds = serverDateHeader ? Math.floor(new Date(serverDateHeader).getTime() / 1000) : NaN;
  const skew = Number.isFinite(serverSeconds) ? Math.floor(Date.now() / 1000) - serverSeconds : null;
  const requestAge = Number.isFinite(serverSeconds) ? serverSeconds - Number(timestamp) : null;

  const ok = upstream.ok && parsed && parsed.data && parsed.data.queued;
  const notes = ok
    ? []
    : diagnose({
        status: upstream.status,
        secret,
        skew,
        requestAge,
        signedContent,
        rawBody,
        timestamp,
        payload,
      });

  console.log('');
  console.log(line());
  console.log(
    `${dim('→ send')}  ${ok ? green(bold('✔ ' + upstream.status)) : red(bold('✘ ' + upstream.status))}  ${dim(url)}`,
  );
  console.log(`  ${dim('signed  ')}  ${JSON.stringify(signedContent)}`);
  if (!ok) {
    notes.forEach((n) => console.log(`  ${yellow('•')} ${n}`));
  }

  res.status(200).json({
    ok: Boolean(ok),
    status: upstream.status,
    // The secret itself never appears here — only the signature derived from it,
    // and enough of a hint to tell two keys apart.
    request: { url, headers, rawBody, signedContent, curl: asCurl(url, headers, rawBody) },
    keySource,
    keyHint: keyHint(secret),
    response: parsed ?? responseText,
    skew,
    requestAge,
    notes,
  });
});

// ------------------------------------------------------------------ signing
/**
 * Body + signing key → signature, and nothing else. No request is made.
 *
 * The counterpart to `/_send` for when the question is "is my signature right?"
 * rather than "did the message land". It hashes the body EXACTLY as typed —
 * whitespace, key order, unicode escaping and all — and, when the body parses
 * as JSON, also reports the digest of its compact re-serialization, because the
 * two differing is the single most common cause of a 403 nobody can explain.
 */
app.post('/_sign', (req, res) => {
  const { body: input, timestamp: tsInput } = req.body || {};
  const { secret, source: keySource } = resolveSigningKey(req.body && req.body.signingKey);
  const apiUrl = resolveApiUrl(req.body && req.body.apiUrl);

  const rawBody = typeof input === 'string' ? input : '';
  if (!rawBody.trim()) {
    res.status(400).json({ error: 'Nothing to sign — paste the request body you intend to send.' });
    return;
  }
  if (!secret) {
    res.status(400).json({
      error: 'No signing key. Paste one above, or set PYLOT_SIGNING_SECRET in .env.',
    });
    return;
  }

  const now = Math.floor(Date.now() / 1000);
  let seconds = now;
  const tsRaw = tsInput === undefined || tsInput === null ? '' : String(tsInput).trim();
  if (tsRaw) {
    const n = Number(tsRaw);
    if (!Number.isFinite(n)) {
      res.status(400).json({ error: `\`${tsRaw}\` is not unix seconds. Leave it blank for now.` });
      return;
    }
    seconds = Math.floor(n);
  }

  const { headers, signedContent, digest, timestamp } = signedHeaders(rawBody, secret, seconds);
  const url = `${apiUrl}/rooms/messages`;

  // The same body, re-serialized compactly: different bytes, different digest.
  // Showing both side by side is what makes "serialize once" concrete.
  let compact = null;
  let jsonError = null;
  try {
    const reserialized = JSON.stringify(JSON.parse(rawBody));
    compact = {
      rawBody: reserialized,
      digest: signRequest(reserialized, secret, seconds).digest,
      differs: reserialized !== rawBody,
    };
  } catch (err) {
    jsonError = err.message;
  }

  const age = now - seconds;
  const expired = Math.abs(age) > SEND_TOLERANCE;

  const warnings = [];
  if (!looksLikeSecret(secret)) {
    warnings.push(
      'That key does not look real — expected `pwhsec_` + 64 hex chars. The digest below is still arithmetically correct; the platform will simply 403 it.',
    );
  }
  if (jsonError) {
    warnings.push(
      `The body is not valid JSON (${jsonError}). It was signed anyway, byte for byte — but POST /rooms/messages answers 400 before the signature matters.`,
    );
  }
  if (compact && compact.differs) {
    warnings.push(
      'This body is not compact, so any client that re-serializes it (a JSON.parse → JSON.stringify round trip, most HTTP libraries given an object) puts different bytes on the wire than the ones hashed here. Send exactly these bytes, or sign the compact form shown below.',
    );
  }
  if (expired) {
    warnings.push(
      `The timestamp is ${age}s old, outside the ±${SEND_TOLERANCE}s replay window — this signature is already expired and gets a 403 however correct the digest is.`,
    );
  }

  res.status(200).json({
    keySource,
    keyHint: keyHint(secret),
    keyLooksReal: looksLikeSecret(secret),
    url,
    timestamp,
    age,
    expired,
    tolerance: SEND_TOLERANCE,
    digest,
    signature: headers['x-pylot-signature'],
    headers,
    signedContent,
    signedBytes: Buffer.byteLength(signedContent, 'utf8'),
    bodyBytes: Buffer.byteLength(rawBody, 'utf8'),
    compact,
    curl: asCurl(url, headers, rawBody),
    warnings,
  });
});

app.get('/_state', (_req, res) => res.json(snapshot()));

app.get('/', (_req, res) => {
  const s = snapshot();

  // Only the steps that are actually still outstanding — a checklist that stays
  // green once you're set up is noise.
  const todo = [];
  if (!s.endpoint) {
    todo.push(
      s.tunnel === 'no-token'
        ? `Set <code>NGROK_AUTHTOKEN</code> in <code>.env</code> and restart, to get a public URL the platform can reach. <a href="https://dashboard.ngrok.com/get-started/your-authtoken">Get a free token</a>.`
        : s.tunnel === 'disabled'
          ? `Tunnel is off (<code>NO_TUNNEL=1</code>). Point the collection's <em>Simulate a signed delivery</em> at the local URL, or restart without the flag for a public one.`
          : `ngrok failed to start — check the console output, then restart.`,
    );
  }
  if (!s.hasSecret) {
    todo.push(
      `Set <code>WEBSUITE_WEBHOOK_SECRET</code> in <code>.env</code> and restart. It's the <code>pwhsec_…</code> value returned <strong>once</strong> by <em>Create subscription</em>. Until then payloads are shown but not verified.`,
    );
  }
  if (s.secretSuspect) {
    todo.push(
      `<strong class="bad">Your <code>WEBSUITE_WEBHOOK_SECRET</code> doesn't look like a real one.</strong> It should be <code>pwhsec_</code> followed by 64 hex characters — yours looks like the <code>.env.example</code> placeholder. Every signature will fail with a digest mismatch until you paste the value from <em>Create subscription</em> (or <em>Rotate subscription secret</em>).`,
    );
  }
  if (!s.envFileLoaded) {
    todo.push(`No <code>.env</code> found in <code>${esc(s.envDir)}</code> — copy <code>.env.example</code> to <code>.env</code>. Exported shell vars work too. Sending works without it: paste the key into the <em>Send</em> tab.`);
  }
  if (s.endpoint && s.hasSecret && !s.total) {
    todo.push(
      `Ready. Create a subscription pointing at the URL above, then fire <em>Send test event</em> from the Postman collection.`,
    );
  }

  const badge = (d) =>
    d.verdict === 'ok'
      ? '<span class="ok">✔ verified</span>'
      : d.verdict === 'skipped'
        ? '<span class="warn">… unchecked</span>'
        : `<span class="bad">✘ invalid</span>`;

  const rows = s.recent.length
    ? s.recent
        .map(
          (d, i) => `<details class="d"${i === 0 ? ' open' : ''}>
        <summary>
          <span class="mono dim">${esc(d.at.slice(11, 19))}</span>
          <span class="ev ${esc(d.family)}">${esc(d.event)}</span>
          ${badge(d)}${d.retry ? ' <span class="warn">↻ retry</span>' : ''}
          <span class="mono dim right">${d.bytes} B</span>
        </summary>
        <div class="body">
          ${
            d.verdict === 'fail' && d.reason
              ? `<p class="bad why">${esc(d.reason)}</p>`
              : ''
          }
          <table class="hdr">${Object.entries(d.headers)
            .map(
              ([k, v]) =>
                `<tr><td class="mono dim">${esc(k)}</td><td class="mono brk">${esc(v)}</td></tr>`,
            )
            .join('')}</table>
          <pre class="mono">${esc(d.pretty)}${d.truncated ? '\n… truncated' : ''}</pre>
        </div>
      </details>`,
        )
        .join('')
    : `<p class="dim pad">Nothing yet — deliveries appear here and in the console.</p>`;

  // ── the two inputs both send-side panels need ──────────────────────────────
  // Repeated rather than hoisted into a global bar, so each panel stands alone
  // and can be read as a complete example. The values are kept in the tab's
  // sessionStorage and mirrored between panels by the script below.
  const keyField = (id) => `<label class="f"><span>signing key ${
    s.sender.hasSigningKey
      ? `<span class="dim">— blank uses <code>PYLOT_SIGNING_SECRET</code> from <code>.env</code> (<code>${esc(s.sender.signingKeyHint)}</code>)</span>`
      : `<span class="warn">— required: there is none in <code>.env</code></span>`
  }</span>
      <span class="row tight">
        <input class="k mono" id="${id}" type="password" autocomplete="off" spellcheck="false" placeholder="pwhsec_…">
        <button type="button" class="ghost reveal" data-for="${id}">show</button>
        <button type="button" class="ghost forget">forget</button>
      </span></label>`;

  const urlField = (id) => `<label class="f"><span>API base <span class="dim">— <code>/rooms/messages</code> is appended</span></span>
      <input class="u mono" id="${id}" spellcheck="false" placeholder="${esc(s.sender.apiUrl)}"></label>`;

  // Pretty-printed on purpose: it makes the Signature panel's "these bytes vs.
  // the compact ones" comparison show a real difference on first load.
  const exampleBody = JSON.stringify(
    {
      roomId: s.sender.roomId || '664f0f1e2c9a4b0012ab34cd',
      message: { type: 'text', text: { value: 'Hello 👋' } },
    },
    null,
    2,
  );

  res.type('html').send(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Pylot messaging playground</title>
<style>
  :root {
    --bg:#fbfaf7; --fg:#1c1b19; --dim:#6b6862; --card:#fff; --line:#e6e2da;
    --ok:#1a7f4b; --warn:#9a6700; --bad:#b3261e; --accent:#2f5bd8;
  }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#16151a; --fg:#e9e7e2; --dim:#9a958c; --card:#1e1d23; --line:#2e2c34;
            --ok:#4ade80; --warn:#fbbf24; --bad:#f87171; --accent:#8ab4ff; }
  }
  * { box-sizing:border-box; }
  [hidden] { display:none !important; }
  body { margin:0; padding:2rem 1.25rem; background:var(--bg); color:var(--fg);
         font:15px/1.55 ui-sans-serif,-apple-system,Segoe UI,Roboto,sans-serif; }
  main { max-width:820px; margin:0 auto; }
  h1 { font-size:1.35rem; margin:0 0 .25rem; }
  h2 { font-size:.8rem; text-transform:uppercase; letter-spacing:.08em;
       color:var(--dim); margin:2rem 0 .6rem; font-weight:600; }
  h2:first-child { margin-top:0; }
  .sub { color:var(--dim); margin:0 0 1.5rem; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:1rem 1.1rem; }
  .url { display:flex; gap:.6rem; align-items:center; flex-wrap:wrap; }
  .url code { font-size:1rem; word-break:break-all; }
  button { font:inherit; padding:.35rem .7rem; border:1px solid var(--line);
           border-radius:6px; background:transparent; color:var(--fg); cursor:pointer; }
  button:hover { border-color:var(--accent); color:var(--accent); }
  button.ghost { color:var(--dim); font-size:.82rem; padding:.3rem .55rem; }
  nav.tabs { display:flex; gap:.4rem; flex-wrap:wrap; margin:1.7rem 0 .9rem; }
  nav.tabs button { border-radius:999px; padding:.4rem .95rem; font-size:.9rem; }
  nav.tabs button.on { border-color:var(--accent); color:var(--accent);
                       background:var(--card); font-weight:600; }
  .pill { display:inline-block; margin-left:.45rem; padding:0 .4rem; border-radius:999px;
          background:var(--accent); color:var(--card); font-size:.72rem; font-weight:700; }
  .mono, code { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }
  .dim { color:var(--dim); }
  .small { font-size:.85rem; }
  .ok { color:var(--ok); } .warn { color:var(--warn); } .bad { color:var(--bad); }
  ol { padding-left:1.2rem; margin:0; } ol li { margin:.45rem 0; }
  table { width:100%; border-collapse:collapse; }
  td { padding:.45rem .5rem; border-top:1px solid var(--line); font-size:.9rem; }
  tr:first-child td { border-top:0; }
  .pad { padding:1rem .5rem; }
  .ev { font-family:ui-monospace,monospace; font-size:.85rem; }
  details.d { border-top:1px solid var(--line); }
  details.d:first-child { border-top:0; }
  details.d summary { display:flex; gap:.7rem; align-items:center; flex-wrap:wrap;
                      padding:.55rem .3rem; cursor:pointer; font-size:.9rem; }
  details.d summary::-webkit-details-marker { display:none; }
  details.d summary:hover { color:var(--accent); }
  details.d .right { margin-left:auto; }
  details.d .body { padding:.2rem .3rem .9rem; }
  details.d .why { margin:.2rem 0 .7rem; font-size:.85rem; }
  table.hdr { margin-bottom:.6rem; }
  table.hdr td { border:0; padding:.12rem .5rem .12rem 0; font-size:.8rem; vertical-align:top; }
  .brk { word-break:break-all; }
  pre { background:var(--bg); border:1px solid var(--line); border-radius:6px;
        padding:.7rem .8rem; overflow-x:auto; font-size:.8rem; margin:0; }
  pre.wrap { white-space:pre-wrap; word-break:break-all; }
  .ev.message { color:var(--accent); } .ev.room { color:var(--warn); } .ev.failed { color:var(--bad); }
  input, textarea { font:inherit; width:100%; padding:.45rem .55rem; border:1px solid var(--line);
                    border-radius:6px; background:var(--bg); color:var(--fg); }
  textarea { min-height:3.2rem; resize:vertical; }
  label.f { display:block; margin:0 0 .7rem; }
  label.f > span { display:block; font-size:.78rem; color:var(--dim); margin:0 0 .25rem; }
  .row { display:flex; gap:.5rem; align-items:center; flex-wrap:wrap; margin-top:.2rem; }
  .row.tight { margin-top:0; }
  .row.tight input { flex:1 1 14rem; min-width:0; }
  .send-out { margin:.9rem 0 0; }
  .send-out .verdict { font-weight:600; margin:0 0 .5rem; }
  .send-out ul { margin:.5rem 0 0; padding-left:1.1rem; font-size:.85rem; color:var(--dim); }
  .send-out li { margin:.3rem 0; }
  .cap { font-size:.78rem; color:var(--dim); margin:.6rem 0 .2rem; }
  .stats { display:flex; gap:1.5rem; flex-wrap:wrap; margin:0; }
  .stat b { display:block; font-size:1.5rem; font-weight:600; }
  .stat span { color:var(--dim); font-size:.8rem; }
  a { color:var(--accent); }
</style></head><body><main>

  <h1>Pylot messaging playground</h1>
  <p class="sub">Send a signed message, watch the deliveries it causes arrive.</p>

  <div class="card url">
    ${
      s.endpoint
        ? `<code id="u">${esc(s.endpoint)}</code><button onclick="navigator.clipboard.writeText(document.getElementById('u').textContent)">Copy</button><span class="dim">← paste into <em>Create subscription</em></span>`
        : `<code id="u">${esc(s.localEndpoint)}</code><button onclick="navigator.clipboard.writeText(document.getElementById('u').textContent)">Copy</button><span class="warn">local only — not reachable from the platform</span>`
    }
  </div>

  ${
    todo.length
      ? `<h2>Next steps</h2><div class="card"><ol>${todo.map((t) => `<li>${t}</li>`).join('')}</ol></div>`
      : ''
  }

  <nav class="tabs" id="tabs">
    <button type="button" data-tab="send">Send a message</button>
    <button type="button" data-tab="sign">Signature</button>
    <button type="button" data-tab="deliveries">Deliveries<span class="pill" id="t-pill" hidden></span></button>
    <button type="button" data-tab="setup">Setup</button>
  </nav>

  <section class="tab" id="tab-send" hidden>
    <div class="card">
      ${
        s.sender.signingKeySuspect
          ? `<p class="bad" style="margin:0 0 .8rem"><strong>The <code>PYLOT_SIGNING_SECRET</code> in <code>.env</code> doesn't look like a real key</strong> — expected <code>pwhsec_</code> + 64 hex. Paste a real one below; it wins over <code>.env</code>.</p>`
          : ''
      }
      <p class="dim small" style="margin:0 0 .9rem">
        Signed with the team key — no api key, no token. The key is used to sign this
        one request and then forgotten: nothing is written to <code>.env</code>, and it
        goes no further than this process. The browser only ever sees the signature.
      </p>
      ${keyField('s-key')}
      ${urlField('s-url')}
      <label class="f"><span>roomId</span><input id="f-room" value="${esc(s.sender.roomId)}" placeholder="664f0f1e2c9a4b0012ab34cd"></label>
      <label class="f"><span>message</span><textarea id="f-text">Hello from the receiver 👋</textarea></label>
      <details style="margin:0 0 .8rem">
        <summary class="dim" style="cursor:pointer;font-size:.85rem">Raw body (overrides the fields above)</summary>
        <textarea id="f-body" style="margin-top:.5rem" class="mono" placeholder='{"roomId":"…","message":{"type":"text","text":{"value":"hi"}}}'></textarea>
      </details>
      <div class="row">
        <button id="f-send">Send signed</button>
        <span class="dim small">the resulting <code>message.sent</code> delivery lands under <em>Deliveries</em></span>
      </div>
      <div class="send-out" id="f-out"></div>
    </div>
  </section>

  <section class="tab" id="tab-sign" hidden>
    <div class="card">
      <p style="margin:0 0 .7rem">Body + signing key → signature. <strong>Nothing is sent.</strong> Use this
        to check a signature your own code produced, or to get a <code>curl</code> that reproduces the request byte for byte.</p>
      <pre class="mono dim wrap" style="margin:0 0 1rem">x-pylot-timestamp: &lt;unix seconds&gt;
x-pylot-signature: sha256=hex(HMAC_SHA256(key, timestamp + "." + body))</pre>
      ${keyField('g-key')}
      ${urlField('g-url')}
      <label class="f"><span>body <span class="dim">— hashed exactly as typed, whitespace and key order included</span></span><textarea id="g-body" class="mono" style="min-height:7rem">${esc(exampleBody)}</textarea></label>
      <label class="f"><span>timestamp <span class="dim">— unix seconds; blank means now. Back-date it past ±${s.sender.sendTolerance}s to see the replay window bite.</span></span>
        <span class="row tight">
          <input id="g-ts" class="mono" spellcheck="false" placeholder="now">
          <button type="button" class="ghost" id="g-stale">−10 min</button>
        </span></label>
      <div class="row">
        <button id="g-go">Compute signature</button>
        <span class="dim small">no request is made — this only does the arithmetic</span>
      </div>
      <div class="send-out" id="g-out"></div>
    </div>
  </section>

  <section class="tab" id="tab-deliveries" hidden>
    <div class="card">
      <p class="stats">
        <span class="stat"><b>${s.total}</b><span>received</span></span>
        <span class="stat"><b class="${s.secretSuspect ? 'bad' : s.hasSecret ? 'ok' : 'warn'}">${
          s.secretSuspect ? 'bad key' : s.hasSecret ? 'on' : 'off'
        }</b><span>verification</span></span>
        <span class="stat"><b>±${s.tolerance}s</b><span>tolerance</span></span>
        <span class="stat"><b class="${s.rejectInvalid ? 'bad' : ''}">${s.rejectInvalid ? '401' : '200'}</b><span>reply on bad sig</span></span>
      </p>
    </div>
    <h2>Recent deliveries</h2>
    <div class="card" style="padding:.15rem .6rem">${rows}</div>
  </section>

  <section class="tab" id="tab-setup" hidden>
    <div class="card">
      <p class="small" style="margin:0 0 .8rem">
        config: ${s.envFileLoaded ? `<code>.env</code> loaded` : `no <code>.env</code>`} from <code>${esc(s.envDir)}</code>
        ${s.secretHint ? ` · subscription secret <code>${esc(s.secretHint)}</code>` : ''}
        ${s.sender.signingKeyHint ? ` · signing key <code>${esc(s.sender.signingKeyHint)}</code>` : ' · no signing key in <code>.env</code>'}
        · sending to <code>${esc(s.sender.apiUrl)}</code>
      </p>
      <p style="margin:0 0 .6rem">Edit <code>.env</code> in <code>${esc(s.envDir)}</code>, then restart:</p>
      <pre class="mono dim wrap" style="margin:0">WEBSUITE_WEBHOOK_SECRET=pwhsec_…   # from Create subscription, shown once
NGROK_AUTHTOKEN=…                  # free, for a public URL
NGROK_DOMAIN=…                     # optional: stable URL across restarts
PYLOT_API_URL=${esc(DEFAULT_API_URL)}
PYLOT_SIGNING_SECRET=pwhsec_…      # optional here — the Send tab takes one too
PORT=${PORT}
REJECT_INVALID=1                   # reply 401 on a bad signature, to see retries</pre>
      <p class="dim small" style="margin:.9rem 0 0">
        Only <code>WEBSUITE_WEBHOOK_SECRET</code> needs a restart to take effect —
        it verifies inbound deliveries. The signing key and the API base can be typed
        into the send-side tabs instead, which is the faster loop when you are testing
        against more than one team or environment.
      </p>
    </div>
  </section>

<script>
  const esc = (v) => String(v).replace(/[&<>]/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));

  // ── tabs ───────────────────────────────────────────────────────────────────
  // One panel at a time, remembered per tab so the reload below doesn't dump you
  // back on the first one.
  const tabButtons = Array.from(document.querySelectorAll('#tabs button'));
  const pill = document.getElementById('t-pill');
  let active = null;
  let unseen = 0;

  function show(name) {
    active = name;
    tabButtons.forEach((b) => b.classList.toggle('on', b.dataset.tab === name));
    document.querySelectorAll('section.tab').forEach((sec) => {
      sec.hidden = sec.id !== 'tab-' + name;
    });
    try { sessionStorage.setItem('pylot.tab', name); } catch {}
    // The delivery list is server-rendered, so seeing the new ones means a reload.
    if (name === 'deliveries' && unseen > 0) { location.reload(); }
  }
  tabButtons.forEach((b) => b.addEventListener('click', () => show(b.dataset.tab)));
  let stored = null;
  try { stored = sessionStorage.getItem('pylot.tab'); } catch {}
  show(document.getElementById('tab-' + stored) ? stored : 'send');

  // ── the key and the target ─────────────────────────────────────────────────
  // Both panels share one value: type it once. It lives in this tab's
  // sessionStorage — survives a refresh, dies with the tab, never touches disk —
  // and is posted to THIS process, which signs. It is never sent to the platform.
  function bind(selector, store, initial) {
    const inputs = Array.from(document.querySelectorAll(selector));
    let saved = null;
    try { saved = sessionStorage.getItem(store); } catch {}
    const value = saved === null ? initial : saved;
    inputs.forEach((input) => {
      input.value = value;
      input.addEventListener('input', () => {
        try { sessionStorage.setItem(store, input.value); } catch {}
        inputs.forEach((other) => { if (other !== input) { other.value = input.value; } });
      });
    });
    return () => (inputs.length ? inputs[0].value.trim() : '');
  }
  const readKey = bind('input.k', 'pylot.signingKey', '');
  const readUrl = bind('input.u', 'pylot.apiUrl', '');

  document.querySelectorAll('button.reveal').forEach((b) => {
    b.addEventListener('click', () => {
      const input = document.getElementById(b.dataset.for);
      const masked = input.type === 'password';
      input.type = masked ? 'text' : 'password';
      b.textContent = masked ? 'hide' : 'show';
    });
  });
  document.querySelectorAll('button.forget').forEach((b) => {
    b.addEventListener('click', () => {
      try { sessionStorage.removeItem('pylot.signingKey'); } catch {}
      document.querySelectorAll('input.k').forEach((i) => { i.value = ''; i.type = 'password'; });
      document.querySelectorAll('button.reveal').forEach((r) => { r.textContent = 'show'; });
    });
  });

  // ── shared renderers ──────────────────────────────────────────────────────
  const rowsOf = (pairs) =>
    '<table class="hdr">' +
    pairs.filter(([, v]) => v !== null && v !== undefined && v !== '')
      .map(([k, v]) => '<tr><td class="mono dim">' + esc(k) + '</td><td class="mono brk">' + esc(v) + '</td></tr>')
      .join('') +
    '</table>';
  const notesOf = (notes) =>
    notes && notes.length
      ? '<ul>' + notes.map((n) => '<li>' + esc(n) + '</li>').join('') + '</ul>'
      : '';
  const block = (caption, text) =>
    '<p class="cap">' + esc(caption) + '</p><pre class="mono wrap">' + esc(text) + '</pre>';
  const keyLine = (r) =>
    '<p class="cap" style="margin-top:.7rem">signed with ' + esc(r.keyHint || '?') +
    (r.keySource === 'ui' ? ' (typed above)' : ' (PYLOT_SIGNING_SECRET)') + '</p>';

  async function post(url, payload, out, pending) {
    out.innerHTML = '<p class="dim">' + pending + '</p>';
    try {
      const r = await (await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })).json();
      if (r.error) {
        out.innerHTML = '<p class="bad">' + esc(r.error) + '</p>' + notesOf(r.notes);
        return null;
      }
      return r;
    } catch (e) {
      out.innerHTML = '<p class="bad">' + esc(e.message) + '</p>';
      return null;
    }
  }

  // ── send ──────────────────────────────────────────────────────────────────
  // Everything the send returned, laid out so a 403 is diagnosable without
  // leaving the page: what was signed, what was sent, and why it likely failed.
  const sendOut = document.getElementById('f-out');
  const sendBtn = document.getElementById('f-send');

  sendBtn.addEventListener('click', async () => {
    sendBtn.disabled = true;
    const r = await post('/_send', {
      signingKey: readKey(),
      apiUrl: readUrl(),
      roomId: document.getElementById('f-room').value.trim(),
      text: document.getElementById('f-text').value,
      body: document.getElementById('f-body').value,
    }, sendOut, 'Signing and sending…');
    sendBtn.disabled = false;
    if (!r) { return; }

    const d = (r.response && r.response.data) || {};
    const head = r.ok
      ? '<p class="verdict ok">✔ ' + r.status + ' queued — room ' + esc(d.roomId || '?') +
        ', message ' + esc(d.messageId || '?') + '</p>' +
        '<p class="dim small" style="margin:0">Accepted by the room pipeline — not yet delivered to the customer.</p>'
      : '<p class="verdict bad">✘ ' + r.status + ' ' + esc((r.response && r.response.msg) || '') + '</p>' +
        (r.status === 403
          ? '<p class="dim small" style="margin:0">The platform will not say which half of the signature was wrong. Likely causes:</p>'
          : '');

    const trace =
      '<details style="margin-top:.8rem"><summary class="dim" style="cursor:pointer;font-size:.85rem">Signature trace</summary>' +
      '<div style="margin-top:.5rem">' +
      rowsOf(Object.entries(r.request.headers).concat([
        ['url', r.request.url],
        ['clock skew', r.skew === null ? '' : r.skew + 's'],
        ['age at server', r.requestAge === null ? '' : r.requestAge + 's'],
      ])) +
      block('signed bytes — HMAC-SHA256 over exactly this', JSON.stringify(r.request.signedContent)) +
      block('body sent', r.request.rawBody) +
      block('curl repro', r.request.curl) +
      block('response', JSON.stringify(r.response, null, 2)) +
      '</div></details>';

    sendOut.innerHTML = head + notesOf(r.notes) + keyLine(r) + trace;
  });

  // ── signature ─────────────────────────────────────────────────────────────
  const signOut = document.getElementById('g-out');
  const signBtn = document.getElementById('g-go');
  const signTs = document.getElementById('g-ts');

  document.getElementById('g-stale').addEventListener('click', () => {
    signTs.value = String(Math.floor(Date.now() / 1000) - 600);
  });

  signBtn.addEventListener('click', async () => {
    signBtn.disabled = true;
    const r = await post('/_sign', {
      signingKey: readKey(),
      apiUrl: readUrl(),
      body: document.getElementById('g-body').value,
      timestamp: signTs.value,
    }, signOut, 'Hashing…');
    signBtn.disabled = false;
    if (!r) { return; }

    const head =
      '<p class="verdict ' + (r.warnings.length ? 'warn' : 'ok') + '">' +
      (r.warnings.length ? '⚠ signature computed, with caveats' : '✔ signature computed') +
      '</p>';

    const summary = rowsOf([
      ['x-pylot-timestamp', r.timestamp],
      ['x-pylot-signature', r.signature],
      ['age', r.age + 's' + (r.expired ? ' — expired (±' + r.tolerance + 's)' : ' — inside the ±' + r.tolerance + 's window')],
      ['body', r.bodyBytes + ' bytes'],
      ['signed', r.signedBytes + ' bytes'],
      ['target', r.url],
    ]);

    const compare = r.compact
      ? (r.compact.differs
          ? block(
              'the same body, compact — different bytes, so a different digest (' +
                r.compact.digest.slice(0, 16) + '… vs ' + r.digest.slice(0, 16) + '…)',
              r.compact.rawBody)
          : '<p class="cap">already compact — re-serializing it changes nothing, so any client sends the bytes this digest covers.</p>')
      : '';

    signOut.innerHTML =
      head + notesOf(r.warnings) + keyLine(r) +
      '<div style="margin-top:.7rem">' + summary +
      block('signed bytes — HMAC-SHA256 over exactly this', JSON.stringify(r.signedContent)) +
      compare +
      block('curl repro — sends the bytes that were hashed', r.curl) +
      '</div>';
  });

  // ── live deliveries ───────────────────────────────────────────────────────
  // Poll rather than reload: a reload here would wipe a half-typed message or a
  // key you just pasted. New deliveries show up as a count on the tab instead,
  // and the reload happens when you actually go look at them.
  const seenTotal = ${s.total};
  setInterval(async () => {
    try {
      const state = await (await fetch('/_state')).json();
      if (state.total === seenTotal) { return; }
      if (active === 'deliveries') { location.reload(); return; }
      unseen = state.total - seenTotal;
      pill.textContent = unseen;
      pill.hidden = false;
    } catch {}
  }, 2000);
</script>
</main></body></html>`);
});

app.post(PATH, (req, res) => {
  total += 1;

  const h = req.headers;
  const eventHeader = h['x-pylot-event'] || '(none)';
  const deliveryId = h['x-pylot-delivery-id'] || '(none)';
  const body = req.body && typeof req.body === 'object' ? req.body : {};
  const eventId = body.eventId || '(none)';

  const verdict = verify(req.rawBody, h);

  const deliveryCount = (seenDeliveries.get(deliveryId) || 0) + 1;
  seenDeliveries.set(deliveryId, deliveryCount);
  const eventCount = (seenEvents.get(eventId) || 0) + 1;
  seenEvents.set(eventId, eventCount);

  // ------------------------------------------------------------- render
  const stamp = new Date().toISOString();

  // Feed the status page (newest first, bounded). Keep the request as it
  // arrived — headers plus the exact raw body — so the page can show what an
  // HTTP inspector would. The embedded ngrok agent has no web inspector (its
  // `inspect` option is documented "unused, will warn and be ignored"), so this
  // is the only place to see a delivery after the fact.
  const shownHeaders = {};
  for (const [k, v] of Object.entries(h)) {
    if (k.startsWith('x-pylot-') || ['content-type', 'content-length', 'user-agent'].includes(k)) {
      shownHeaders[k] = String(v);
    }
  }
  const rawStr = typeof req.rawBody === 'string' ? req.rawBody : '';
  const RAW_MAX = 20000;
  const ev = String(eventHeader);
  recent.unshift({
    at: stamp,
    event: ev,
    family: ev.endsWith('.failed') ? 'failed' : ev.startsWith('room.') ? 'room' : 'message',
    verdict: verdict.status,
    reason: verdict.reason || null,
    deliveryId: String(deliveryId),
    eventId: String(eventId),
    retry: deliveryCount > 1,
    headers: shownHeaders,
    bytes: Buffer.byteLength(rawStr, 'utf8'),
    // Pretty-printed for reading; `raw` is what was actually signed.
    pretty: (() => {
      try {
        return JSON.stringify(JSON.parse(rawStr), null, 2);
      } catch {
        return rawStr;
      }
    })().slice(0, RAW_MAX),
    truncated: rawStr.length > RAW_MAX,
  });
  if (recent.length > RECENT_MAX) {
    recent.length = RECENT_MAX;
  }
  console.log('');
  console.log(line());
  console.log(`${dim(`#${total}`)}  ${paintEvent(String(eventHeader))}   ${dim(stamp)}`);

  if (verdict.status === 'ok') {
    console.log(`  ${green('✔ signature verified')} ${dim(`(clock skew ${verdict.skew}s)`)}`);
  } else if (verdict.status === 'skipped') {
    console.log(`  ${yellow('… signature NOT checked')} ${dim(`— ${verdict.reason}`)}`);
  } else {
    console.log(`  ${red('✘ signature INVALID')} ${dim(`— ${verdict.reason}`)}`);
  }

  console.log(`  ${dim('delivery')}  ${deliveryId}`);
  console.log(`  ${dim('event   ')}  ${eventId}`);

  if (deliveryCount > 1) {
    console.log(
      `  ${yellow(`↻ RETRY — this delivery id has now arrived ${deliveryCount}×`)} ${dim('(did you ack with 2xx?)')}`,
    );
  }
  if (eventCount > 1 && deliveryCount === 1) {
    console.log(
      `  ${yellow(`⧉ same event, different delivery — fan-out to another subscription (${eventCount}×)`)}`,
    );
  }

  if (body.type || body.occurredAt || body.teamId) {
    const bits = [];
    if (body.type && body.type !== eventHeader) {
      bits.push(`type=${body.type} ${red('(≠ header!)')}`);
    }
    if (body.occurredAt) {
      bits.push(`occurredAt=${body.occurredAt}`);
    }
    if (body.teamId) {
      bits.push(`teamId=${body.teamId}`);
    }
    if (bits.length) {
      console.log(`  ${dim(bits.join('  '))}`);
    }
  }

  const data = body.data !== undefined ? body.data : body;
  console.log(dim('  ── payload ' + '─'.repeat(20)));
  console.log(
    JSON.stringify(data, null, 2)
      .split('\n')
      .map((l) => '  ' + l)
      .join('\n'),
  );

  if (REJECT_INVALID && verdict.status === 'fail') {
    console.log(
      `  ${red('→ replying 401')} ${dim('(REJECT_INVALID=1 — expect this delivery to be retried)')}`,
    );
    res.status(401).json({ error: 'invalid signature' });
    return;
  }

  // Ack fast. Anything non-2xx is treated as a failed delivery and retried.
  res.status(200).json({ received: true });
});

// ---------------------------------------------------------------- boot
async function openTunnel() {
  if (NO_TUNNEL) {
    return null;
  }
  let ngrok;
  try {
    ngrok = require('@ngrok/ngrok');
  } catch {
    console.log(yellow('  @ngrok/ngrok is not installed — run `npm install` first.'));
    return null;
  }
  if (!NGROK_AUTHTOKEN) {
    console.log(yellow('  NGROK_AUTHTOKEN is not set — starting without a tunnel.'));
    console.log(
      dim('  Get a free token at https://dashboard.ngrok.com/get-started/your-authtoken'),
    );
    return null;
  }
  try {
    const listener = await ngrok.forward({
      addr: PORT,
      authtoken: NGROK_AUTHTOKEN,
      ...(NGROK_DOMAIN ? { domain: NGROK_DOMAIN } : {}),
    });
    return listener.url();
  } catch (err) {
    console.log(red(`  ngrok failed to start: ${err && err.message ? err.message : err}`));
    return null;
  }
}

async function main() {
  await new Promise((resolve) => app.listen(PORT, resolve));

  console.log('');
  console.log(bold('  Pylot messaging playground'));
  console.log(line('═'));
  console.log(`  ${dim('local   ')}  http://localhost:${PORT}${PATH}`);

  // Assigns the module-level `publicUrl` (no `const`) so the status page can
  // show the URL to paste.
  publicUrl = await openTunnel();
  if (publicUrl) {
    console.log(`  ${dim('public  ')}  ${bold(green(publicUrl + PATH))}`);
    console.log('');
    console.log(
      `  ${dim('Paste that into')} ${bold('Create subscription')} ${dim('as the `url`.')}`,
    );
  } else {
    console.log('');
    console.log(
      `  ${yellow('No public tunnel.')} ${dim('Local-only — the platform cannot reach this yet.')}`,
    );
  }

  console.log('');
  if (SECRET && SECRET_SUSPECT) {
    console.log(
      `  ${red('secret  ')}  ${SECRET.slice(0, 11)}… ${red('— not a valid secret')} ${dim('(expected pwhsec_ + 64 hex; looks like the .env.example placeholder)')}`,
    );
  } else if (SECRET) {
    console.log(
      `  ${dim('secret  ')}  ${SECRET.slice(0, 11)}${dim('…')} ${dim(`(±${TOLERANCE_SECONDS}s tolerance)`)}`,
    );
  } else {
    console.log(
      `  ${yellow('No WEBSUITE_WEBHOOK_SECRET set')} ${dim('— payloads will be shown but NOT verified.')}`,
    );
  }
  // Say where config came from — "I set it and nothing happened" is otherwise
  // indistinguishable from "the file was never read".
  console.log(
    `  ${dim('config  ')}  ${
      envFileLoaded ? dim(`.env loaded from ${__dirname}`) : yellow(`no .env found in ${__dirname} — using exported vars only`)
    }`,
  );
  if (SIGNING_SECRET && !looksLikeSecret(SIGNING_SECRET)) {
    console.log(
      `  ${red('sending ')}  ${SIGNING_SECRET.slice(0, 11)}… ${red('— not a valid signing key')} ${dim('(expected pwhsec_ + 64 hex)')}`,
    );
  } else if (SIGNING_SECRET) {
    console.log(`  ${dim('sending ')}  ${dim(`${keyHint(SIGNING_SECRET)} → ${API_URL}/rooms/messages`)}`);
  } else {
    console.log(
      `  ${yellow('No PYLOT_SIGNING_SECRET set')} ${dim(`— the CLI needs one (\`node send.js --provision\`); the web panel takes one pasted in. → ${API_URL}/rooms/messages`)}`,
    );
  }
  console.log(
    `  ${dim('setup   ')}  ${bold(`http://localhost:${PORT}/`)} ${dim('— status, setup, and the send panel')}`,
  );
  console.log(line('═'));
  console.log(dim('  Waiting for deliveries…  (ctrl-c to stop)'));
}

main().catch((err) => {
  console.error(red(`fatal: ${err && err.stack ? err.stack : err}`));
  process.exit(1);
});
