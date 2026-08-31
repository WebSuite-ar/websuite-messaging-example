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
const { signedHeaders, looksLikeSecret } = require('./sign');
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
const API_URL = (process.env.PYLOT_API_URL || 'http://localhost:4000/api/v2').replace(/\/+$/, '');
const SIGNING_SECRET = process.env.PYLOT_SIGNING_SECRET || '';
const ROOM_ID = process.env.PYLOT_ROOM_ID || '';

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
      signingKeyHint: SIGNING_SECRET ? SIGNING_SECRET.slice(0, 11) + '…' : null,
      roomId: ROOM_ID,
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
  const { headers, signedContent, timestamp } = signedHeaders(rawBody, SIGNING_SECRET);
  const url = `${API_URL}/rooms/messages`;

  let upstream;
  let responseText = '';
  try {
    upstream = await fetch(url, { method: 'POST', headers, body: rawBody });
    responseText = await upstream.text();
  } catch (err) {
    res.status(502).json({
      error: `could not reach ${url} — ${err.message}`,
      request: { url, headers, rawBody, signedContent },
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
        secret: SIGNING_SECRET,
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
    // The secret itself never appears here — only the signature derived from it.
    request: { url, headers, rawBody, signedContent },
    response: parsed ?? responseText,
    skew,
    requestAge,
    notes,
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
    todo.push(`No <code>.env</code> found in <code>${esc(s.envDir)}</code> — copy <code>.env.example</code> to <code>.env</code>. Exported shell vars work too.`);
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
  body { margin:0; padding:2rem 1.25rem; background:var(--bg); color:var(--fg);
         font:15px/1.55 ui-sans-serif,-apple-system,Segoe UI,Roboto,sans-serif; }
  main { max-width:820px; margin:0 auto; }
  h1 { font-size:1.35rem; margin:0 0 .25rem; }
  h2 { font-size:.8rem; text-transform:uppercase; letter-spacing:.08em;
       color:var(--dim); margin:2rem 0 .6rem; font-weight:600; }
  .sub { color:var(--dim); margin:0 0 1.5rem; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:1rem 1.1rem; }
  .url { display:flex; gap:.6rem; align-items:center; flex-wrap:wrap; }
  .url code { font-size:1rem; word-break:break-all; }
  button { font:inherit; padding:.35rem .7rem; border:1px solid var(--line);
           border-radius:6px; background:transparent; color:var(--fg); cursor:pointer; }
  button:hover { border-color:var(--accent); color:var(--accent); }
  .mono, code { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }
  .dim { color:var(--dim); }
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
  .ev.message { color:var(--accent); } .ev.room { color:var(--warn); } .ev.failed { color:var(--bad); }
  input, textarea { font:inherit; width:100%; padding:.45rem .55rem; border:1px solid var(--line);
                    border-radius:6px; background:var(--bg); color:var(--fg); }
  textarea { min-height:3.2rem; resize:vertical; }
  label.f { display:block; margin:0 0 .7rem; }
  label.f span { display:block; font-size:.78rem; color:var(--dim); margin:0 0 .25rem; }
  .row { display:flex; gap:.7rem; align-items:center; margin-top:.2rem; }
  .send-out { margin:.9rem 0 0; }
  .send-out .verdict { font-weight:600; margin:0 0 .5rem; }
  .send-out ul { margin:.5rem 0 0; padding-left:1.1rem; font-size:.85rem; color:var(--dim); }
  .send-out li { margin:.3rem 0; }
  .stats { display:flex; gap:1.5rem; flex-wrap:wrap; margin:0; }
  .stat b { display:block; font-size:1.5rem; font-weight:600; }
  .stat span { color:var(--dim); font-size:.8rem; }
  a { color:var(--accent); }
</style></head><body><main>

  <h1>Pylot messaging playground</h1>
  <p class="sub">Send a signed message, watch the deliveries it causes arrive. This page refreshes itself.</p>

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

  <h2>Status</h2>
  <div class="card">
    <p class="stats">
      <span class="stat"><b>${s.total}</b><span>received</span></span>
      <span class="stat"><b class="${s.secretSuspect ? 'bad' : s.hasSecret ? 'ok' : 'warn'}">${
        s.secretSuspect ? 'bad key' : s.hasSecret ? 'on' : 'off'
      }</b><span>verification</span></span>
      <span class="stat"><b>±${s.tolerance}s</b><span>tolerance</span></span>
      <span class="stat"><b class="${s.rejectInvalid ? 'bad' : ''}">${s.rejectInvalid ? '401' : '200'}</b><span>reply on bad sig</span></span>
    </p>
    <p class="dim" style="margin:.9rem 0 0;font-size:.85rem">
      config: ${s.envFileLoaded ? `<code>.env</code> loaded` : `no <code>.env</code>`} from <code>${esc(s.envDir)}</code>
      ${s.secretHint ? ` · secret <code>${esc(s.secretHint)}</code>` : ''}
    </p>
  </div>

  <h2>Send a message</h2>
  <div class="card">
    ${
      s.sender.hasSigningKey
        ? s.sender.signingKeySuspect
          ? `<p class="bad" style="margin:0 0 .8rem"><strong>PYLOT_SIGNING_SECRET doesn't look like a real key</strong> — expected <code>pwhsec_</code> + 64 hex. Every send will 403.</p>`
          : ''
        : `<p class="warn" style="margin:0 0 .8rem">Set <code>PYLOT_SIGNING_SECRET</code> in <code>.env</code> and restart. Get it from <code>GET /rooms/signing-key</code>, or run <code>node send.js --provision</code>.</p>`
    }
    <p class="dim" style="margin:0 0 .9rem;font-size:.85rem">
      Signed with the team key — no api key, no token. Posted to
      <code>${esc(s.sender.apiUrl)}/rooms/messages</code>${
        s.sender.signingKeyHint ? ` as <code>${esc(s.sender.signingKeyHint)}</code>` : ''
      }. The key stays on this server; the browser only ever sees the signature.
    </p>
    <label class="f"><span>roomId</span><input id="f-room" value="${esc(s.sender.roomId)}" placeholder="664f0f1e2c9a4b0012ab34cd"></label>
    <label class="f"><span>message</span><textarea id="f-text">Hello from the receiver 👋</textarea></label>
    <details style="margin:0 0 .8rem">
      <summary class="dim" style="cursor:pointer;font-size:.85rem">Raw body (overrides the fields above)</summary>
      <textarea id="f-body" style="margin-top:.5rem" class="mono" placeholder='{"roomId":"…","message":{"type":"text","text":{"value":"hi"}}}'></textarea>
    </details>
    <div class="row">
      <button id="f-send">Send signed</button>
      <span class="dim" style="font-size:.85rem">the resulting <code>message.sent</code> delivery appears below</span>
    </div>
    <div class="send-out" id="f-out"></div>
  </div>

  <h2>Recent deliveries</h2>
  <div class="card" style="padding:.15rem .6rem">${rows}</div>

  <h2>Configure</h2>
  <div class="card">
    <p style="margin:0 0 .6rem">Edit <code>.env</code> in <code>${esc(s.envDir)}</code>, then restart:</p>
    <pre class="mono dim" style="margin:0;white-space:pre-wrap;font-size:.85rem">WEBSUITE_WEBHOOK_SECRET=pwhsec_…   # from Create subscription, shown once
NGROK_AUTHTOKEN=…                  # free, for a public URL
NGROK_DOMAIN=…                     # optional: stable URL across restarts
PORT=${PORT}
REJECT_INVALID=1                   # reply 401 on a bad signature, to see retries</pre>
  </div>

<script>
  // Everything the send returned, laid out so a 403 is diagnosable without
  // leaving the page: what was signed, what was sent, and why it likely failed.
  const esc = (v) => String(v).replace(/[&<>]/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
  const out = document.getElementById('f-out');
  const btn = document.getElementById('f-send');

  btn.addEventListener('click', async () => {
    btn.disabled = true;
    out.innerHTML = '<p class="dim">Signing and sending…</p>';
    let r;
    try {
      r = await (await fetch('/_send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          roomId: document.getElementById('f-room').value.trim(),
          text: document.getElementById('f-text').value,
          body: document.getElementById('f-body').value,
        }),
      })).json();
    } catch (e) {
      out.innerHTML = '<p class="bad">' + esc(e.message) + '</p>';
      btn.disabled = false;
      return;
    }
    if (r.error) {
      out.innerHTML = '<p class="bad">' + esc(r.error) + '</p>';
      btn.disabled = false;
      return;
    }

    const d = (r.response && r.response.data) || {};
    const head = r.ok
      ? '<p class="verdict ok">✔ ' + r.status + ' queued — room ' + esc(d.roomId || '?') +
        ', message ' + esc(d.messageId || '?') + '</p>' +
        '<p class="dim" style="font-size:.85rem;margin:0">Accepted by the room pipeline — not yet delivered to the customer.</p>'
      : '<p class="verdict bad">✘ ' + r.status + ' ' + esc((r.response && r.response.msg) || '') + '</p>' +
        (r.status === 403
          ? '<p class="dim" style="font-size:.85rem;margin:0">The platform will not say which half of the signature was wrong. Likely causes:</p>'
          : '');

    const notes = r.notes && r.notes.length
      ? '<ul>' + r.notes.map((n) => '<li>' + esc(n) + '</li>').join('') + '</ul>'
      : '';

    const trace =
      '<details style="margin-top:.8rem"><summary class="dim" style="cursor:pointer;font-size:.85rem">Signature trace</summary>' +
      '<table class="hdr" style="margin-top:.5rem">' +
      Object.entries(r.request.headers).map(([k, v]) =>
        '<tr><td class="mono dim">' + esc(k) + '</td><td class="mono brk">' + esc(v) + '</td></tr>').join('') +
      (r.skew !== null ? '<tr><td class="mono dim">clock skew</td><td class="mono">' + esc(r.skew) + 's</td></tr>' : '') +
      (r.requestAge !== null ? '<tr><td class="mono dim">age at server</td><td class="mono">' + esc(r.requestAge) + 's</td></tr>' : '') +
      '</table>' +
      '<p class="dim" style="font-size:.78rem;margin:.6rem 0 .2rem">signed bytes — HMAC-SHA256 over exactly this</p>' +
      '<pre class="mono">' + esc(JSON.stringify(r.request.signedContent)) + '</pre>' +
      '<p class="dim" style="font-size:.78rem;margin:.6rem 0 .2rem">body sent</p>' +
      '<pre class="mono">' + esc(r.request.rawBody) + '</pre>' +
      '<p class="dim" style="font-size:.78rem;margin:.6rem 0 .2rem">response</p>' +
      '<pre class="mono">' + esc(JSON.stringify(r.response, null, 2)) + '</pre>' +
      '</details>';

    out.innerHTML = head + notes + trace;
    btn.disabled = false;
  });

  // Poll rather than reload, so a copied URL selection and scroll position survive.
  setInterval(async () => {
    try {
      const r = await fetch('/_state');
      const s = await r.json();
      if (s.total !== ${s.total}) location.reload();
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
    console.log(`  ${dim('sending ')}  ${dim(`${SIGNING_SECRET.slice(0, 11)}… → ${API_URL}/rooms/messages`)}`);
  } else {
    console.log(
      `  ${yellow('No PYLOT_SIGNING_SECRET set')} ${dim('— sending is off. Run `node send.js --provision`.')}`,
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
