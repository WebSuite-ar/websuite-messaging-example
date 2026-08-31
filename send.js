#!/usr/bin/env node
/**
 * Send a message into a Pylot room — signed, with no api key and no token — and
 * show exactly what went on the wire.
 *
 * The companion to index.js: that one receives events, this one sends messages.
 * Run both and you have the whole loop — send here, watch the resulting
 * `message.sent` delivery land in the receiver.
 *
 * The point of this file is DEBUGGABILITY. A rejected signature comes back as a
 * bare 403 with no explanation (deliberately — the platform will not tell an
 * unauthenticated caller which half of its signature is wrong), so everything
 * needed to work out the cause is printed locally: the exact signed bytes, the
 * digest, the headers, the measured clock skew against the server, and a
 * diagnosis of the usual causes.
 *
 * Run `node send.js --help`. See README.md.
 */
'use strict';

const path = require('path');

const { diagnose } = require('./diagnose');
const { signedHeaders, looksLikeSecret, TOLERANCE_SECONDS } = require('./sign');
const { bold, dim, red, green, yellow, cyan, line } = require('./tty');

// Load `.env` from THIS directory (not the cwd), same as the receiver.
let envFileLoaded = false;
try {
  process.loadEnvFile(path.join(__dirname, '.env'));
  envFileLoaded = true;
} catch {
  envFileLoaded = false;
}

// ---------------------------------------------------------------- config
const API_URL = (process.env.PYLOT_API_URL || 'http://localhost:4000/api/v2').replace(/\/+$/, '');
const SIGNING_SECRET = process.env.PYLOT_SIGNING_SECRET || '';
const TOKEN = process.env.PYLOT_TOKEN || '';
const DEFAULT_ROOM = process.env.PYLOT_ROOM_ID || '';
const DEFAULT_CONNECTION = process.env.PYLOT_USER_CONNECTION_ID || '';

// ------------------------------------------------------------------ args
/** Minimal flag parser — `--flag value` / `--flag` / bare words as the text. */
function parseArgs(argv) {
  const flags = {};
  const rest = [];
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next === undefined || next.startsWith('--')) {
        flags[key] = true;
      } else {
        flags[key] = next;
        i += 1;
      }
    } else {
      rest.push(a);
    }
  }
  return { flags, rest };
}

const { flags, rest } = parseArgs(process.argv.slice(2));
const DEBUG = Boolean(flags.debug);

const USAGE = `
${bold('  Pylot signed message sender')}

  ${dim('Send')}
    node send.js "Hello there"                       ${dim('# to PYLOT_ROOM_ID')}
    node send.js --room <roomId> --text "Hello"
    node send.js --room <roomId> --image <url> --caption "..."
    node send.js --connection <id> --to 18095550123 --name Jane --text "Hi"
    node send.js --body '{"roomId":"…","message":{…}}' ${dim('# full control')}

  ${dim('Debug')}
    --debug         show the signed bytes, the digest, the headers, a curl repro
    --check         verify config and measure clock skew against the server
    --provision     GET /rooms/signing-key with PYLOT_TOKEN, print the secret
    --stale         sign with a 10-minute-old timestamp (demo the replay window)
    --tamper        sign the body, then alter it (demo a digest mismatch)
    --unsigned      send with PYLOT_TOKEN as a Bearer instead of a signature

  ${dim('Config')} ${dim(`(.env in ${__dirname})`)}
    PYLOT_API_URL              ${dim('default http://localhost:4000/api/v2')}
    PYLOT_SIGNING_SECRET       ${dim('pwhsec_… from GET /rooms/signing-key')}
    PYLOT_ROOM_ID              ${dim('default target')}
    PYLOT_USER_CONNECTION_ID   ${dim('default channel for connect+send')}
    PYLOT_TOKEN                ${dim('JWT — only for --provision / --unsigned')}
`;

// ------------------------------------------------------------- printing
const label = (k) => dim(k.padEnd(11));

function header(title) {
  console.log('');
  console.log(bold(`  ${title}`));
  console.log(line('═'));
}

/** Show a string as the bytes it is: escapes, exact length, no ambiguity. */
function showBytes(name, s) {
  const bytes = Buffer.byteLength(s, 'utf8');
  console.log(`  ${label(name)} ${dim(`${bytes} bytes`)}`);
  console.log(`  ${dim('│')} ${JSON.stringify(s)}`);
}

/** A copy-pasteable curl that reproduces the request byte for byte. */
function asCurl(url, headers, rawBody) {
  const h = Object.entries(headers)
    .map(([k, v]) => `  -H ${JSON.stringify(`${k}: ${v}`)}`)
    .join(' \\\n');
  return `curl -sS -X POST ${JSON.stringify(url)} \\\n${h} \\\n  --data-raw ${JSON.stringify(rawBody)}`;
}

// ------------------------------------------------------------ operations
/**
 * Measure this host's clock against the server's, using the `Date` header on
 * any response. Skew is invisible locally and produces a perfect-looking
 * signature that is rejected anyway, so it is worth measuring before guessing.
 */
function serverSeconds(res) {
  const serverDate = res.headers.get('date');
  if (!serverDate) {
    return null;
  }
  const server = Math.floor(new Date(serverDate).getTime() / 1000);
  return Number.isFinite(server) ? server : null;
}

/** How far THIS host's clock is ahead of the server's, in seconds. */
function clockSkew(res) {
  const server = serverSeconds(res);
  return server === null ? null : Math.floor(Date.now() / 1000) - server;
}

/** GET /rooms/signing-key — needs a real session; prints the team's secret. */
async function provision() {
  header('Provision signing key');
  if (!TOKEN) {
    console.log(`  ${red('PYLOT_TOKEN is not set.')} ${dim('This one call needs a real session — the key is what replaces it afterwards.')}`);
    process.exitCode = 1;
    return;
  }
  const url = `${API_URL}/rooms/signing-key`;
  console.log(`  ${label('GET')} ${url}`);
  const res = await fetch(url, { headers: { Authorization: `Bearer ${TOKEN}` } });
  const body = await res.json().catch(() => null);
  const data = body && body.data;

  if (!res.ok || !data || !data.webhookSecret) {
    console.log(`  ${red(`✘ ${res.status}`)} ${dim(body ? JSON.stringify(body) : '(no body)')}`);
    if (res.status === 403) {
      console.log(`  ${dim('403 here means the token is invalid/expired, or the role lacks the `GET rooms/signing-key` permission.')}`);
    }
    process.exitCode = 1;
    return;
  }

  console.log(`  ${green('✔')} team ${dim(data.teamId)} ${data.created ? dim('(key created)') : dim('(existing key)')}`);
  console.log('');
  console.log(`  ${bold('PYLOT_SIGNING_SECRET')}=${data.webhookSecret}`);
  console.log('');
  console.log(dim(`  Put that in .env (${path.join(__dirname, '.env')}). Rotating invalidates it immediately.`));
}

/** Config sanity + clock skew, without sending anything. */
async function check() {
  header('Config check');
  const rows = [
    ['api url', API_URL, true],
    ['.env', envFileLoaded ? `loaded from ${__dirname}` : `not found in ${__dirname} — using exported vars`, envFileLoaded],
    [
      'signing key',
      SIGNING_SECRET
        ? looksLikeSecret(SIGNING_SECRET)
          ? `${SIGNING_SECRET.slice(0, 11)}… (well-formed)`
          : `${SIGNING_SECRET.slice(0, 11)}… NOT a pwhsec_ + 64 hex key`
        : 'not set',
      Boolean(SIGNING_SECRET) && looksLikeSecret(SIGNING_SECRET),
    ],
    ['room id', DEFAULT_ROOM || 'not set', Boolean(DEFAULT_ROOM)],
    ['connection', DEFAULT_CONNECTION || 'not set (optional)', true],
    ['token', TOKEN ? 'set (used only by --provision / --unsigned)' : 'not set (optional)', true],
  ];
  for (const [k, v, ok] of rows) {
    console.log(`  ${ok ? green('✔') : yellow('!')} ${label(k)} ${ok ? v : yellow(v)}`);
  }

  // Any response carries a `Date`, so an unauthenticated probe is enough.
  try {
    const res = await fetch(`${API_URL}/rooms/messages`, { method: 'POST' });
    const skew = clockSkew(res);
    if (skew === null) {
      console.log(`  ${yellow('!')} ${label('clock')} server sent no Date header — skew unknown`);
    } else if (Math.abs(skew) > TOLERANCE_SECONDS) {
      console.log(`  ${red('✘')} ${label('clock')} ${red(`${skew}s ahead of the server`)} ${dim(`— outside the ±${TOLERANCE_SECONDS}s window; every signature will be rejected`)}`);
    } else {
      console.log(`  ${green('✔')} ${label('clock')} ${skew}s from the server ${dim(`(±${TOLERANCE_SECONDS}s allowed)`)}`);
    }
  } catch (err) {
    console.log(`  ${red('✘')} ${label('reachable')} ${red(String((err && err.message) || err))}`);
  }
}

/** Build the request payload from the flags. */
function buildPayload() {
  if (typeof flags.body === 'string') {
    try {
      return JSON.parse(flags.body);
    } catch (err) {
      console.log(`  ${red('--body is not valid JSON:')} ${String((err && err.message) || err)}`);
      process.exit(1);
    }
  }

  const text = typeof flags.text === 'string' ? flags.text : rest.join(' ');
  const message =
    typeof flags.image === 'string'
      ? {
          type: 'image',
          image: { mediaUrl: flags.image, ...(flags.caption ? { caption: String(flags.caption) } : {}) },
        }
      : { type: 'text', text: { value: text || 'Hello from send.js 👋' } };

  const connection = typeof flags.connection === 'string' ? flags.connection : '';
  const room = typeof flags.room === 'string' ? flags.room : connection ? '' : DEFAULT_ROOM;

  // Target an existing room, or name a channel + how to reach the customer and
  // let the platform find-or-create the room. Not both.
  if (room) {
    return { roomId: room, message };
  }
  const contact = {};
  if (flags.name) {
    contact.name = String(flags.name);
  }
  if (flags.to) {
    contact.phone = String(flags.to);
  }
  return {
    userConnectionId: connection || DEFAULT_CONNECTION,
    ...(flags.to ? { transportId: String(flags.to) } : {}),
    ...(Object.keys(contact).length ? { contact } : {}),
    message,
  };
}

/** Sign (or not) and POST, narrating every step. */
async function send() {
  const payload = buildPayload();

  if (!payload.roomId && !payload.userConnectionId) {
    console.log(`  ${red('No target.')} ${dim('Pass --room, or --connection (+ --to), or set PYLOT_ROOM_ID in .env.')}`);
    process.exitCode = 1;
    return;
  }

  // Serialize ONCE. This exact string is what gets hashed AND what gets sent —
  // the whole scheme rests on those being the same bytes.
  let rawBody = JSON.stringify(payload);
  const url = `${API_URL}/rooms/messages`;
  const unsigned = Boolean(flags.unsigned);

  let headers;
  let signedContent = '';
  let timestamp = '';

  if (unsigned) {
    // The contrast case: a real credential is tried before the signature and
    // wins, and the message is then attributed to that user instead of the team.
    headers = { 'Content-Type': 'application/json', Authorization: `Bearer ${TOKEN}` };
  } else {
    // `--stale` back-dates past the replay window; the signature is still
    // perfectly valid, which is exactly what makes clock drift so confusing.
    const now = flags.stale ? Math.floor(Date.now() / 1000) - 600 : undefined;
    const signed = signedHeaders(rawBody, SIGNING_SECRET, now);
    headers = signed.headers;
    signedContent = signed.signedContent;
    timestamp = signed.timestamp;

    // `--tamper` alters the body AFTER signing — the same failure you get for
    // free by hashing one serialization and sending another.
    if (flags.tamper) {
      rawBody = rawBody.replace(/}$/, ', "tampered": true}');
    }
  }

  header(unsigned ? 'Send (Bearer token)' : flags.stale ? 'Send (stale timestamp)' : flags.tamper ? 'Send (tampered body)' : 'Send (HMAC signed)');
  console.log(`  ${label('POST')} ${url}`);
  console.log(`  ${label('target')} ${payload.roomId ? `room ${payload.roomId}` : `connection ${payload.userConnectionId}${payload.transportId ? ` → ${payload.transportId}` : ''}`}`);
  if (!unsigned) {
    console.log(
      `  ${label('key')} ${SIGNING_SECRET ? `${SIGNING_SECRET.slice(0, 11)}…` : red('not set')}${
        SIGNING_SECRET && !looksLikeSecret(SIGNING_SECRET) ? ` ${yellow('(malformed)')}` : ''
      }`,
    );
    console.log(`  ${label('timestamp')} ${timestamp}${flags.stale ? yellow(' (back-dated 600s — expect 403)') : ''}`);
    console.log(`  ${label('signature')} ${headers['x-pylot-signature']}`);
  }

  if (DEBUG) {
    console.log(line());
    if (!unsigned) {
      showBytes('signed', signedContent);
    }
    showBytes('body sent', rawBody);
    if (!unsigned && signedContent !== `${timestamp}.${rawBody}`) {
      console.log(`  ${red('✘ the signed bytes and the sent bytes differ')} ${dim('— this request cannot verify')}`);
    }
    console.log(line());
    console.log(dim('  curl repro:'));
    console.log(dim(asCurl(url, headers, rawBody).split('\n').map((l) => `  ${l}`).join('\n')));
    console.log(line());
  }

  let res;
  try {
    res = await fetch(url, { method: 'POST', headers, body: rawBody });
  } catch (err) {
    console.log(`  ${red('✘ request failed')} ${dim(String((err && err.message) || err))}`);
    console.log(`  ${dim(`Is ${API_URL} reachable from here?`)}`);
    process.exitCode = 1;
    return;
  }

  const text = await res.text();
  let body = null;
  try {
    body = JSON.parse(text);
  } catch {
    /* non-JSON — shown raw below */
  }
  const skew = clockSkew(res);
  // How stale the signed timestamp looked from where it was judged.
  const server = serverSeconds(res);
  const requestAge = server === null || !timestamp ? null : server - Number(timestamp);

  console.log('');
  if (res.ok && body && body.data && body.data.queued) {
    console.log(`  ${green(bold(`✔ ${res.status}`))} queued`);
    console.log(`  ${label('room')} ${body.data.roomId}`);
    console.log(`  ${label('message')} ${body.data.messageId}`);
    console.log('');
    console.log(
      dim('  `queued` means accepted by the room pipeline — not yet delivered to the customer.'),
    );
    console.log(dim('  Subscribe to `message.sent` / `message.failed` and run index.js to watch it land.'));
  } else {
    console.log(`  ${red(bold(`✘ ${res.status}`))} ${dim(body ? `${body.msg || ''}` : '(non-JSON response)')}`);
    if (body && body.data && body.data.message) {
      console.log(`  ${dim(body.data.message)}`);
    } else if (!body) {
      console.log(`  ${dim(text.slice(0, 500))}`);
    }
    if (res.status === 403) {
      console.log('');
      console.log(
        `  ${dim('403 E_UNAUTHORIZED is the platform\'s generic rejection. It will not say which half of the')}`,
      );
      console.log(`  ${dim('signature was wrong — the real reason is in the server-side AUTH_REJECT log. Likely causes:')}`);
    }
    const notes = diagnose({
      status: res.status,
      secret: SIGNING_SECRET,
      skew,
      requestAge,
      signedContent,
      rawBody,
      timestamp,
      unsigned,
      payload,
    });
    if (notes.length) {
      console.log('');
      for (const n of notes) {
        console.log(`  ${yellow('•')} ${n}`);
      }
    }
    process.exitCode = 1;
  }

  if (skew !== null && (DEBUG || Math.abs(skew) > 60)) {
    console.log('');
    console.log(`  ${label('clock')} ${Math.abs(skew) > TOLERANCE_SECONDS ? red(`${skew}s skew`) : dim(`${skew}s skew`)} ${dim(`(±${TOLERANCE_SECONDS}s allowed)`)}`);
  }
  if (DEBUG) {
    console.log(`  ${label('trace id')} ${res.headers.get('x-trace-id') || dim('(none)')}`);
  }
}

// ---------------------------------------------------------------- main
async function main() {
  if (flags.help || flags.h) {
    console.log(USAGE);
    return;
  }
  if (flags.provision) {
    await provision();
    return;
  }
  if (flags.check) {
    await check();
    return;
  }
  if (!SIGNING_SECRET && !flags.unsigned) {
    console.log(USAGE);
    console.log(`  ${yellow('PYLOT_SIGNING_SECRET is not set.')} ${dim('Run `node send.js --provision` (needs PYLOT_TOKEN once).')}`);
    console.log('');
    process.exitCode = 1;
    return;
  }
  await send();
  console.log('');
}

main().catch((err) => {
  console.error(red(`fatal: ${(err && err.stack) || err}`));
  process.exit(1);
});
