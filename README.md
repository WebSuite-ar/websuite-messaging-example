# WebSuite messaging playground

A throwaway box for working on both halves of the Pylot messaging surface.

- **Receive** — opens an ngrok tunnel, prints the public URL to paste into a
  subscription, and shows every delivery that arrives: headers, payload, and
  signature verdict, in a web UI and the console.
- **Send** — signs a `POST /rooms/messages` with the team key (**no api key, no
  token**) and shows exactly what went on the wire: the bytes that were hashed,
  the digest, the headers, and — when the platform refuses — why it probably did.
- **Sign** — body + key → signature, and nothing else. For checking a signature
  your own code produced, without sending a message to anyone.

Run both and you have the whole loop: send a message, watch the `message.sent`
delivery it causes land in the same page.

| File | What it is |
| --- | --- |
| `index.js` | the receiver + the status page (which can also send) |
| `send.js` | the sender, as a CLI with a `--debug` trace |
| `sign.js` | the signing primitive, shared by both |
| `diagnose.js` | "why was this 403'd", shared by both |

## Setup

```bash
npm install
cp .env.example .env      # then fill it in
```

Three values matter:

- **`WEBSUITE_WEBHOOK_SECRET`** — the `pwhsec_…` secret returned *once* by
  **Create subscription**. Without it the receiver still prints payloads but
  cannot verify them, and says so loudly.
- **`PYLOT_SIGNING_SECRET`** — the `pwhsec_…` **team signing key**, for sending.
  `npm run provision` fetches it. Optional: leave it out and type the key into
  the UI's **Send** or **Signature** tab instead (or pass `--key` to `send.js`).
- **`NGROK_AUTHTOKEN`** — a free token from
  [ngrok](https://dashboard.ngrok.com/get-started/your-authtoken). Without it the
  receiver runs local-only and the platform cannot reach it.

> **The two `pwhsec_…` secrets are not interchangeable.** One verifies what Pylot
> sends *out* to you (a subscription secret); the other authenticates what you
> send *in* (the team signing key). Both HMAC identically, so swapping them fails
> silently-ish: a digest mismatch on the way in, an unexplained 403 on the way
> out. Nothing else about them differs, which is exactly why it costs people an
> afternoon.

## Receiving

```bash
npm start
```

```
  WebSuite webhook receiver
════════════════════════════════════════════════════════════
  local     http://localhost:2000/webhook
  public    https://abc123.ngrok-free.app/webhook

  Paste that into Create subscription as the `url`.

  secret    pwhsec_aaaa… (±300s tolerance)
════════════════════════════════════════════════════════════
  Waiting for deliveries…  (ctrl-c to stop)
```

Then create a subscription pointing at the public URL and fire **Send test
event** — from the WebSuite Postman collection, or however you manage
subscriptions.

The same URL, opened in a browser, serves a status page. Outstanding setup steps
sit at the top; everything else is behind a tab, so you get one thing at a time:

| Tab | What it does |
| --- | --- |
| **Send a message** | the signed `POST /rooms/messages`, with the trace |
| **Signature** | body + key → signature, computed and explained; nothing sent |
| **Deliveries** | the last 25 deliveries, headers and payloads expandable. Counts new arrivals on the tab rather than reloading under you |
| **Setup** | where config came from, and what to put in `.env` |

The page is bilingual. It opens in the language your browser asks for
(`Accept-Language`, q-values respected), so `es-AR` gets Spanish and everything
else falls back to English. The link in the top-right switches it; the choice is
remembered in a `pylot.lang` cookie, and `?lang=es` / `?lang=en` forces one for
a shareable URL. The diagnostics from the Send and Signature tabs follow the
same language. The **CLI stays English** whatever the browser says.

The **signing key** and **API base** are fields in the send-side tabs, not just
`.env` values. A key typed there wins over `.env`, is used to sign that one
request and then forgotten — nothing is written to disk, and it never reaches
the platform, only the signature does. It is held in the browser tab's
`sessionStorage`, so it survives a refresh and dies with the tab.

Each delivery prints as:

```
#1  message.received   2026-08-13T13:29:55.905Z
  ✔ signature verified (clock skew 0s)
  delivery  019248...
  event     019248...
  occurredAt=…  teamId=…
  ── payload ────────────────────
  { … }
```

Event types are colour-coded by family, and two conditions are called out
explicitly because they are the ones that confuse people:

- **`↻ RETRY`** — the same `x-pylot-delivery-id` arrived again, meaning a previous
  attempt was not acked with a 2xx.
- **`⧉ same event, different delivery`** — the same `eventId` fanned out to more
  than one subscription. This is why `eventId`, not the delivery id, is the
  correct deduplication key.

A failed signature prints the actual reason — stale timestamp with the measured
clock skew, digest mismatch, malformed hex — rather than a bare "invalid".

## Sending a message

The other direction: get a message into a room from a system that has **no JWT
and no API key**, by signing the request body with the team's HMAC key.

### 1. Get the key

```bash
npm run provision          # GET /rooms/signing-key, needs PYLOT_TOKEN once
```

```
  ✔ team 0f3f…-uuid (existing key)

  PYLOT_SIGNING_SECRET=pwhsec_9c1a…
```

Put that in `.env` — or skip `.env` and paste it into the **Send** tab, or pass
`--key`. It's the *only* credential the sender needs afterwards; that one JWT was
just to fetch it. Rotating (`POST /rooms/signing-key/rotate`) invalidates it
immediately, with no grace window.

### 2. Send

```bash
npm run send -- --text "Your order #1042 has shipped 📦"
node send.js --room 664f… --text "hi"
node send.js --connection 664f… --to 18095550123 --name Jane --text "Hi Jane 👋"
node send.js --body '{"roomId":"664f…","message":{"type":"text","text":{"value":"hi"}}}'
node send.js --key pwhsec_… --api https://api.websuite.ar/api/v2 --text "hi"
```

`--key` and `--api` override `PYLOT_SIGNING_SECRET` and `PYLOT_API_URL` for that
one send — the CLI counterpart to the fields in the UI. Neither writes anything
back to `.env`.

```
  Send (HMAC signed)
════════════════════════════════════════════════════════
  POST        https://api.pylot.io/api/v2/rooms/messages
  target      room 664f0f1e2c9a4b0012ab34cd
  key         pwhsec_9c1a…
  timestamp   1756612800
  signature   sha256=f989728a3eaedfede600653c…

  ✔ 200 queued
  room        664f0f1e2c9a4b0012ab34cd
  message     a1b2c3d4e5f6…
```

`queued` means accepted by the room pipeline — **not** delivered to the customer
yet. Subscribe to `message.sent` / `message.failed` and leave `npm start`
running to watch it actually land.

Or use the **Send a message** tab on the receiver's status page, which does the
same thing with the trace rendered inline — and counts the resulting delivery on
the **Deliveries** tab.

### Just the signature

When the question is "is my signature right?" rather than "did the message
land", the **Signature** tab takes a body and a key and computes the two
headers without sending anything:

```
x-pylot-timestamp: <unix seconds>
x-pylot-signature: sha256=hex(HMAC_SHA256(key, timestamp + "." + body))
```

It hashes the body **exactly as typed** — whitespace, key order, unicode
escaping and all — and then, if the body parses as JSON, shows the digest of its
compact re-serialization too. Those two digests differing is the point: it is
what "serialize once, hash that string, send that string" looks like when you
get it wrong, and it is the most common cause of a 403 nobody can explain. The
tab also flags a key that isn't `pwhsec_` + 64 hex, a body that isn't valid
JSON, and a timestamp already outside the ±300s window, and hands you a `curl`
that sends precisely the bytes it hashed.

### 3. Debug

A rejected signature comes back as a bare `403 E_UNAUTHORIZED`. That is
deliberate: the platform will not tell an unauthenticated caller which half of
its signature was wrong, and the real reason goes to the server-side
`AUTH_REJECT` log. So everything needed to work it out is printed locally
instead.

```bash
node send.js --text hi --debug
```

```
  signed      105 bytes
  │ "1756612800.{\"roomId\":\"664f…\",\"message\":{…}}"
  body sent   94 bytes
  │ "{\"roomId\":\"664f…\",\"message\":{…}}"
  ────────────────────────────────────────────────────
  curl repro:
  curl -sS -X POST "https://api.pylot.io/api/v2/rooms/messages" \
    -H "Content-Type: application/json" \
    -H "x-pylot-timestamp: 1756612800" \
    -H "x-pylot-signature: sha256=f98972…" \
    --data-raw "{…}"
```

On a rejection it names the likely causes rather than leaving you guessing:

```
  ✘ 403 E_UNAUTHORIZED

  • the timestamp was 600s old when it reached the server, outside the ±300s
    replay window — rejected regardless of how correct the digest is.
  • the key may have been rotated since it was cached…
```

Three flags reproduce the failures on demand, so you can see what each one looks
like before meeting it in production:

| Flag | Reproduces |
| --- | --- |
| `--stale` | signs with a 10-minute-old timestamp — a *correct* signature outside the replay window. This is what clock drift looks like. |
| `--tamper` | alters the body after signing — what hashing one serialization and sending another looks like. |
| `--unsigned` | sends with `PYLOT_TOKEN` as a Bearer instead, to compare the two auth models on the same endpoint. |

And before any of that:

```bash
npm run send:check
```

checks the config and **measures this host's clock against the server's** — skew
is invisible locally and produces a flawless signature that is rejected anyway.

The full scheme, with Node / Python / PHP / curl implementations and a
failure-cause table, is in `ts-node-be/docs/signing-room-messages.md`.

## Options

| Variable | Default | Purpose |
| --- | --- | --- |
| `WEBSUITE_WEBHOOK_SECRET` | — | Subscription signing secret. Omit to skip verification. |
| `NGROK_AUTHTOKEN` | — | ngrok token. Omit to run local-only. |
| `NGROK_DOMAIN` | — | Reserved ngrok domain, so the URL survives restarts and you don't have to re-edit the subscription. |
| `PORT` | `2000` | Local port. |
| `WEBHOOK_PATH` | `/webhook` | Path deliveries are POSTed to. |
| `TOLERANCE_SECONDS` | `300` | Replay window, matching the platform. |
| `REJECT_INVALID` | off | Reply **401** on a bad signature instead of 200. Use this to watch the platform's retry schedule (1/3/10/30/60s, cap 5) actually fire. |
| `NO_TUNNEL` | off | Skip ngrok entirely (`npm run start:local`). |
| `PYLOT_API_URL` | `https://api.websuite.ar/api/v2` | Where to send. The `/api/v2` is part of it. Overridable in the UI, or with `--api`. |
| `PYLOT_SIGNING_SECRET` | — | Team signing key. Omit it and type the key into the UI, or pass `--key`. |
| `PYLOT_ROOM_ID` | — | Default send target. |
| `PYLOT_USER_CONNECTION_ID` | — | Default channel, for connect+send. |
| `PYLOT_TOKEN` | — | JWT. Only `--provision` and `--unsigned` use it. |

By default **every** delivery is acked with 200, including ones that fail
verification — this is an inspection tool first, and you want to see the payload
that failed. `REJECT_INVALID=1` makes it behave like a real receiver.

## Notes

- The signature covers the **exact bytes on the wire**, so the raw body is
  captured via `express.json({ verify })` before parsing. Verifying a
  re-serialised body is the classic source of mystery 401s — this is the one
  detail worth copying into your real implementation.
- The receiver acks fast and does all its work synchronously after responding
  where possible. A real consumer should do the same: queue the work, ack
  immediately, and stay well inside the 10s dispatch timeout.
- Headers carry the literal token `pylot` (`x-pylot-signature`, …). Those are
  wire values, not branding — see the collection description.
- `sign.js` takes the body as a **string**, never an object to serialize. That is
  the one design decision worth copying: accepting an object would let the signer
  serialize one way and the HTTP client another, and a body that is hashed
  differently from how it is sent is the single most common cause of a rejected
  signature. Serialize once, hash that string, send that string.
- The web panel signs on the **server** and proxies. A signature computed in a
  browser means the key is in the browser, which means anyone with devtools can
  send as the team. A key you paste into the UI is posted to this local process,
  which signs and forgets it; it is never forwarded to the platform, and only
  the signature comes back. That is still a credential typed into a web page, so
  the page is worth keeping on localhost — which is where it runs.
