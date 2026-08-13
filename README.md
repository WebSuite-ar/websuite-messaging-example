# WebSuite webhook receiver

A throwaway endpoint for watching WebSuite event deliveries. It opens an ngrok
tunnel, prints the public URL to paste into a subscription, and shows every
delivery it receives — headers, payload, and signature verdict — in a web UI and
the console.

Use it while building the receiving half of a webhook integration: point a
subscription at it, fire a test event, and see exactly what arrives.

## Setup

```bash
npm install
cp .env.example .env      # then fill it in
```

Two values matter:

- **`WEBSUITE_WEBHOOK_SECRET`** — the `pwhsec_…` secret returned *once* by
  **Create subscription**. Without it the receiver still prints payloads but
  cannot verify them, and says so loudly.
- **`NGROK_AUTHTOKEN`** — a free token from
  [ngrok](https://dashboard.ngrok.com/get-started/your-authtoken). Without it the
  receiver runs local-only and the platform cannot reach it.

## Run

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

The same URL, opened in a browser, serves a status page: outstanding setup
steps, verification state, and the last 25 deliveries with their full headers
and payloads expandable.

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
