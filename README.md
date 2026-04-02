# NOSTR Mail Bridge — SMTP <-> NOSTR Gateway

Bidirectional bridge between email (SMTP/MIME) and NOSTR Mail (kind 1400 events with NIP-59 gift wrapping).

## Architecture

```
                    INBOUND (Email -> NOSTR)
  ┌──────────┐     ┌─────────────────────────────────────┐     ┌──────────┐
  │  Email    │────>│  SMTP Server                        │────>│  NOSTR   │
  │  Sender   │     │  1. Parse MIME (mailparser)         │     │  Relays  │
  │           │     │  2. Verify SPF/DKIM/DMARC           │     │          │
  └──────────┘     │  3. Resolve recipient (NIP-05)      │     └──────────┘
                    │  4. HTML -> Markdown                 │
                    │  5. Attachments -> Blossom upload    │
                    │  6. Build kind 1400 rumor              │
                    │  7. NIP-59 gift wrap                 │
                    │  8. Publish to inbox relays          │
                    └─────────────────────────────────────┘

                    OUTBOUND (NOSTR -> Email)
  ┌──────────┐     ┌─────────────────────────────────────┐     ┌──────────┐
  │  NOSTR   │────>│  NOSTR Subscriber                   │────>│  Email   │
  │  Relays  │     │  1. Subscribe kind 1059 (#p bridge)  │     │  Recip.  │
  │          │     │  2. Decrypt NIP-59 three layers      │     │          │
  └──────────┘     │  3. Check ["email-to", addr] tag    │     └──────────┘
                    │  4. Markdown -> HTML                 │
                    │  5. Download Blossom attachments     │
                    │  6. Build MIME message               │
                    │  7. DKIM sign                        │
                    │  8. Send via SMTP                    │
                    └─────────────────────────────────────┘
```

## Quick Start

```bash
# Install dependencies
npm install

# Set required environment variables
export BRIDGE_DOMAIN=bridge.example.com
export BRIDGE_PRIVATE_KEY=$(openssl rand -hex 32)
export NOSTR_RELAYS=wss://relay.damus.io,wss://nos.lol

# Development mode
npm run dev

# Production build
npm run build
npm start
```

## Docker

```bash
docker build -t nostr-mail-bridge .

docker run -d \
  -e BRIDGE_DOMAIN=bridge.example.com \
  -e BRIDGE_PRIVATE_KEY=<hex-private-key> \
  -e NOSTR_RELAYS=wss://relay.damus.io,wss://nos.lol \
  -p 2525:2525 \
  -p 8080:8080 \
  nostr-mail-bridge
```

## Configuration Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `BRIDGE_DOMAIN` | Yes | — | Domain name for the bridge |
| `BRIDGE_PRIVATE_KEY` | No | Auto-generated | Hex NOSTR private key (64 chars) |
| `NOSTR_RELAYS` | No | `wss://relay.damus.io,...` | Comma-separated relay URLs |
| `SMTP_PORT` | No | `2525` | Inbound SMTP port |
| `SMTP_SUBMISSION_PORT` | No | `587` | Authenticated submission port |
| `BRIDGE_HOSTNAME` | No | Same as domain | SMTP EHLO hostname |
| `DKIM_PRIVATE_KEY` | No | — | PEM-encoded DKIM signing key |
| `DKIM_SELECTOR` | No | `default` | DKIM DNS selector |
| `BLOSSOM_SERVERS` | No | `https://blossom.primal.net` | Comma-separated Blossom URLs |
| `OUTBOUND_SMTP_HOST` | No | `localhost` | Outbound SMTP relay host |
| `OUTBOUND_SMTP_PORT` | No | `25` | Outbound SMTP relay port |
| `OUTBOUND_SMTP_SECURE` | No | `false` | Use TLS for outbound |
| `OUTBOUND_SMTP_USER` | No | — | Outbound SMTP auth user |
| `OUTBOUND_SMTP_PASS` | No | — | Outbound SMTP auth password |
| `HEALTH_PORT` | No | `8080` | HTTP health-check port |
| `MAX_MESSAGE_SIZE` | No | `26214400` | Max inbound email size (bytes) |
| `REQUIRE_AUTH` | No | `false` | Require SPF/DKIM pass |

## DNS Configuration

For the bridge to receive email and send DKIM-signed mail:

```
; MX record — route email to the bridge
bridge.example.com.  IN  MX  10  bridge.example.com.

; A/AAAA record — point to the bridge server
bridge.example.com.  IN  A   1.2.3.4

; DKIM record
default._domainkey.bridge.example.com.  IN  TXT  "v=DKIM1; k=rsa; p=<base64-public-key>"

; SPF record
bridge.example.com.  IN  TXT  "v=spf1 ip4:1.2.3.4 -all"

; DMARC record
_dmarc.bridge.example.com.  IN  TXT  "v=DMARC1; p=reject; rua=mailto:dmarc@bridge.example.com"
```

## How It Works

### Inbound Flow (Email -> NOSTR)

1. External email sender sends to `user@bridge.example.com`
2. Bridge SMTP server receives the MIME message
3. Parses headers, body, attachments via `mailparser`
4. Evaluates SPF/DKIM/DMARC from `Authentication-Results` header
5. Resolves recipient email to NOSTR pubkey via NIP-05 lookup
6. Converts HTML body to Markdown; uploads attachments to Blossom
7. Builds kind 1400 rumor with bridge provenance tags
8. Gift wraps (NIP-59 three-layer encryption) for each recipient
9. Publishes kind 1059 events to recipient's inbox relays

### Outbound Flow (NOSTR -> Email)

1. NOSTR user creates a kind 1400 mail with `["email-to", "user@example.com"]` tag
2. Gift wraps and publishes to bridge's pubkey
3. Bridge subscribes to kind 1059 events tagged with its pubkey
4. Decrypts three NIP-59 layers to extract the kind 1400 rumor
5. Checks for `email-to` tags indicating email delivery
6. Converts Markdown body to HTML; downloads Blossom attachments
7. Builds MIME message with proper headers and threading
8. DKIM signs and sends via outbound SMTP relay

### Identity Resolution

- **Email -> NOSTR**: NIP-05 lookup (`user@domain` -> `GET https://domain/.well-known/nostr.json?name=user`)
- **NOSTR -> Email**: Bridge-assigned addresses (`<pubkey-prefix>@bridge.example.com`) or registered mappings

### Threading

- Email `In-Reply-To` / `References` headers map to NOSTR `["reply", ...]` / `["thread", ...]` tags
- Message-ID <-> event ID mappings are stored for cross-protocol threading

### Security

- HTML is sanitized (strips scripts, event handlers, dangerous URL schemes)
- Gift wrap timestamps are randomized +/- 2 days
- Ephemeral keys are used for each gift wrap (no key reuse)
- DKIM signing on outbound ensures email authenticity

## Project Structure

```
src/
├── types.ts      — Bridge-specific type definitions
├── server.ts     — Main entry point, config loading, lifecycle
├── inbound.ts    — SMTP -> NOSTR conversion pipeline
├── outbound.ts   — NOSTR -> SMTP conversion pipeline
├── convert.ts    — Bidirectional MIME/rumor conversion utilities
├── identity.ts   — NIP-05 resolution, identity mapping database
└── sanitize.ts   — HTML sanitization
```

## Testing

```bash
# Run tests
npm test

# Watch mode
npm run test:watch
```

## Protocol References

- **NIP-01**: Basic protocol flow (events, relays)
- **NIP-05**: DNS-based identity verification
- **NIP-13**: Proof of Work
- **NIP-14**: Subject tag
- **NIP-17**: Private direct messages
- **NIP-44**: Versioned encryption
- **NIP-59**: Gift wrap (three-layer encryption)
- **NIP-65**: Relay list metadata (inbox relays)
- **Kind 1400**: NOSTR Mail message (proposed)
- **Kind 13**: Seal
- **Kind 1059**: Gift wrap

## License

MIT
