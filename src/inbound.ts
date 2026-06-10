// ─── SMTP <-> NOSTR Mail Bridge — Inbound (SMTP -> NOSTR) ──────────────────
// Receives email via SMTP, converts to NOSTR Mail kind 1400 events, and
// publishes to recipient's relays via NIP-59 gift wrapping.

import { SMTPServer } from 'smtp-server'
import { simpleParser } from 'mailparser'
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools'
import * as nip44 from 'nostr-tools/nip44'
import { createCipheriv, createHash, randomBytes } from 'node:crypto'
import type { BridgeConfig, BridgedMessage, ConversionResult, AuthResults, MailRumor } from './types.js'
import { mimeToRumor, extractAttachments, htmlToMarkdown, threadingEmailToNostr } from './convert.js'
import {
  resolveEmailToNostr,
  resolveMessageId,
  storeMessageIdMapping,
  fetchInboxRelays,
} from './identity.js'
import {
  sanitizeEmailAddress,
  sanitizeHeaderValue,
  parseHexBytes,
  sanitizeMessageId,
  sanitizeMessageIdList,
  sanitizeWebSocketUrl,
} from './security.js'
import { assertPublicUrl } from './ssrf.js'

/** Active SMTP server instance. */
let smtpServer: SMTPServer | null = null

/**
 * Per-IP connection rate limiter. Window: 60s rolling. Default cap: 30 conns.
 * The cap is intentionally generous for legitimate bursts but tight enough
 * to throttle a single-source flood. Counts reset every minute.
 */
const connectionRate = new Map<string, { count: number; windowStart: number }>()
const CONN_RATE_WINDOW_MS = 60_000
const CONN_RATE_MAX = 30

function checkConnRate(ip: string): boolean {
  const now = Date.now()
  const entry = connectionRate.get(ip)
  if (!entry || now - entry.windowStart >= CONN_RATE_WINDOW_MS) {
    connectionRate.set(ip, { count: 1, windowStart: now })
    return true
  }
  if (entry.count >= CONN_RATE_MAX) return false
  entry.count++
  return true
}

/**
 * Generic rolling-window rate limiter (F-BRIDGE-DOS-01). Per-IP limits alone
 * don't bound a single connection that resolves many recipients (each a fresh
 * outbound NIP-05 fetch → SSRF amplification) or a single sender flooding
 * messages. These limit by envelope-sender and by recipient.
 */
function makeRateLimiter(windowMs: number, max: number) {
  const buckets = new Map<string, { count: number; windowStart: number }>()
  return {
    check(key: string): boolean {
      const now = Date.now()
      const entry = buckets.get(key)
      if (!entry || now - entry.windowStart >= windowMs) {
        buckets.set(key, { count: 1, windowStart: now })
        // Opportunistically drop stale buckets to cap memory.
        if (buckets.size > 50_000) {
          for (const [k, v] of buckets) {
            if (now - v.windowStart >= windowMs) buckets.delete(k)
          }
        }
        return true
      }
      if (entry.count >= max) return false
      entry.count++
      return true
    },
    _buckets: buckets,
  }
}

const SENDER_RATE_WINDOW_MS = Number(process.env['SENDER_RATE_WINDOW_MS'] ?? 60_000)
const SENDER_RATE_MAX = Number(process.env['SENDER_RATE_MAX'] ?? 20)
const RECIPIENT_RATE_WINDOW_MS = Number(process.env['RECIPIENT_RATE_WINDOW_MS'] ?? 60_000)
const RECIPIENT_RATE_MAX = Number(process.env['RECIPIENT_RATE_MAX'] ?? 30)

const senderRate = makeRateLimiter(SENDER_RATE_WINDOW_MS, SENDER_RATE_MAX)
const recipientRate = makeRateLimiter(RECIPIENT_RATE_WINDOW_MS, RECIPIENT_RATE_MAX)

/** Exposed for tests. */
export const _rateLimiters = { senderRate, recipientRate, makeRateLimiter }

/**
 * LRU of recently-processed inbound messages keyed by raw-email SHA-256.
 * Bounded to 10_000 entries to cap memory.
 */
const inboundReplayCache = new Set<string>()
const INBOUND_REPLAY_CAP = 10_000
function rememberInbound(hash: string): boolean {
  if (inboundReplayCache.has(hash)) return false
  inboundReplayCache.add(hash)
  if (inboundReplayCache.size > INBOUND_REPLAY_CAP) {
    // Evict the oldest insertion (Set preserves insertion order).
    const oldest = inboundReplayCache.values().next().value
    if (oldest) inboundReplayCache.delete(oldest)
  }
  return true
}

/**
 * Encrypt an attachment body with AES-256-GCM under a fresh random key.
 *
 * Returns a blob laid out as `iv (12B) || ciphertext || authTag (16B)` and
 * the hex-encoded 32-byte key. The blob is what gets uploaded to Blossom;
 * the key is what gets shipped to the recipient inside the encrypted rumor
 * as the `attachment-key` tag.
 */
export function encryptAttachment(plaintext: Buffer): { blob: Buffer; keyHex: string } {
  const key = randomBytes(32)
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', key, iv)
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()])
  const tag = cipher.getAuthTag()
  const blob = Buffer.concat([iv, ct, tag])
  const keyHex = key.toString('hex')
  // Best-effort wipe of the standalone key buffer (the hex string is the
  // canonical carrier from here on).
  key.fill(0)
  return { blob, keyHex }
}

/**
 * Start the inbound SMTP server.
 *
 * Listens for incoming email, parses MIME, resolves recipients to NOSTR
 * pubkeys via NIP-05, converts to kind 1400 rumors, gift wraps, and publishes
 * to recipient inbox relays.
 *
 * @param config - Bridge configuration.
 * @returns The running SMTP server instance.
 */
export function startInboundServer(config: BridgeConfig): SMTPServer {
  const bridgePrivkey = parseHexBytes(config.bridgePrivateKeyHex)
  const bridgePubkey = getPublicKey(bridgePrivkey)

  // Production fail-closed if no TLS material is configured. The user can
  // override by setting BRIDGE_ALLOW_PLAINTEXT=1 — but in NODE_ENV=production
  // this is a hard error to prevent DKIM/credential exposure on port 25.
  if (
    process.env['NODE_ENV'] === 'production' &&
    !process.env['BRIDGE_TLS_KEY'] &&
    !process.env['BRIDGE_TLS_CERT'] &&
    process.env['BRIDGE_ALLOW_PLAINTEXT'] !== '1'
  ) {
    throw new Error(
      '[inbound] Refusing to start without STARTTLS in production. ' +
        'Set BRIDGE_TLS_KEY+BRIDGE_TLS_CERT or BRIDGE_ALLOW_PLAINTEXT=1 (development only).',
    )
  }

  smtpServer = new SMTPServer({
    name: config.hostname,
    size: config.maxMessageSize,
    authOptional: true,
    disabledCommands: ['AUTH'], // No auth needed for inbound relay
    secure: false, // STARTTLS handled separately in production
    // ── Resource limits (audit-required hardening) ─────────────────────
    maxClients: 50,
    closeTimeout: 30_000,
    socketTimeout: 60_000,
    // The fields below are valid smtp-server options but missing from
    // @types/smtp-server in some versions; spread to bypass the type gap.
    ...({ maxAllowedUnauthenticatedCommands: 10, maxRecipients: 50 } as object),

    onConnect(session, callback) {
      const ip = (session.remoteAddress ?? 'unknown').toString()
      if (!checkConnRate(ip)) {
        return callback(new Error(`421 Too many connections from ${ip}`))
      }
      callback()
    },

    onData(stream, session, callback) {
      const chunks: Buffer[] = []

      stream.on('data', (chunk: Buffer) => {
        chunks.push(chunk)
      })

      stream.on('end', () => {
        const rawEmail = Buffer.concat(chunks)

        // Process asynchronously, acknowledge receipt immediately
        processInboundEmail(rawEmail, session, config, bridgePrivkey, bridgePubkey)
          .then(result => {
            if (!result.success) {
              console.error('[inbound] Processing failed:', result.error)
            } else {
              console.log('[inbound] Message processed successfully:', result.warnings)
            }
          })
          .catch(err => {
            console.error('[inbound] Unexpected error:', err)
          })

        callback()
      })

      stream.on('error', (err) => {
        console.error('[inbound] Stream error:', err)
        callback(new Error('Stream error'))
      })
    },

    onRcptTo(address, _session, callback) {
      // Accept mail for our domain
      const domain = address.address.split('@')[1]?.toLowerCase()
      if (domain === config.domain.toLowerCase()) {
        callback()
      } else {
        callback(new Error(`Relay access denied for domain: ${domain}`))
      }
    },
  })

  smtpServer.listen(config.smtpPort, () => {
    console.log(`[inbound] SMTP server listening on port ${config.smtpPort}`)
  })

  smtpServer.on('error', (err) => {
    console.error('[inbound] SMTP server error:', err)
  })

  return smtpServer
}

/**
 * Stop the inbound SMTP server gracefully.
 */
export async function stopInboundServer(): Promise<void> {
  if (smtpServer) {
    return new Promise((resolve) => {
      smtpServer!.close(() => {
        console.log('[inbound] SMTP server stopped')
        smtpServer = null
        resolve()
      })
    })
  }
}

/**
 * Process a single inbound email: parse, convert, wrap, publish.
 *
 * @param rawEmail - Raw MIME email data.
 * @param session - SMTP session info (sender IP, envelope).
 * @param config - Bridge configuration.
 * @param bridgePrivkey - Bridge private key bytes.
 * @param bridgePubkey - Bridge public key hex.
 * @returns Conversion result with details.
 */
async function processInboundEmail(
  rawEmail: Buffer,
  session: { remoteAddress?: string; envelope?: { mailFrom?: false | { address?: string }; rcptTo?: Array<{ address?: string }> } },
  config: BridgeConfig,
  bridgePrivkey: Uint8Array,
  bridgePubkey: string,
): Promise<ConversionResult> {
  const warnings: string[] = []

  try {
    // ── Step 0: Replay + loop avoidance ─────────────────────────────────
    const rawHash = createHash('sha256').update(rawEmail).digest('hex')
    if (!rememberInbound(rawHash)) {
      return { success: false, error: 'Duplicate email (replay rejected)', warnings }
    }

    // ── Step 1: Parse MIME ───────────────────────────────────────────────
    const parsed = await simpleParser(rawEmail)

    // Loop avoidance: reject if our own X-Nostr-Bridge header is present.
    const bridgeMarker = parsed.headers.get('x-nostr-bridge')
    if (typeof bridgeMarker === 'string' && bridgeMarker.includes('NostrMail-Bridge')) {
      return {
        success: false,
        error: 'X-Nostr-Bridge header present — refusing to bridge a bridged message (loop avoidance)',
        warnings,
      }
    }

    // ── Step 2: Extract sender info ─────────────────────────────────────
    const fromAddress = sanitizeEmailAddress(parsed.from?.value[0]?.address)
    if (!fromAddress) {
      return { success: false, error: 'No From address in email', warnings }
    }

    // Loop avoidance: reject if From: is one of our own bridge-managed addrs.
    const fromDomain = fromAddress.split('@')[1]?.toLowerCase()
    if (fromDomain === config.domain.toLowerCase()) {
      return {
        success: false,
        error: `From: address ${fromAddress} is in this bridge's domain — refusing to relay (loop avoidance)`,
        warnings,
      }
    }

    const fromName = parsed.from?.value[0]?.name
      ? sanitizeHeaderValue(parsed.from.value[0].name, 128)
      : undefined

    // F-BRIDGE-DOS-01: throttle per envelope-sender (independent of source IP).
    const envelopeFrom =
      (session.envelope && typeof session.envelope.mailFrom === 'object'
        ? sanitizeEmailAddress(session.envelope.mailFrom?.address)
        : null) ?? fromAddress
    if (!senderRate.check(envelopeFrom)) {
      return { success: false, error: `Rate limit exceeded for sender ${envelopeFrom}`, warnings }
    }

    // ── Step 3: Evaluate authentication (SPF/DKIM/DMARC) ───────────────
    // F-DKIM-01: verify cryptographically and locally (mailauth) rather than
    // trusting upstream headers; fall back to a trusted authserv-id only when
    // explicitly configured. The gate requires a DMARC *pass* (i.e. an aligned
    // SPF or DKIM), not a bare SPF pass, to prevent From-header spoofing.
    const authResults = await verifyInboundAuth(rawEmail, session, parsed.headers, config)

    if (config.requireAuth && authResults.dmarc !== 'pass') {
      return {
        success: false,
        error: `Inbound authentication failed (DMARC not aligned): SPF=${authResults.spf}, DKIM=${authResults.dkim}, DMARC=${authResults.dmarc}`,
        warnings,
      }
    }
    if (authResults.dmarc !== 'pass') {
      warnings.push(`Inbound mail is not DMARC-aligned (SPF=${authResults.spf}, DKIM=${authResults.dkim}); delivered because requireAuth is disabled`)
    }

    // ── Step 4: Resolve recipients to NOSTR pubkeys ─────────────────────
    const toAddresses = extractAddresses(parsed.to)
    const ccAddresses = extractAddresses(parsed.cc)
    const recipientMappings = new Map<string, { pubkey: string; relay?: string }>()
    const resolvedRecipients: Array<{ pubkey: string; relays: string[] }> = []

    for (const email of [...toAddresses, ...ccAddresses]) {
      // F-BRIDGE-DOS-01: bound NIP-05 resolutions per recipient per window
      // (each resolution is an outbound fetch — limit SSRF amplification).
      if (!recipientRate.check(email)) {
        warnings.push(`Rate limit exceeded resolving ${email}; skipped`)
        continue
      }
      const resolved = await resolveEmailToNostr(email)
      if (resolved) {
        recipientMappings.set(email, { pubkey: resolved.pubkey, relay: resolved.relays[0] })
        resolvedRecipients.push({ pubkey: resolved.pubkey, relays: resolved.relays })
      } else {
        warnings.push(`Could not resolve ${email} to NOSTR pubkey`)
      }
    }

    if (resolvedRecipients.length === 0) {
      return { success: false, error: 'No recipients could be resolved to NOSTR pubkeys', warnings }
    }

    // ── Step 5: Convert body (HTML -> Markdown if needed) ───────────────
    let body: string
    let contentType: 'text/plain' | 'text/markdown'

    if (parsed.html) {
      body = htmlToMarkdown(parsed.html as string)
      contentType = 'text/markdown'
    } else {
      body = parsed.text ?? ''
      contentType = 'text/plain'
    }

    // ── Step 6: Encrypt + upload attachments to Blossom ─────────────────
    // Per NIP §"Attachment Encryption" (DEC-009 ripple): files MUST be
    // encrypted before upload to a public Blossom server. We use AES-256-GCM
    // with a fresh random key per attachment; the key (hex) is carried in
    // the encrypted rumor as ["attachment-key", hash, hexKey].
    const attachments = extractAttachments(parsed)
    const attachmentHashes = new Map<string, { hash: string; size: number; key?: string }>()

    for (const att of attachments) {
      try {
        const encrypted = encryptAttachment(Buffer.from(att.data))
        const uploadResult = await uploadToBlossom(
          encrypted.blob,
          'application/octet-stream',
          config.blossomServers,
        )
        if (uploadResult) {
          attachmentHashes.set(att.filename, {
            hash: uploadResult.hash,
            size: uploadResult.size,
            key: encrypted.keyHex,
          })
        } else {
          warnings.push(`Failed to upload attachment: ${att.filename}`)
        }
      } catch (err) {
        warnings.push(`Attachment upload error for ${att.filename}: ${String(err)}`)
      }
    }

    // ── Step 7: Resolve email threading to NOSTR threading ──────────────
    const messageId = sanitizeMessageId(parsed.messageId ?? undefined) ?? parsed.messageId
    const inReplyTo = sanitizeMessageId(parsed.inReplyTo ?? undefined) ?? parsed.inReplyTo
    const references = sanitizeMessageIdList(parsed.references as string[] | string | undefined)
      .filter(Boolean)

    const threadMapping = await threadingEmailToNostr(
      messageId,
      inReplyTo,
      references.length > 0 ? references : undefined,
      resolveMessageId,
    )

    // ── Step 8: Build bridged message ───────────────────────────────────
    const bridgedMessage: BridgedMessage = {
      fromEmail: fromAddress,
      fromName,
      toEmails: toAddresses,
      ccEmails: ccAddresses,
      bccEmails: [], // BCC not visible in received headers
      subject: sanitizeHeaderValue(parsed.subject ?? '', 512),
      body,
      contentType,
      attachments,
      messageId,
      inReplyTo,
      references,
      authResults,
      originalHeaders: extractRelevantHeaders(parsed.headers),
    }

    // ── Step 9: Create kind 1400 rumor ────────────────────────────────────
    const rumor = mimeToRumor(
      bridgedMessage,
      bridgePubkey,
      recipientMappings,
      attachmentHashes,
      threadMapping,
    )

    // ── Step 10: Gift wrap and publish to each recipient's relays ───────
    for (const recipient of resolvedRecipients) {
      try {
        const wrap = await giftWrapRumor(rumor, bridgePrivkey, recipient.pubkey)
        const relays = recipient.relays.length > 0
          ? recipient.relays
          : await fetchInboxRelays(recipient.pubkey, config.relays)

        await publishToRelays(wrap, relays.length > 0 ? relays : config.relays)
      } catch (err) {
        warnings.push(`Failed to publish to ${recipient.pubkey.slice(0, 16)}...: ${String(err)}`)
      }
    }

    // ── Step 11: Store Message-ID mapping for future threading ──────────
    if (messageId) {
      const pseudoEventId = createHash('sha256')
        .update(messageId)
        .update(bridgePubkey)
        .digest('hex')
      storeMessageIdMapping(messageId, pseudoEventId)
    }

    return {
      success: true,
      data: { recipientCount: resolvedRecipients.length, attachmentCount: attachmentHashes.size },
      warnings,
    }

  } catch (err) {
    return {
      success: false,
      error: `Inbound processing error: ${err instanceof Error ? err.message : String(err)}`,
      warnings,
    }
  }
}

// ─── NIP-59 Gift Wrapping ───────────────────────────────────────────────────

/**
 * Seal and gift-wrap a kind 1400 rumor for a recipient.
 *
 * Three-layer NIP-59 encryption:
 * 1. Rumor (kind 1400, unsigned) - the mail content
 * 2. Seal (kind 13, signed by bridge) - encrypts rumor to recipient
 * 3. Gift Wrap (kind 1059, signed by ephemeral key) - encrypts seal to recipient
 *
 * Timestamps are randomized +/- 2 days.
 *
 * @param rumor - Kind 1400 mail rumor.
 * @param senderPrivkey - Bridge private key (32 bytes).
 * @param recipientPubkey - Recipient hex public key.
 * @returns Signed kind 1059 gift wrap event.
 */
async function giftWrapRumor(
  rumor: MailRumor,
  senderPrivkey: Uint8Array,
  recipientPubkey: string,
): Promise<ReturnType<typeof finalizeEvent>> {
  const now = Math.floor(Date.now() / 1000)

  // Layer 1: Serialize rumor
  const rumorJson = JSON.stringify(rumor)

  // Layer 2: Seal (kind 13)
  const sealConvKey = nip44.v2.utils.getConversationKey(senderPrivkey, recipientPubkey)
  const encryptedRumor = nip44.v2.encrypt(rumorJson, sealConvKey)

  const seal = finalizeEvent({
    kind: 13,
    created_at: now + randomTimestampOffset(),
    tags: [],
    content: encryptedRumor,
  }, senderPrivkey)

  // Layer 3: Gift Wrap (kind 1059)
  const ephemeralPrivkey = generateSecretKey()
  const wrapConvKey = nip44.v2.utils.getConversationKey(ephemeralPrivkey, recipientPubkey)
  const encryptedSeal = nip44.v2.encrypt(JSON.stringify(seal), wrapConvKey)

  const wrap = finalizeEvent({
    kind: 1059,
    created_at: now + randomTimestampOffset(),
    tags: [['p', recipientPubkey]],
    content: encryptedSeal,
  }, ephemeralPrivkey)

  // Zero ephemeral key material after use (DEC-014)
  ephemeralPrivkey.fill(0)

  return wrap
}

/**
 * Generate a random timestamp offset within +/- 2 days (CSPRNG, uniform).
 */
function randomTimestampOffset(): number {
  const maxOffset = 172800 // 2 days in seconds
  const buf = new Uint32Array(1)
  crypto.getRandomValues(buf)
  const normalized = (buf[0]! / 0x100000000) * 2 - 1
  return Math.floor(normalized * maxOffset)
}

// ─── Blossom Upload ─────────────────────────────────────────────────────────

/**
 * Upload a file to Blossom servers.
 *
 * Tries each server in order until one succeeds. Returns the SHA-256 hash
 * and size of the uploaded file.
 *
 * @param data - File data.
 * @param mimeType - MIME type.
 * @param servers - Blossom server URLs to try.
 * @returns Hash and size on success, null on failure.
 */
async function uploadToBlossom(
  data: Uint8Array,
  mimeType: string,
  servers: string[],
): Promise<{ hash: string; size: number } | null> {
  for (const server of servers) {
    try {
      const url = `${server.replace(/\/$/, '')}/upload`
      const response = await fetch(url, {
        method: 'PUT',
        headers: {
          'Content-Type': mimeType,
          'Content-Length': String(data.length),
        },
        body: data as unknown as BodyInit,
        signal: AbortSignal.timeout(60000),
      })

      if (response.ok) {
        const result = await response.json() as { sha256?: string; size?: number }
        if (result.sha256) {
          return { hash: result.sha256, size: result.size ?? data.length }
        }
      }
    } catch {
      continue // Try next server
    }
  }

  return null
}

// ─── Relay Publishing ───────────────────────────────────────────────────────

/**
 * Publish a signed event to multiple NOSTR relays.
 *
 * Opens WebSocket connections, sends the event, and waits for OK responses.
 * Uses a 10-second timeout per relay.
 *
 * @param event - Signed NOSTR event.
 * @param relayUrls - Relay WebSocket URLs.
 */
async function publishToRelays(
  event: ReturnType<typeof finalizeEvent>,
  relayUrls: string[],
): Promise<void> {
  const message = JSON.stringify(['EVENT', event])

  // F-SSRF-02: relay URLs may originate from attacker-controlled NIP-05
  // responses (resolveEmailToNostr → recipient.relays) or kind-10050 tags.
  // Pass each through the scheme check AND the SSRF resolution guard, so an
  // attacker cannot steer the bridge's WebSocket at an internal service
  // (e.g. wss://169.254.169.254 or ws://localhost). Drop unsafe URLs.
  const safeUrls: string[] = []
  for (const url of relayUrls) {
    const safe = sanitizeWebSocketUrl(url)
    if (typeof safe !== 'string') {
      console.warn(`[inbound] Skipping malformed relay URL: ${String(url).slice(0, 64)}`)
      continue
    }
    try {
      await assertPublicUrl(safe, ['ws:', 'wss:'])
      safeUrls.push(safe)
    } catch (err) {
      console.warn(`[inbound] Skipping non-public relay URL ${safe.slice(0, 64)}: ${err instanceof Error ? err.message : 'blocked'}`)
    }
  }

  const publishPromises = safeUrls.map(async (url) => {
    return new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => {
        ws.close()
        reject(new Error(`Timeout publishing to ${url}`))
      }, 10000)

      let ws: WebSocket

      try {
        ws = new WebSocket(url)
      } catch (err) {
        clearTimeout(timeout)
        reject(err)
        return
      }

      ws.onopen = () => {
        ws.send(message)
      }

      ws.onmessage = (msg) => {
        try {
          const data = JSON.parse(String(msg.data))
          if (Array.isArray(data) && data[0] === 'OK') {
            clearTimeout(timeout)
            ws.close()
            if (data[2] === true) {
              resolve()
            } else {
              reject(new Error(`Relay ${url} rejected event: ${data[3]}`))
            }
          }
        } catch {
          // Ignore parse errors on non-OK messages
        }
      }

      ws.onerror = (err) => {
        clearTimeout(timeout)
        ws.close()
        reject(err)
      }
    })
  })

  // Wait for at least one successful publish
  const results = await Promise.allSettled(publishPromises)
  const successes = results.filter(r => r.status === 'fulfilled')

  if (successes.length === 0) {
    throw new Error('Failed to publish to any relay')
  }

  console.log(`[inbound] Published to ${successes.length}/${relayUrls.length} relays`)
}

// ─── Helper Functions ───────────────────────────────────────────────────────

/**
 * Verify inbound authentication (F-DKIM-01).
 *
 * Primary path: cryptographically verify SPF/DKIM/DMARC locally via the
 * `mailauth` package against the raw RFC822 message and the SMTP session
 * (remote IP + envelope MAIL FROM). This produces our own attestation rather
 * than trusting whatever an upstream hop claims.
 *
 * Fallback path: only when `config.trustedAuthservId` is set do we also honor
 * a matching upstream `Authentication-Results:` header (for deployments that
 * sit behind a verifying MTA). The stronger of the two results wins.
 */
async function verifyInboundAuth(
  rawEmail: Buffer,
  session: { remoteAddress?: string; envelope?: { mailFrom?: false | { address?: string } } },
  headers: Map<string, unknown> | undefined,
  config: BridgeConfig,
): Promise<AuthResults> {
  let local: AuthResults = { spf: 'none', dkim: 'none', dmarc: 'none' }
  try {
    const { authenticate } = await import('mailauth')
    const mailFrom =
      session.envelope && session.envelope.mailFrom && typeof session.envelope.mailFrom === 'object'
        ? session.envelope.mailFrom.address
        : undefined
    const res = (await authenticate(rawEmail, {
      ip: session.remoteAddress,
      sender: mailFrom,
      mta: config.hostname || config.domain,
    })) as {
      spf?: { status?: { result?: string } }
      dmarc?: { status?: { result?: string } }
      dkim?: { results?: Array<{ status?: { result?: string } }> }
    }
    const dkimPass = Array.isArray(res.dkim?.results)
      ? res.dkim!.results.some((r) => r?.status?.result === 'pass')
      : false
    local = {
      spf: normalizeAuthResult(res.spf?.status?.result, 'spf') as AuthResults['spf'],
      dkim: (dkimPass ? 'pass' : normalizeAuthResult(res.dkim?.results?.[0]?.status?.result, 'dkim')) as AuthResults['dkim'],
      dmarc: normalizeAuthResult(res.dmarc?.status?.result, 'dmarc') as AuthResults['dmarc'],
    }
  } catch (err) {
    console.warn(`[inbound] mailauth verification error: ${err instanceof Error ? err.message : 'unknown'}`)
  }

  // Optional upstream-trust fallback.
  const upstream = evaluateUpstreamAuthResults(headers, config)
  return mergeAuthResults(local, upstream)
}

/** Clamp an arbitrary mailauth result string to our AuthResults enum. */
function normalizeAuthResult(value: string | undefined, kind: 'spf' | 'dkim' | 'dmarc'): string {
  const v = (value ?? 'none').toLowerCase()
  const spfAllowed = ['pass', 'fail', 'softfail', 'neutral', 'none', 'temperror', 'permerror']
  const allowed = kind === 'spf' ? spfAllowed : ['pass', 'fail', 'none', 'temperror', 'permerror']
  return allowed.includes(v) ? v : 'none'
}

/** Take the stronger (pass-wins) of two AuthResults. */
function mergeAuthResults(a: AuthResults, b: AuthResults): AuthResults {
  const strongest = (x: string, y: string): string => (x === 'pass' || y === 'pass' ? 'pass' : x !== 'none' ? x : y)
  return {
    spf: strongest(a.spf, b.spf) as AuthResults['spf'],
    dkim: strongest(a.dkim, b.dkim) as AuthResults['dkim'],
    dmarc: strongest(a.dmarc, b.dmarc) as AuthResults['dmarc'],
  }
}

/**
 * Parse a trusted upstream `Authentication-Results:` header (RFC 8601 §5),
 * honored only when its authserv-id matches `config.trustedAuthservId`.
 * Returns all-`none` when no trust is configured.
 */
function evaluateUpstreamAuthResults(
  headers: Map<string, unknown> | undefined,
  config: BridgeConfig,
): AuthResults {
  const defaults: AuthResults = { spf: 'none', dkim: 'none', dmarc: 'none' }

  if (!headers) return defaults
  const trustedAuthservId = config.trustedAuthservId
  if (!trustedAuthservId) return defaults

  // mailparser exposes a single string for repeated headers (semicolon-joined)
  // or an array via getAll-style iteration. Iterate every variant we recognise.
  const candidates: string[] = []
  const single = headers.get('authentication-results')
  if (typeof single === 'string') candidates.push(single)
  // mailparser's `headers` is a Map<string, string|string[]> in current
  // versions; an array form is possible.
  if (Array.isArray(single)) {
    for (const v of single) if (typeof v === 'string') candidates.push(v)
  }

  const results = { ...defaults }
  for (const header of candidates) {
    const trimmed = header.trim()
    // RFC 8601 §2.2: leading authserv-id (token) followed by ';'
    const semiIdx = trimmed.indexOf(';')
    const authservId = (semiIdx >= 0 ? trimmed.slice(0, semiIdx) : trimmed)
      .trim()
      .split(/\s+/)[0]
    if (authservId !== trustedAuthservId) continue

    const body = semiIdx >= 0 ? trimmed.slice(semiIdx + 1) : ''
    const spfMatch = /spf=(pass|fail|softfail|neutral|none|temperror|permerror)/i.exec(body)
    if (spfMatch?.[1]) results.spf = spfMatch[1].toLowerCase() as AuthResults['spf']
    const dkimMatch = /dkim=(pass|fail|none|temperror|permerror)/i.exec(body)
    if (dkimMatch?.[1]) results.dkim = dkimMatch[1].toLowerCase() as AuthResults['dkim']
    const dmarcMatch = /dmarc=(pass|fail|none|temperror|permerror)/i.exec(body)
    if (dmarcMatch?.[1]) results.dmarc = dmarcMatch[1].toLowerCase() as AuthResults['dmarc']
  }
  return results
}

/**
 * Extract email addresses from parsed address objects.
 */
function extractAddresses(field: unknown): string[] {
  if (!field) return []

  if (Array.isArray(field)) {
    return field.flatMap(item => extractAddresses(item))
  }

  if (typeof field === 'string') {
    const addr = sanitizeEmailAddress(field)
    return addr ? [addr] : []
  }

  if (typeof field === 'object' && field !== null && 'value' in field) {
    const values = (field as { value: Array<{ address?: string }> }).value
    return values
      .map(v => sanitizeEmailAddress(v.address))
      .filter((a): a is string => typeof a === 'string')
  }

  return []
}

/**
 * Extract relevant headers from parsed mail for storage.
 */
function extractRelevantHeaders(headers: Map<string, unknown> | undefined): Record<string, string> {
  const result: Record<string, string> = {}
  if (!headers) return result

  const keep = ['message-id', 'date', 'from', 'to', 'cc', 'subject', 'in-reply-to', 'references']
  for (const key of keep) {
    const val = headers.get(key)
    if (typeof val === 'string') {
      if (key === 'message-id' || key === 'in-reply-to') {
        result[key] = sanitizeMessageId(val) ?? sanitizeHeaderValue(val, 512)
      } else if (key === 'references') {
        const refs = sanitizeMessageIdList(val)
        result[key] = refs.length > 0 ? refs.join(' ') : sanitizeHeaderValue(val, 512)
      } else {
        result[key] = sanitizeHeaderValue(val, 512)
      }
    }
  }

  return result
}
