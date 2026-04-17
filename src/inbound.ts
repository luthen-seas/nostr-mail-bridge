// ─── SMTP <-> NOSTR Mail Bridge — Inbound (SMTP -> NOSTR) ──────────────────
// Receives email via SMTP, converts to NOSTR Mail kind 1400 events, and
// publishes to recipient's relays via NIP-59 gift wrapping.

import { SMTPServer } from 'smtp-server'
import { simpleParser } from 'mailparser'
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools'
import * as nip44 from 'nostr-tools/nip44'
import { createHash } from 'node:crypto'
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
} from './security.js'

/** Active SMTP server instance. */
let smtpServer: SMTPServer | null = null

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

  smtpServer = new SMTPServer({
    name: config.hostname,
    size: config.maxMessageSize,
    authOptional: true,
    disabledCommands: ['AUTH'], // No auth needed for inbound relay
    secure: false, // STARTTLS handled separately in production

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
    // ── Step 1: Parse MIME ───────────────────────────────────────────────
    const parsed = await simpleParser(rawEmail)

    // ── Step 2: Extract sender info ─────────────────────────────────────
    const fromAddress = sanitizeEmailAddress(parsed.from?.value[0]?.address)
    if (!fromAddress) {
      return { success: false, error: 'No From address in email', warnings }
    }

    const fromName = parsed.from?.value[0]?.name
      ? sanitizeHeaderValue(parsed.from.value[0].name, 128)
      : undefined

    // ── Step 3: Evaluate authentication (SPF/DKIM/DMARC) ───────────────
    const authResults = evaluateAuthResults(parsed.headers, session.remoteAddress)

    if (config.requireAuth && authResults.dkim !== 'pass' && authResults.spf !== 'pass') {
      return {
        success: false,
        error: `Email authentication failed: SPF=${authResults.spf}, DKIM=${authResults.dkim}`,
        warnings,
      }
    }

    // ── Step 4: Resolve recipients to NOSTR pubkeys ─────────────────────
    const toAddresses = extractAddresses(parsed.to)
    const ccAddresses = extractAddresses(parsed.cc)
    const recipientMappings = new Map<string, { pubkey: string; relay?: string }>()
    const resolvedRecipients: Array<{ pubkey: string; relays: string[] }> = []

    for (const email of [...toAddresses, ...ccAddresses]) {
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

    // ── Step 6: Extract and upload attachments to Blossom ───────────────
    const attachments = extractAttachments(parsed)
    const attachmentHashes = new Map<string, { hash: string; size: number }>()

    for (const att of attachments) {
      try {
        const uploadResult = await uploadToBlossom(att.data, att.mimeType, config.blossomServers)
        if (uploadResult) {
          attachmentHashes.set(att.filename, uploadResult)
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

  const publishPromises = relayUrls.map(async (url) => {
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
 * Evaluate email authentication from headers and session info.
 * Parses Authentication-Results header if present.
 */
function evaluateAuthResults(
  headers: Map<string, unknown> | undefined,
  _remoteAddress?: string,
): AuthResults {
  const defaults: AuthResults = { spf: 'none', dkim: 'none', dmarc: 'none' }

  if (!headers) return defaults

  const authHeader = headers.get('authentication-results')
  if (typeof authHeader !== 'string') return defaults

  const results = { ...defaults }

  // Parse SPF result
  const spfMatch = /spf=(pass|fail|softfail|neutral|none|temperror|permerror)/i.exec(authHeader)
  if (spfMatch?.[1]) {
    results.spf = spfMatch[1].toLowerCase() as AuthResults['spf']
  }

  // Parse DKIM result
  const dkimMatch = /dkim=(pass|fail|none|temperror|permerror)/i.exec(authHeader)
  if (dkimMatch?.[1]) {
    results.dkim = dkimMatch[1].toLowerCase() as AuthResults['dkim']
  }

  // Parse DMARC result
  const dmarcMatch = /dmarc=(pass|fail|none|temperror|permerror)/i.exec(authHeader)
  if (dmarcMatch?.[1]) {
    results.dmarc = dmarcMatch[1].toLowerCase() as AuthResults['dmarc']
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
