// ─── SMTP <-> NOSTR Mail Bridge — Outbound (NOSTR -> SMTP) ─────────────────
// Subscribes to kind 1059 gift-wrapped events addressed to the bridge pubkey,
// decrypts them, checks for email delivery tags, converts to MIME, and sends
// via SMTP with DKIM signing.

import { createTransport, type Transporter } from 'nodemailer'
import { getPublicKey, verifyEvent } from 'nostr-tools'
import * as nip44 from 'nostr-tools/nip44'
import type { BridgeConfig, MailRumor, OutboundEmail, MimeAttachment } from './types.js'
import { rumorToMime, buildMimeAttachments } from './convert.js'
import { resolveNostrToEmail, isBridgeAddress, generateMessageId } from './identity.js'

/** Active WebSocket subscriptions. */
const activeSubscriptions: WebSocket[] = []

/** Nodemailer transport instance. */
let transport: Transporter | null = null

/**
 * Start the outbound NOSTR -> SMTP subscriber.
 *
 * Connects to configured relays, subscribes to kind 1059 events tagged
 * with the bridge's pubkey. When a gift-wrapped event arrives:
 * 1. Decrypt the gift wrap (NIP-59 three-layer)
 * 2. Check for ["email-to", address] tag in the rumor
 * 3. Convert rumor to MIME email
 * 4. DKIM sign and send via SMTP
 *
 * @param config - Bridge configuration.
 */
export function startOutboundSubscriber(config: BridgeConfig): void {
  const bridgePrivkey = hexToBytes(config.bridgePrivateKeyHex)
  const bridgePubkey = getPublicKey(bridgePrivkey)

  // Initialize SMTP transport for outbound sending
  transport = createTransport({
    host: config.outboundSmtp.host,
    port: config.outboundSmtp.port,
    secure: config.outboundSmtp.secure,
    auth: config.outboundSmtp.auth,
    dkim: config.dkimPrivateKey ? {
      domainName: config.domain,
      keySelector: config.dkimSelector,
      privateKey: config.dkimPrivateKey,
    } : undefined,
  })

  console.log(`[outbound] SMTP transport configured for ${config.outboundSmtp.host}:${config.outboundSmtp.port}`)

  // Subscribe to each relay
  for (const relayUrl of config.relays) {
    connectAndSubscribe(relayUrl, bridgePrivkey, bridgePubkey, config)
  }
}

/**
 * Stop all outbound subscriptions and close SMTP transport.
 */
export async function stopOutboundSubscriber(): Promise<void> {
  for (const ws of activeSubscriptions) {
    ws.close()
  }
  activeSubscriptions.length = 0

  if (transport) {
    transport.close()
    transport = null
  }

  console.log('[outbound] All subscriptions and SMTP transport closed')
}

/**
 * Connect to a relay and subscribe to gift-wrapped events for the bridge.
 */
function connectAndSubscribe(
  relayUrl: string,
  bridgePrivkey: Uint8Array,
  bridgePubkey: string,
  config: BridgeConfig,
): void {
  let ws: WebSocket
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null

  function connect(): void {
    try {
      ws = new WebSocket(relayUrl)
    } catch (err) {
      console.error(`[outbound] Failed to connect to ${relayUrl}:`, err)
      scheduleReconnect()
      return
    }

    ws.onopen = () => {
      console.log(`[outbound] Connected to ${relayUrl}`)

      // Subscribe to kind 1059 events tagged with our pubkey
      const subId = `bridge-${Date.now()}`
      const filter = {
        kinds: [1059],
        '#p': [bridgePubkey],
        since: Math.floor(Date.now() / 1000) - 3600, // Last hour
      }

      ws.send(JSON.stringify(['REQ', subId, filter]))
      activeSubscriptions.push(ws)
    }

    ws.onmessage = (msg) => {
      try {
        const data = JSON.parse(String(msg.data)) as unknown[]
        if (!Array.isArray(data)) return

        if (data[0] === 'EVENT' && data[2]) {
          const event = data[2] as {
            kind: number
            pubkey: string
            created_at: number
            tags: string[][]
            content: string
            id: string
            sig: string
          }

          // Process the gift-wrapped event
          processGiftWrap(event, bridgePrivkey, bridgePubkey, config)
            .catch(err => console.error('[outbound] Processing error:', err))
        }
      } catch {
        // Ignore parse errors
      }
    }

    ws.onclose = () => {
      const idx = activeSubscriptions.indexOf(ws)
      if (idx !== -1) activeSubscriptions.splice(idx, 1)
      console.log(`[outbound] Disconnected from ${relayUrl}`)
      scheduleReconnect()
    }

    ws.onerror = (err) => {
      console.error(`[outbound] WebSocket error on ${relayUrl}:`, err)
    }
  }

  function scheduleReconnect(): void {
    if (reconnectTimer) return
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null
      console.log(`[outbound] Reconnecting to ${relayUrl}...`)
      connect()
    }, 5000)
  }

  connect()
}

/**
 * Process a received kind 1059 gift-wrapped event.
 *
 * Decrypts the three NIP-59 layers, extracts the kind 1111 rumor,
 * checks for email delivery tags, and sends via SMTP if applicable.
 *
 * @param event - The received kind 1059 event.
 * @param bridgePrivkey - Bridge private key for decryption.
 * @param bridgePubkey - Bridge public key hex.
 * @param config - Bridge configuration.
 */
async function processGiftWrap(
  event: {
    kind: number
    pubkey: string
    created_at: number
    tags: string[][]
    content: string
    id: string
    sig: string
  },
  bridgePrivkey: Uint8Array,
  bridgePubkey: string,
  config: BridgeConfig,
): Promise<void> {
  // ── Step 1: Verify the gift wrap event signature ──────────────────────
  if (!verifyEvent(event)) {
    console.warn('[outbound] Invalid gift wrap signature, discarding')
    return
  }

  // ── Step 2: Decrypt gift wrap layer (ECDH with ephemeral key) ─────────
  let sealJson: string
  try {
    const wrapConvKey = nip44.v2.utils.getConversationKey(bridgePrivkey, event.pubkey)
    sealJson = nip44.v2.decrypt(event.content, wrapConvKey)
  } catch (err) {
    console.warn('[outbound] Failed to decrypt gift wrap:', err)
    return
  }

  // ── Step 3: Parse and verify the seal (kind 13) ───────────────────────
  let seal: {
    kind: number
    pubkey: string
    created_at: number
    tags: string[][]
    content: string
    id: string
    sig: string
  }
  try {
    seal = JSON.parse(sealJson)
  } catch {
    console.warn('[outbound] Invalid seal JSON')
    return
  }

  if (seal.kind !== 13) {
    console.warn(`[outbound] Unexpected seal kind: ${seal.kind}`)
    return
  }

  if (!verifyEvent(seal)) {
    console.warn('[outbound] Invalid seal signature')
    return
  }

  const senderPubkey = seal.pubkey

  // ── Step 4: Decrypt seal layer to get the rumor ───────────────────────
  let rumorJson: string
  try {
    const sealConvKey = nip44.v2.utils.getConversationKey(bridgePrivkey, senderPubkey)
    rumorJson = nip44.v2.decrypt(seal.content, sealConvKey)
  } catch (err) {
    console.warn('[outbound] Failed to decrypt seal:', err)
    return
  }

  // ── Step 5: Parse the rumor (kind 1111) ─────────────────────────────────
  let rumor: MailRumor
  try {
    rumor = JSON.parse(rumorJson)
  } catch {
    console.warn('[outbound] Invalid rumor JSON')
    return
  }

  if (rumor.kind !== 1111) {
    console.warn(`[outbound] Unexpected rumor kind: ${rumor.kind}, expected 15`)
    return
  }

  // ── Step 6: Check for email delivery tags ─────────────────────────────
  const emailToTags = rumor.tags.filter(t => t[0] === 'email-to')

  if (emailToTags.length === 0) {
    // No email delivery requested — this is a regular NOSTR Mail, skip
    console.log('[outbound] No email-to tags, ignoring event')
    return
  }

  const emailRecipients = emailToTags
    .map(t => t[1])
    .filter((addr): addr is string => typeof addr === 'string')

  if (emailRecipients.length === 0) {
    console.warn('[outbound] email-to tags present but no valid addresses')
    return
  }

  console.log(`[outbound] Processing mail from ${senderPubkey.slice(0, 16)}... to ${emailRecipients.join(', ')}`)

  // ── Step 7: Resolve sender pubkey to bridge email ─────────────────────
  const senderEmail = resolveNostrToEmail(senderPubkey, config.domain)
  // Sender name from kind 0 would be fetched in production
  const senderName = undefined

  // ── Step 8: Build recipient mapping for email headers ─────────────────
  const pubkeyToEmail = new Map<string, string>()
  for (const tag of rumor.tags) {
    if (tag[0] !== 'p') continue
    const pk = tag[1]
    if (!pk) continue
    // Check if any email-to tags match this recipient
    const emailTag = emailToTags.find(t => t[1])
    if (emailTag?.[1]) {
      pubkeyToEmail.set(pk, emailTag[1])
    }
  }

  // Also add direct email-to addresses
  for (const addr of emailRecipients) {
    // Find the pubkey for this address (or use a placeholder)
    if (!Array.from(pubkeyToEmail.values()).includes(addr)) {
      pubkeyToEmail.set(`email:${addr}`, addr)
    }
  }

  // ── Step 9: Download attachments from Blossom ─────────────────────────
  const attachmentTags = rumor.tags.filter(t => t[0] === 'attachment')
  const blossomTags = rumor.tags.filter(t => t[0] === 'blossom')
  const blossomUrls = blossomTags.flatMap(t => t.slice(1)).concat(config.blossomServers)

  let downloadedAttachments: MimeAttachment[] = []
  if (attachmentTags.length > 0) {
    try {
      downloadedAttachments = await buildMimeAttachments(attachmentTags, blossomUrls)
    } catch (err) {
      console.warn('[outbound] Attachment download failed:', err)
    }
  }

  // ── Step 10: Convert rumor to MIME email ──────────────────────────────
  const email = rumorToMime(
    rumor,
    pubkeyToEmail,
    senderEmail,
    senderName,
    downloadedAttachments,
  )

  // Override To with the explicit email-to addresses
  email.to = emailRecipients

  // Generate a proper Message-ID
  email.messageId = generateMessageId(event.id, config.domain)

  // ── Step 11: Send via SMTP ────────────────────────────────────────────
  try {
    await sendEmail(email)
    console.log(`[outbound] Email sent successfully to ${emailRecipients.join(', ')}`)
  } catch (err) {
    console.error(`[outbound] Failed to send email:`, err)
  }
}

/**
 * Send an outbound email via the SMTP transport.
 *
 * @param email - Outbound email structure.
 */
async function sendEmail(email: OutboundEmail): Promise<void> {
  if (!transport) {
    throw new Error('SMTP transport not initialized')
  }

  const mailOptions = {
    from: email.from,
    to: email.to.join(', '),
    cc: email.cc.length > 0 ? email.cc.join(', ') : undefined,
    subject: email.subject,
    text: email.text,
    html: email.html,
    messageId: email.messageId,
    inReplyTo: email.inReplyTo,
    references: email.references,
    headers: email.headers,
    attachments: email.attachments.map(att => ({
      filename: att.filename,
      content: Buffer.from(att.content),
      contentType: att.contentType,
      cid: att.cid,
    })),
  }

  const info = await transport.sendMail(mailOptions)
  console.log(`[outbound] Message sent: ${info.messageId}`)
}

/**
 * Convert a hex string to Uint8Array.
 */
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return bytes
}
