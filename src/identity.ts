// ─── SMTP <-> NOSTR Mail Bridge — Identity Mapping ──────────────────────────
// Resolves email addresses to NOSTR pubkeys (via NIP-05) and vice versa.
// Maintains an in-memory identity mapping database (replace with persistent
// storage for production use).

import type { ResolvedIdentity, IdentityMapping } from './types.js'
import {
  isSafeHex64,
  sanitizeDomainName,
  sanitizeEmailAddress,
  sanitizeMessageId,
} from './security.js'

// ─── In-Memory Identity Database ────────────────────────────────────────────

/** Email -> NOSTR pubkey mapping (NIP-05 resolved). */
const emailToNostrMap = new Map<string, ResolvedIdentity>()

/** NOSTR pubkey -> bridge email address mapping. */
const nostrToEmailMap = new Map<string, IdentityMapping>()

/** Email Message-ID -> NOSTR event ID mapping (for threading). */
const messageIdMap = new Map<string, string>()

// ─── NIP-05 Resolution ─────────────────────────────────────────────────────

/**
 * Resolve an email address to a NOSTR pubkey via NIP-05.
 *
 * NIP-05 uses the format `user@domain` and resolves via:
 *   GET https://domain/.well-known/nostr.json?name=user
 *
 * The response contains `{ names: { user: <hex-pubkey> }, relays: { <pubkey>: [...] } }`
 *
 * Falls back to the bridge identity database if NIP-05 resolution fails.
 *
 * @param email - Email address (user@domain format).
 * @returns Resolved identity with pubkey and relays, or null if unresolvable.
 */
export async function resolveEmailToNostr(email: string): Promise<ResolvedIdentity | null> {
  const normalizedEmail = sanitizeEmailAddress(email)
  if (!normalizedEmail) return null

  // Check cache first
  const cached = emailToNostrMap.get(normalizedEmail)
  if (cached) return cached

  // Parse email address
  const atIndex = normalizedEmail.lastIndexOf('@')
  if (atIndex === -1) return null

  const user = normalizedEmail.slice(0, atIndex)
  const domain = sanitizeDomainName(normalizedEmail.slice(atIndex + 1))
  if (!domain) return null

  // Attempt NIP-05 resolution
  try {
    const url = `https://${domain}/.well-known/nostr.json?name=${encodeURIComponent(user)}`
    const response = await fetch(url, {
      signal: AbortSignal.timeout(10000),
      headers: { 'Accept': 'application/json' },
    })

    if (!response.ok) return null

    const data = await response.json() as {
      names?: Record<string, string>
      relays?: Record<string, string[]>
    }

    const pubkey = data.names?.[user]
    if (!pubkey || !/^[0-9a-f]{64}$/.test(pubkey)) return null

    const relays = data.relays?.[pubkey] ?? []

    const identity: ResolvedIdentity = {
      pubkey,
      relays,
      nip05: `${user}@${domain}`,
    }

    // Cache the result
    emailToNostrMap.set(normalizedEmail, identity)
    return identity

  } catch {
    // NIP-05 resolution failed — check local mapping
    return null
  }
}

/**
 * Resolve a NOSTR pubkey to a bridge-assigned email address.
 *
 * If the pubkey has a registered bridge email, returns it.
 * Otherwise, generates a deterministic address from the pubkey:
 *   npub-prefix@bridge-domain
 *
 * @param pubkey - Hex public key.
 * @param bridgeDomain - Bridge's email domain.
 * @returns Email address for the pubkey.
 */
export function resolveNostrToEmail(pubkey: string, bridgeDomain: string): string {
  if (!isSafeHex64(pubkey)) {
    throw new Error('Invalid NOSTR pubkey')
  }

  const safeDomain = sanitizeDomainName(bridgeDomain)
  if (!safeDomain) {
    throw new Error('Invalid bridge domain')
  }

  // Check registered mapping
  const mapping = nostrToEmailMap.get(pubkey)
  if (mapping) {
    mapping.lastUsedAt = Math.floor(Date.now() / 1000)
    return mapping.emailAddress
  }

  // Generate deterministic address from pubkey (first 20 hex chars)
  return `${pubkey.slice(0, 20)}@${safeDomain}`
}

/**
 * Register a bridge user mapping (NOSTR pubkey <-> email address).
 *
 * This creates a persistent (in-memory for reference impl) mapping between
 * a NOSTR identity and a bridge-assigned email address. Used when NOSTR users
 * want a stable email address for receiving bridged mail.
 *
 * @param pubkey - Hex public key.
 * @param emailAddress - Assigned email address.
 */
export function registerBridgeUser(pubkey: string, emailAddress: string): void {
  if (!isSafeHex64(pubkey)) {
    throw new Error('Invalid NOSTR pubkey')
  }

  const normalizedEmail = sanitizeEmailAddress(emailAddress)
  if (!normalizedEmail) {
    throw new Error('Invalid bridge email address')
  }

  const now = Math.floor(Date.now() / 1000)

  nostrToEmailMap.set(pubkey, {
    pubkey,
    emailAddress: normalizedEmail,
    createdAt: now,
    lastUsedAt: now,
  })

  // Reverse mapping for inbound resolution
  emailToNostrMap.set(normalizedEmail, {
    pubkey,
    relays: [],
    nip05: undefined,
  })
}

/**
 * Store a Message-ID <-> NOSTR event ID mapping for threading.
 *
 * When an inbound email is converted to a NOSTR event, we store the
 * mapping so that future replies (referencing the Message-ID) can be
 * threaded to the correct NOSTR event.
 *
 * @param messageId - Email Message-ID header value.
 * @param eventId - NOSTR event ID.
 */
export function storeMessageIdMapping(messageId: string, eventId: string): void {
  const normalizedMessageId = sanitizeMessageId(messageId)
  if (!normalizedMessageId || !isSafeHex64(eventId)) return

  messageIdMap.set(normalizedMessageId, eventId)
}

/**
 * Resolve an email Message-ID to a NOSTR event ID.
 *
 * @param messageId - Email Message-ID header value.
 * @returns NOSTR event ID, or undefined if not found.
 */
export async function resolveMessageId(messageId: string): Promise<string | undefined> {
  const normalizedMessageId = sanitizeMessageId(messageId)
  if (!normalizedMessageId) return undefined

  return messageIdMap.get(normalizedMessageId)
}

/**
 * Store a NOSTR event ID -> Message-ID mapping (reverse direction).
 *
 * Used for outbound: when a NOSTR event is converted to email, we need
 * to generate a Message-ID and store the reverse mapping.
 *
 * @param eventId - NOSTR event ID.
 * @param bridgeDomain - Bridge domain for Message-ID generation.
 * @returns Generated Message-ID.
 */
export function generateMessageId(eventId: string, bridgeDomain: string): string {
  if (!isSafeHex64(eventId)) {
    throw new Error('Invalid NOSTR event ID')
  }

  const safeDomain = sanitizeDomainName(bridgeDomain)
  if (!safeDomain) {
    throw new Error('Invalid bridge domain')
  }

  const msgId = `<${eventId}@${safeDomain}>`
  messageIdMap.set(msgId, eventId)
  return msgId
}

/**
 * Get all registered bridge users.
 * @returns Array of identity mappings.
 */
export function getRegisteredUsers(): IdentityMapping[] {
  return Array.from(nostrToEmailMap.values())
}

/**
 * Check if an email address is managed by this bridge.
 * @param email - Email address to check.
 * @param bridgeDomain - Bridge domain.
 * @returns True if the address belongs to this bridge.
 */
export function isBridgeAddress(email: string, bridgeDomain: string): boolean {
  const domain = sanitizeDomainName(email.split('@')[1])
  const safeBridgeDomain = sanitizeDomainName(bridgeDomain)
  return domain !== null && safeBridgeDomain !== null && domain === safeBridgeDomain
}

/**
 * Fetch inbox relays for a pubkey via NIP-65 (kind 10002).
 *
 * In production, this queries relays for the user's kind 10002 event
 * and extracts relay URLs tagged as read/inbox. For the reference
 * implementation, we return an empty array (callers should fall back
 * to default relays).
 *
 * @param pubkey - Hex public key.
 * @param _defaultRelays - Fallback relay URLs.
 * @returns Array of inbox relay URLs.
 */
export async function fetchInboxRelays(pubkey: string, _defaultRelays: string[]): Promise<string[]> {
  // In production, query kind 10002 events for this pubkey.
  // For reference implementation, return defaults.
  const identity = emailToNostrMap.get(pubkey)
  if (identity && identity.relays.length > 0) {
    return identity.relays
  }
  return _defaultRelays
}
