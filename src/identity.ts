// ─── SMTP <-> NOSTR Mail Bridge — Identity Mapping ──────────────────────────
// Resolves email addresses to NOSTR pubkeys (via NIP-05) and vice versa.
// Maintains an in-memory identity mapping database (replace with persistent
// storage for production use).

import { writeFileSync, renameSync, readFileSync, existsSync, mkdirSync } from 'node:fs'
import { dirname } from 'node:path'
import type { ResolvedIdentity, IdentityMapping } from './types.js'
import {
  isSafeHex64,
  sanitizeDomainName,
  sanitizeEmailAddress,
  sanitizeMessageId,
} from './security.js'
import { assertPublicUrl } from './ssrf.js'

// ─── Identity Database (in-memory, optionally file-backed) ───────────────────

/** Email -> NOSTR pubkey mapping (NIP-05 resolved). */
const emailToNostrMap = new Map<string, ResolvedIdentity>()

/** NOSTR pubkey -> bridge email address mapping. */
const nostrToEmailMap = new Map<string, IdentityMapping>()

/** Email Message-ID -> NOSTR event ID mapping (for threading). */
const messageIdMap = new Map<string, string>()

// ─── Persistence (F-BRIDGE-DOS-01) ───────────────────────────────────────────
// When BRIDGE_IDENTITY_STORE is set, the pubkey↔email registry is persisted to
// a JSON file so a restart does not silently re-issue users' deterministic
// fallback addresses. Writes are atomic (temp file + rename). Absent ⇒ the
// previous in-memory-only behavior (fine for dev).

let identityStorePath: string | null = null

/**
 * Initialize the identity store from BRIDGE_IDENTITY_STORE (or an explicit
 * path). Loads existing registrations into memory. Safe to call once at
 * startup; a missing file is not an error.
 */
export function initIdentityStore(path?: string): void {
  identityStorePath = path ?? process.env['BRIDGE_IDENTITY_STORE'] ?? null
  if (!identityStorePath || !existsSync(identityStorePath)) return
  try {
    const data = JSON.parse(readFileSync(identityStorePath, 'utf-8')) as {
      registrations?: IdentityMapping[]
    }
    for (const m of data.registrations ?? []) {
      if (!isSafeHex64(m.pubkey)) continue
      const email = sanitizeEmailAddress(m.emailAddress)
      if (!email) continue
      nostrToEmailMap.set(m.pubkey, { ...m, emailAddress: email })
      emailToNostrMap.set(email, { pubkey: m.pubkey, relays: [], nip05: undefined })
    }
  } catch (err) {
    console.warn(`[identity] failed to load store ${identityStorePath}: ${err instanceof Error ? err.message : 'unknown'}`)
  }
}

/** Atomically persist the registry. No-op when no store path is configured. */
function persistIdentityStore(): void {
  if (!identityStorePath) return
  try {
    mkdirSync(dirname(identityStorePath), { recursive: true })
    const payload = JSON.stringify({ registrations: [...nostrToEmailMap.values()] })
    const tmp = `${identityStorePath}.tmp`
    writeFileSync(tmp, payload, 'utf-8')
    renameSync(tmp, identityStorePath)
  } catch (err) {
    console.warn(`[identity] failed to persist store: ${err instanceof Error ? err.message : 'unknown'}`)
  }
}

/** Test helper: reset all in-memory identity maps and store path. */
export function _resetIdentityStoreForTests(): void {
  emailToNostrMap.clear()
  nostrToEmailMap.clear()
  messageIdMap.clear()
  identityStorePath = null
}

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
    // SSRF guard (F-SSRF-01): the domain is attacker-controlled (it comes from
    // an inbound envelope recipient). Reject any host that resolves to a
    // private / loopback / link-local / metadata range before we fetch.
    await assertPublicUrl(url, ['https:'])
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

  // Persist the registry so the mapping survives a restart (F-BRIDGE-DOS-01).
  persistIdentityStore()
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
 * Fetch inbox relays for a pubkey via NIP-17 kind 10050 (DM Relay List).
 *
 * Per NIP-17, kind 10050 events list the relays where a user expects to
 * receive gift-wrapped DMs/mail. We query a known fallback relay over a
 * one-shot WebSocket subscription, parse the `relay` tags from the
 * returned event, and return them. On error, timeout, or empty result we
 * return _defaultRelays.
 *
 * @param pubkey - Hex public key.
 * @param _defaultRelays - Fallback relay URLs (also used as bootstrap).
 * @returns Array of inbox relay URLs.
 */
export async function fetchInboxRelays(pubkey: string, _defaultRelays: string[]): Promise<string[]> {
  // 1) Local cache hit (e.g. populated by registerBridgeUser).
  const identity = emailToNostrMap.get(pubkey)
  if (identity && identity.relays.length > 0) {
    return identity.relays
  }
  if (!isSafeHex64(pubkey) || _defaultRelays.length === 0) {
    return _defaultRelays
  }

  // 2) Live lookup against the first reachable bootstrap relay.
  const bootstrap = _defaultRelays[0]
  if (typeof bootstrap !== 'string') return _defaultRelays
  return new Promise<string[]>((resolve) => {
    let settled = false
    const done = (value: string[]) => {
      if (settled) return
      settled = true
      try { ws.close() } catch { /* ignore */ }
      resolve(value)
    }
    let ws: WebSocket
    try {
      ws = new WebSocket(bootstrap)
    } catch {
      resolve(_defaultRelays)
      return
    }
    const timer = setTimeout(() => done(_defaultRelays), 5000)
    const subId = `inbox-${Math.random().toString(36).slice(2, 10)}`
    ws.onopen = () => {
      const req = JSON.stringify(['REQ', subId, { authors: [pubkey], kinds: [10050], limit: 1 }])
      ws.send(req)
    }
    ws.onmessage = (msg) => {
      try {
        const data = JSON.parse(String(msg.data))
        if (Array.isArray(data) && data[0] === 'EVENT' && data[1] === subId && data[2]) {
          const event = data[2] as { tags?: unknown }
          const tags = Array.isArray(event.tags) ? event.tags : []
          const relays: string[] = []
          for (const tag of tags) {
            if (Array.isArray(tag) && tag[0] === 'relay' && typeof tag[1] === 'string') {
              relays.push(tag[1])
            }
          }
          clearTimeout(timer)
          done(relays.length > 0 ? relays : _defaultRelays)
        } else if (Array.isArray(data) && data[0] === 'EOSE' && data[1] === subId) {
          clearTimeout(timer)
          done(_defaultRelays)
        }
      } catch {
        // Ignore parse errors on non-EVENT messages.
      }
    }
    ws.onerror = () => {
      clearTimeout(timer)
      done(_defaultRelays)
    }
    ws.onclose = () => {
      clearTimeout(timer)
      done(_defaultRelays)
    }
  })
}
