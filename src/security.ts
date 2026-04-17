// ─── SMTP <-> NOSTR Mail Bridge — Shared Security Helpers ──────────────────
// Conservative normalizers for headers, addresses, IDs, filenames, MIME
// types, and relay / Blossom URLs.

const SAFE_EMAIL_ADDRESS = /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+$/i
const SAFE_HEX64 = /^[0-9a-f]{64}$/i
const SAFE_MIME_TYPE = /^[A-Za-z0-9!#$&^_.+-]+\/[A-Za-z0-9!#$&^_.+-]+$/
const SAFE_DOMAIN_NAME = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$/i

/** Remove CR/LF and other control characters from a header-like string. */
export function sanitizeHeaderValue(value: string, maxLength = 998): string {
  return value
    .replace(/[\u0000-\u001f\u007f]+/g, ' ')
    .replace(/\r\n?|\n/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, maxLength)
}

/** Sanitize a display name for use in a MIME address header. */
export function sanitizeDisplayName(value: string | undefined, maxLength = 128): string | undefined {
  if (!value) return undefined

  const cleaned = sanitizeHeaderValue(value, maxLength)
    .replace(/[<>]/g, '')
    .trim()

  return cleaned || undefined
}

/** Normalize a mailbox address or return null if it is unsafe. */
export function sanitizeEmailAddress(value: string | undefined): string | null {
  if (!value) return null

  const cleaned = sanitizeHeaderValue(value, 320)
    .replace(/^<([^<>]+)>$/, '$1')
    .trim()

  if (!cleaned || /[\s<>"'(),;\\[\]\0]/.test(cleaned)) return null
  if (!SAFE_EMAIL_ADDRESS.test(cleaned)) return null

  return cleaned.toLowerCase()
}

/** Format a safe mailbox header value using a display name if present. */
export function formatMailboxAddress(email: string, displayName?: string): string | null {
  const normalizedEmail = sanitizeEmailAddress(email)
  if (!normalizedEmail) return null

  const normalizedName = sanitizeDisplayName(displayName)
  if (!normalizedName) return normalizedEmail

  return `"${normalizedName.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}" <${normalizedEmail}>`
}

/** Canonicalize a message-id like value, preserving its opaque token. */
export function sanitizeMessageId(value: string | undefined): string | null {
  if (!value) return null

  const cleaned = sanitizeHeaderValue(value, 512)
  const unwrapped = cleaned.match(/^<([^<>]+)>$/)?.[1] ?? cleaned

  if (!unwrapped || /[\s<>\0]/.test(unwrapped)) return null
  if (!/^.+@.+$/.test(unwrapped)) return null

  return `<${unwrapped}>`
}

/** Canonicalize a list of message-id-like tokens from a header. */
export function sanitizeMessageIdList(values: string[] | string | undefined): string[] {
  if (!values) return []

  const raw = Array.isArray(values) ? values : values.split(/[\s,]+/)
  const seen = new Set<string>()
  const result: string[] = []

  for (const token of raw) {
    const normalized = sanitizeMessageId(token)
    if (!normalized || seen.has(normalized)) continue
    seen.add(normalized)
    result.push(normalized)
  }

  return result
}

/** Validate a NOSTR hex identifier. */
export function isSafeHex64(value: string | undefined): value is string {
  return typeof value === 'string' && SAFE_HEX64.test(value)
}

/** Decode a hex string to bytes, rejecting malformed input. */
export function parseHexBytes(value: string | undefined): Uint8Array {
  if (!value || value.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(value)) {
    throw new Error('Invalid hex string')
  }

  const bytes = new Uint8Array(value.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16)
  }
  return bytes
}

/** Sanitize a MIME type, falling back to application/octet-stream. */
export function sanitizeMimeType(value: string | undefined, fallback = 'application/octet-stream'): string {
  if (!value) return fallback

  const cleaned = sanitizeHeaderValue(value, 128).toLowerCase().split(';', 1)[0]!.trim()
  return SAFE_MIME_TYPE.test(cleaned) ? cleaned : fallback
}

/** Sanitize a filename so it cannot smuggle paths or control characters. */
export function sanitizeFilename(value: string | undefined, fallback = 'attachment'): string {
  const cleaned = sanitizeHeaderValue(value ?? '', 255)
  const basename = cleaned.split(/[\\/]/).pop() ?? cleaned
  const safeBase = basename
    .replace(/[\/\\]/g, '_')
    .replace(/[<>:"|?*\u0000-\u001f]/g, '_')
    .replace(/^\.+/, '')
    .trim()

  if (!safeBase) return fallback
  return safeBase.slice(0, 128)
}

/** Validate a DNS hostname / bridge domain value. */
export function sanitizeDomainName(value: string | undefined): string | null {
  if (!value) return null

  const cleaned = sanitizeHeaderValue(value, 253).toLowerCase()
  return SAFE_DOMAIN_NAME.test(cleaned) ? cleaned : null
}

/** Allow only ws/wss relay URLs. */
export function sanitizeWebSocketUrl(value: string | undefined): string | null {
  return sanitizeUrlByScheme(value, new Set(['ws:', 'wss:']))
}

/** Allow only http/https URLs. */
export function sanitizeHttpUrl(value: string | undefined): string | null {
  return sanitizeUrlByScheme(value, new Set(['http:', 'https:']))
}

function sanitizeUrlByScheme(value: string | undefined, allowedSchemes: Set<string>): string | null {
  if (!value) return null

  const cleaned = sanitizeHeaderValue(value, 2048)
  try {
    const url = new URL(cleaned)
    if (!allowedSchemes.has(url.protocol)) return null
    if (url.username || url.password) return null
    return url.toString().replace(/\/$/, '')
  } catch {
    return null
  }
}
