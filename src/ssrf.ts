// ─── SMTP <-> NOSTR Mail Bridge — SSRF Guards ──────────────────────────────
// Every outbound request whose host derives from untrusted input (NIP-05
// domains, kind-10050 relay hints, rumor `blossom` tags) MUST pass through
// these guards before a fetch()/WebSocket() is opened. We reject:
//   - IP literals and hostnames that resolve into private / loopback /
//     link-local / ULA / CGNAT / documentation / metadata ranges, and
//   - localhost / *.local / *.internal style names.
//
// Resolution-then-check closes direct-IP and static-DNS SSRF (e.g.
// 169.254.169.254 cloud metadata, 127.0.0.1, 10.0.0.0/8). For full
// DNS-rebinding (TOCTOU) safety, callers SHOULD additionally pin the
// resolved address for the connection; `resolvePublicAddresses` returns the
// vetted addresses so a pinning dispatcher can be layered on later.

import { isIP } from 'node:net'
import { lookup } from 'node:dns/promises'

/** Thrown when a host is rejected as non-public (SSRF guard). */
export class BlockedHostError extends Error {
  constructor(host: string, reason: string) {
    super(`Blocked non-public host "${host}": ${reason}`)
    this.name = 'BlockedHostError'
  }
}

// ── IPv4 ────────────────────────────────────────────────────────────────────

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split('.')
  if (parts.length !== 4) return null
  let value = 0
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null
    const n = Number(part)
    if (n > 255) return null
    value = (value << 8) | n
  }
  return value >>> 0
}

interface Cidr4 {
  base: number
  bits: number
}

function cidr4(ip: string, bits: number): Cidr4 {
  return { base: ipv4ToInt(ip)!, bits }
}

// Non-public IPv4 ranges (RFC 1918, 5735, 6598, 3927, multicast, reserved…).
const FORBIDDEN_V4: Cidr4[] = [
  cidr4('0.0.0.0', 8), // "this" network / unspecified
  cidr4('10.0.0.0', 8), // private
  cidr4('100.64.0.0', 10), // CGNAT
  cidr4('127.0.0.0', 8), // loopback
  cidr4('169.254.0.0', 16), // link-local (incl. 169.254.169.254 metadata)
  cidr4('172.16.0.0', 12), // private
  cidr4('192.0.0.0', 24), // IETF protocol assignments
  cidr4('192.0.2.0', 24), // TEST-NET-1 (documentation)
  cidr4('192.168.0.0', 16), // private
  cidr4('198.18.0.0', 15), // benchmarking
  cidr4('198.51.100.0', 24), // TEST-NET-2
  cidr4('203.0.113.0', 24), // TEST-NET-3
  cidr4('224.0.0.0', 4), // multicast
  cidr4('240.0.0.0', 4), // reserved (incl. 255.255.255.255)
]

function v4InCidr(value: number, { base, bits }: Cidr4): boolean {
  if (bits === 0) return true
  const mask = bits === 32 ? 0xffffffff : (~((1 << (32 - bits)) - 1)) >>> 0
  return (value & mask) === (base & mask)
}

function isForbiddenV4(ip: string): boolean {
  const value = ipv4ToInt(ip)
  if (value === null) return true // unparseable → treat as forbidden (fail closed)
  return FORBIDDEN_V4.some((range) => v4InCidr(value, range))
}

// ── IPv6 ────────────────────────────────────────────────────────────────────

/** Expand an IPv6 address to its 8 16-bit groups (numbers). */
function expandV6(ip: string): number[] | null {
  let address = ip
  // Strip zone id (fe80::1%eth0) and brackets.
  address = address.replace(/%.*$/, '').replace(/^\[|\]$/g, '')

  // Handle IPv4-mapped/embedded tail (e.g. ::ffff:127.0.0.1).
  let v4Tail: number[] | null = null
  const lastColon = address.lastIndexOf(':')
  const tail = address.slice(lastColon + 1)
  if (tail.includes('.')) {
    const v4 = ipv4ToInt(tail)
    if (v4 === null) return null
    v4Tail = [(v4 >>> 16) & 0xffff, v4 & 0xffff]
    address = address.slice(0, lastColon + 1) + '0:0'
  }

  const halves = address.split('::')
  if (halves.length > 2) return null
  const head = halves[0] ? halves[0].split(':') : []
  const back = halves.length === 2 && halves[1] ? halves[1].split(':') : []

  const groups: number[] = []
  for (const h of head) groups.push(parseV6Group(h))
  const fill = 8 - head.length - back.length
  if (halves.length === 2) {
    if (fill < 0) return null
    for (let i = 0; i < fill; i++) groups.push(0)
  }
  for (const b of back) groups.push(parseV6Group(b))

  // Replace the synthetic tail placeholder with the real embedded v4 groups.
  if (v4Tail) {
    groups[groups.length - 2] = v4Tail[0]!
    groups[groups.length - 1] = v4Tail[1]!
  }

  if (groups.length !== 8 || groups.some((g) => Number.isNaN(g) || g < 0 || g > 0xffff)) {
    return null
  }
  return groups
}

function parseV6Group(group: string): number {
  if (!/^[0-9a-f]{1,4}$/i.test(group)) return NaN
  return parseInt(group, 16)
}

function isForbiddenV6(ip: string): boolean {
  const g = expandV6(ip)
  if (g === null) return true // fail closed

  // ::  (unspecified) and ::1 (loopback)
  if (g.every((x) => x === 0)) return true
  if (g.slice(0, 7).every((x) => x === 0) && g[7] === 1) return true

  // IPv4-mapped ::ffff:0:0/96 → check embedded v4
  if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) {
    const v4 = `${(g[6]! >> 8) & 0xff}.${g[6]! & 0xff}.${(g[7]! >> 8) & 0xff}.${g[7]! & 0xff}`
    return isForbiddenV4(v4)
  }
  // IPv4/IPv6 translation 64:ff9b::/96
  if (g[0] === 0x64 && g[1] === 0xff9b && g.slice(2, 6).every((x) => x === 0)) {
    const v4 = `${(g[6]! >> 8) & 0xff}.${g[6]! & 0xff}.${(g[7]! >> 8) & 0xff}.${g[7]! & 0xff}`
    return isForbiddenV4(v4)
  }

  const first = g[0]!
  if ((first & 0xfe00) === 0xfc00) return true // fc00::/7 ULA
  if ((first & 0xffc0) === 0xfe80) return true // fe80::/10 link-local
  if ((first & 0xff00) === 0xff00) return true // ff00::/8 multicast
  if (first === 0x2001 && g[1] === 0x0db8) return true // 2001:db8::/32 documentation

  return false
}

/** True if a raw IP literal (v4 or v6) is in a non-public range. */
export function isForbiddenAddress(ip: string): boolean {
  const family = isIP(ip)
  if (family === 4) return isForbiddenV4(ip)
  if (family === 6) return isForbiddenV6(ip)
  return true // not an IP → caller should not reach here; fail closed
}

/** Hostnames that must never be resolved/connected to. */
function isForbiddenHostname(host: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, '')
  if (h === 'localhost') return true
  if (h.endsWith('.localhost')) return true
  if (h.endsWith('.local')) return true // mDNS
  if (h.endsWith('.internal')) return true // common cloud metadata alias
  if (h.endsWith('.localdomain')) return true
  return false
}

/**
 * Resolve a hostname and reject if it (or any of its addresses) is non-public.
 * Returns the vetted addresses so callers may pin them for the connection.
 *
 * @throws BlockedHostError if the host is an IP literal in a forbidden range,
 *         a forbidden name (localhost/*.local/*.internal), or resolves to any
 *         non-public address.
 */
export async function resolvePublicAddresses(host: string): Promise<string[]> {
  const hostname = host.trim()
  if (!hostname) throw new BlockedHostError(host, 'empty host')

  if (isForbiddenHostname(hostname)) {
    throw new BlockedHostError(hostname, 'forbidden hostname')
  }

  // Bare IP literal — check directly, no DNS.
  const literalFamily = isIP(hostname)
  if (literalFamily !== 0) {
    if (isForbiddenAddress(hostname)) {
      throw new BlockedHostError(hostname, 'non-public IP literal')
    }
    return [hostname]
  }

  let records: { address: string }[]
  try {
    records = await lookup(hostname, { all: true })
  } catch (err) {
    throw new BlockedHostError(hostname, `DNS resolution failed: ${err instanceof Error ? err.message : 'unknown'}`)
  }
  if (records.length === 0) {
    throw new BlockedHostError(hostname, 'no DNS records')
  }
  for (const { address } of records) {
    if (isForbiddenAddress(address)) {
      throw new BlockedHostError(hostname, `resolves to non-public address ${address}`)
    }
  }
  return records.map((r) => r.address)
}

/**
 * Parse and SSRF-guard a URL. Validates the scheme, rejects credentials, and
 * verifies the host resolves only to public addresses.
 *
 * @returns the parsed URL when safe.
 * @throws BlockedHostError on any violation.
 */
export async function assertPublicUrl(
  rawUrl: string,
  allowedSchemes: readonly string[],
): Promise<URL> {
  let url: URL
  try {
    url = new URL(rawUrl)
  } catch {
    throw new BlockedHostError(rawUrl, 'invalid URL')
  }
  if (!allowedSchemes.includes(url.protocol)) {
    throw new BlockedHostError(url.hostname, `scheme ${url.protocol} not allowed`)
  }
  if (url.username || url.password) {
    throw new BlockedHostError(url.hostname, 'embedded credentials not allowed')
  }
  await resolvePublicAddresses(url.hostname)
  return url
}
