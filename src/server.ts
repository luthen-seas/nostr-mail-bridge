// ─── SMTP <-> NOSTR Mail Bridge — Main Server Entry Point ──────────────────
// Loads configuration, starts inbound SMTP server, outbound NOSTR subscriber,
// and HTTP health-check endpoint. Handles graceful shutdown.

import http from 'node:http'
import { createHash, timingSafeEqual } from 'node:crypto'
import { generateSecretKey, getPublicKey } from 'nostr-tools'
import type { BridgeConfig } from './types.js'
import { startInboundServer, stopInboundServer } from './inbound.js'
import { startOutboundSubscriber, stopOutboundSubscriber } from './outbound.js'
import { registerBridgeUser, initIdentityStore } from './identity.js'
import {
  parseHexBytes,
  sanitizeDomainName,
  sanitizeHeaderValue,
  sanitizeHttpUrl,
  sanitizeWebSocketUrl,
} from './security.js'

/** Health-check HTTP server. */
let healthServer: http.Server | null = null

/** Admin provisioning HTTP server (only started when BRIDGE_ADMIN_TOKEN set). */
let adminServer: http.Server | null = null

/** Server start time for uptime reporting. */
let startTime: number = 0

/**
 * Load bridge configuration from environment variables.
 *
 * Required environment variables:
 * - BRIDGE_DOMAIN: Domain name for the bridge
 * - BRIDGE_PRIVATE_KEY: Hex-encoded NOSTR private key (64 hex chars)
 * - NOSTR_RELAYS: Comma-separated relay URLs
 *
 * Optional:
 * - SMTP_PORT: Inbound SMTP port (default: 2525 for dev, 25 for prod)
 * - SMTP_SUBMISSION_PORT: Submission port (default: 587)
 * - DKIM_PRIVATE_KEY: PEM-encoded DKIM signing key
 * - DKIM_SELECTOR: DKIM selector (default: "default")
 * - BLOSSOM_SERVERS: Comma-separated Blossom URLs
 * - OUTBOUND_SMTP_HOST: Outbound SMTP host (default: "localhost")
 * - OUTBOUND_SMTP_PORT: Outbound SMTP port (default: 25)
 * - OUTBOUND_SMTP_SECURE: Use TLS (default: false)
 * - OUTBOUND_SMTP_USER: SMTP auth user
 * - OUTBOUND_SMTP_PASS: SMTP auth password
 * - HEALTH_PORT: HTTP health-check port (default: 8080)
 * - MAX_MESSAGE_SIZE: Max inbound email size in bytes (default: 26214400 = 25MB)
 * - REQUIRE_AUTH: Require SPF/DKIM pass (default: false)
 *
 * @returns Validated BridgeConfig.
 */
function loadConfig(): BridgeConfig {
  const domain = sanitizeDomainName(requireEnv('BRIDGE_DOMAIN'))
  if (!domain) {
    throw new Error('BRIDGE_DOMAIN must be a valid DNS hostname')
  }

  // Generate a keypair if not provided (dev mode)
  let privateKeyHex = process.env['BRIDGE_PRIVATE_KEY'] ?? ''
  if (!privateKeyHex) {
    const sk = generateSecretKey()
    privateKeyHex = Buffer.from(sk).toString('hex')
    console.log('[config] No BRIDGE_PRIVATE_KEY set, generated ephemeral keypair')
    console.log(`[config] Bridge pubkey: ${getPublicKey(sk)}`)
  } else {
    parseHexBytes(privateKeyHex)
  }

  const relays = (process.env['NOSTR_RELAYS'] ?? 'wss://relay.damus.io,wss://nos.lol,wss://relay.nostr.band')
    .split(',')
    .map(r => r.trim())
    .map(r => sanitizeWebSocketUrl(r))
    .filter((r): r is string => typeof r === 'string')

  const blossomServers = (process.env['BLOSSOM_SERVERS'] ?? 'https://blossom.primal.net')
    .split(',')
    .map(s => s.trim())
    .map(s => sanitizeHttpUrl(s))
    .filter((s): s is string => typeof s === 'string')

  // B7: outbound auth empty-pass fail-fast.
  // If a user is configured but the password is empty, fail at startup
  // rather than silently constructing an `auth: { user, pass: "" }` config
  // that some SMTP servers misinterpret.
  const outboundUser = process.env['OUTBOUND_SMTP_USER']
  const outboundPass = process.env['OUTBOUND_SMTP_PASS']
  if (outboundUser && !outboundPass) {
    throw new Error(
      'OUTBOUND_SMTP_USER is set but OUTBOUND_SMTP_PASS is empty. ' +
        'Either set both (for AUTH-required submission) or unset both (for anonymous outbound).',
    )
  }
  const outboundAuth = outboundUser
    ? {
        user: outboundUser,
        pass: outboundPass!,
      }
    : undefined

  return {
    smtpPort: parseInt(process.env['SMTP_PORT'] ?? '2525', 10),
    smtpSubmissionPort: parseInt(process.env['SMTP_SUBMISSION_PORT'] ?? '587', 10),
    domain,
    hostname: sanitizeDomainName(process.env['BRIDGE_HOSTNAME'] ?? domain) ?? domain,
    dkimPrivateKey: process.env['DKIM_PRIVATE_KEY'] ?? '',
    dkimSelector: sanitizeHeaderValue(process.env['DKIM_SELECTOR'] ?? 'default', 128),
    relays,
    bridgePrivateKeyHex: privateKeyHex,
    blossomServers,
    outboundSmtp: {
      host: process.env['OUTBOUND_SMTP_HOST'] ?? 'localhost',
      port: parseInt(process.env['OUTBOUND_SMTP_PORT'] ?? '25', 10),
      secure: process.env['OUTBOUND_SMTP_SECURE'] === 'true',
      auth: outboundAuth,
    },
    healthPort: parseInt(process.env['HEALTH_PORT'] ?? '8080', 10),
    maxMessageSize: parseInt(process.env['MAX_MESSAGE_SIZE'] ?? '26214400', 10),
    // F-DKIM-01: fail-closed by default. Operators must explicitly opt out
    // (REQUIRE_AUTH=false) to accept unauthenticated inbound mail.
    requireAuth: process.env['REQUIRE_AUTH'] !== 'false',
    trustedAuthservId: process.env['TRUSTED_AUTHSERV_ID']
      ? sanitizeHeaderValue(process.env['TRUSTED_AUTHSERV_ID'], 253)
      : undefined,
  }
}

/**
 * Require an environment variable, throwing if not set.
 */
function requireEnv(name: string): string {
  const value = process.env[name]
  if (!value) {
    throw new Error(`Required environment variable ${name} is not set`)
  }
  return value
}

/**
 * Constant-time string comparison (F-BRIDGE-DOS-01). Both sides are hashed to
 * a fixed-length digest first so neither the length nor the content of the
 * secret leaks through comparison timing.
 */
function timingSafeEqualStr(a: string, b: string): boolean {
  const ha = createHash('sha256').update(a).digest()
  const hb = createHash('sha256').update(b).digest()
  return timingSafeEqual(ha, hb)
}

/**
 * Start the HTTP health-check server.
 *
 * Responds to GET /health with bridge status, uptime, and configuration.
 * Returns 200 when healthy, 503 when shutting down.
 *
 * @param config - Bridge configuration.
 */
function startHealthServer(config: BridgeConfig): void {
  healthServer = http.createServer((_req, res) => {
    const uptime = Math.floor((Date.now() - startTime) / 1000)
    const bridgePubkey = getPublicKey(parseHexBytes(config.bridgePrivateKeyHex))

    const status = {
      status: 'healthy',
      uptime,
      version: '0.1.0',
      bridge: {
        domain: config.domain,
        pubkey: bridgePubkey,
        smtpPort: config.smtpPort,
        relays: config.relays,
        blossomServers: config.blossomServers,
      },
    }

    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify(status, null, 2))
  })

  healthServer.listen(config.healthPort, () => {
    console.log(`[health] Health-check endpoint on http://localhost:${config.healthPort}/health`)
  })
}

/**
 * Start the admin provisioning HTTP server.
 *
 * Endpoint: `POST /admin/users` with header `Authorization: Bearer <token>`
 * and JSON body `{pubkey, email}` calls `registerBridgeUser`. The endpoint
 * is only started when `BRIDGE_ADMIN_TOKEN` is set in the environment.
 *
 * Returns:
 *  - 401 on missing/wrong token
 *  - 400 on malformed body
 *  - 200 with `{ok:true}` on success
 *  - 500 on internal error
 *
 * Every successful registration is logged to stdout (audit trail).
 */
function startAdminServer(_config: BridgeConfig): void {
  const adminToken = process.env['BRIDGE_ADMIN_TOKEN']
  if (!adminToken) {
    console.log('[admin] BRIDGE_ADMIN_TOKEN unset; admin endpoint disabled')
    return
  }
  const adminPort = parseInt(process.env['BRIDGE_ADMIN_PORT'] ?? '8025', 10)

  adminServer = http.createServer((req, res) => {
    if (req.method !== 'POST' || req.url !== '/admin/users') {
      res.writeHead(404, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: 'not found' }))
      return
    }
    const authHeader = req.headers['authorization']
    // F-BRIDGE-DOS-01: constant-time comparison to avoid a timing oracle on
    // the admin token.
    if (typeof authHeader !== 'string' || !timingSafeEqualStr(authHeader, `Bearer ${adminToken}`)) {
      res.writeHead(401, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: 'unauthorized' }))
      return
    }
    const chunks: Buffer[] = []
    req.on('data', (c: Buffer) => chunks.push(c))
    req.on('end', () => {
      let body: { pubkey?: unknown; email?: unknown }
      try {
        body = JSON.parse(Buffer.concat(chunks).toString('utf8'))
      } catch {
        res.writeHead(400, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ error: 'invalid JSON body' }))
        return
      }
      if (typeof body.pubkey !== 'string' || typeof body.email !== 'string') {
        res.writeHead(400, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ error: 'pubkey and email must be strings' }))
        return
      }
      try {
        registerBridgeUser(body.pubkey, body.email)
        const remote = req.socket.remoteAddress ?? 'unknown'
        // Audit log — do NOT log the token itself.
        console.log(`[admin] registered pubkey=${body.pubkey.slice(0, 8)}... email=${body.email} from=${remote}`)
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ ok: true }))
      } catch (err) {
        const msg = err instanceof Error ? err.message : 'unknown error'
        res.writeHead(400, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ error: msg }))
      }
    })
    req.on('error', () => {
      try {
        res.writeHead(500, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ error: 'request error' }))
      } catch { /* ignore */ }
    })
  })

  adminServer.listen(adminPort, '127.0.0.1', () => {
    console.log(`[admin] Provisioning endpoint on http://127.0.0.1:${adminPort}/admin/users (token-gated)`)
  })
}

/**
 * Gracefully shut down all bridge components.
 */
async function shutdown(): Promise<void> {
  console.log('\n[bridge] Shutting down...')

  const shutdownPromises: Promise<void>[] = []

  // Stop accepting new SMTP connections
  shutdownPromises.push(stopInboundServer())

  // Close NOSTR subscriptions and SMTP transport
  shutdownPromises.push(stopOutboundSubscriber())

  // Close health server
  if (healthServer) {
    shutdownPromises.push(new Promise((resolve) => {
      healthServer!.close(() => resolve())
    }))
  }

  // Close admin server (if running)
  if (adminServer) {
    shutdownPromises.push(new Promise((resolve) => {
      adminServer!.close(() => resolve())
    }))
  }

  await Promise.allSettled(shutdownPromises)
  console.log('[bridge] Shutdown complete')
  process.exit(0)
}

/**
 * Main entry point — start the bridge.
 */
async function main(): Promise<void> {
  console.log('='.repeat(60))
  console.log('  NOSTR Mail Bridge v0.1.0')
  console.log('  SMTP <-> NOSTR bidirectional gateway')
  console.log('='.repeat(60))

  try {
    const config = loadConfig()
    startTime = Date.now()

    // Load persisted identity registrations (F-BRIDGE-DOS-01) so bridge
    // addresses survive restarts. No-op unless BRIDGE_IDENTITY_STORE is set.
    initIdentityStore()

    const bridgePubkey = getPublicKey(parseHexBytes(config.bridgePrivateKeyHex))
    console.log(`[config] Domain: ${config.domain}`)
    console.log(`[config] Bridge pubkey: ${bridgePubkey}`)
    console.log(`[config] Relays: ${config.relays.join(', ')}`)
    console.log(`[config] Blossom servers: ${config.blossomServers.join(', ')}`)

    // Start all components
    startInboundServer(config)
    startOutboundSubscriber(config)
    startHealthServer(config)
    startAdminServer(config)

    console.log('[bridge] All components started successfully')

    // Register shutdown handlers
    process.on('SIGINT', shutdown)
    process.on('SIGTERM', shutdown)

  } catch (err) {
    console.error('[bridge] Fatal startup error:', err)
    process.exit(1)
  }
}

// ── Run ──────────────────────────────────────────────────────────────────────
main().catch((err) => {
  console.error('[bridge] Unhandled error:', err)
  process.exit(1)
})
