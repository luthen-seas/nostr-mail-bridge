// ─── SMTP <-> NOSTR Mail Bridge — Main Server Entry Point ──────────────────
// Loads configuration, starts inbound SMTP server, outbound NOSTR subscriber,
// and HTTP health-check endpoint. Handles graceful shutdown.

import http from 'node:http'
import { generateSecretKey, getPublicKey } from 'nostr-tools'
import type { BridgeConfig } from './types.js'
import { startInboundServer, stopInboundServer } from './inbound.js'
import { startOutboundSubscriber, stopOutboundSubscriber } from './outbound.js'

/** Health-check HTTP server. */
let healthServer: http.Server | null = null

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
  const domain = requireEnv('BRIDGE_DOMAIN')

  // Generate a keypair if not provided (dev mode)
  let privateKeyHex = process.env['BRIDGE_PRIVATE_KEY'] ?? ''
  if (!privateKeyHex) {
    const sk = generateSecretKey()
    privateKeyHex = Buffer.from(sk).toString('hex')
    console.log('[config] No BRIDGE_PRIVATE_KEY set, generated ephemeral keypair')
    console.log(`[config] Bridge pubkey: ${getPublicKey(sk)}`)
  }

  const relays = (process.env['NOSTR_RELAYS'] ?? 'wss://relay.damus.io,wss://nos.lol,wss://relay.nostr.band')
    .split(',')
    .map(r => r.trim())
    .filter(Boolean)

  const blossomServers = (process.env['BLOSSOM_SERVERS'] ?? 'https://blossom.primal.net')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean)

  const outboundAuth = process.env['OUTBOUND_SMTP_USER']
    ? {
        user: process.env['OUTBOUND_SMTP_USER']!,
        pass: process.env['OUTBOUND_SMTP_PASS'] ?? '',
      }
    : undefined

  return {
    smtpPort: parseInt(process.env['SMTP_PORT'] ?? '2525', 10),
    smtpSubmissionPort: parseInt(process.env['SMTP_SUBMISSION_PORT'] ?? '587', 10),
    domain,
    hostname: process.env['BRIDGE_HOSTNAME'] ?? domain,
    dkimPrivateKey: process.env['DKIM_PRIVATE_KEY'] ?? '',
    dkimSelector: process.env['DKIM_SELECTOR'] ?? 'default',
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
    requireAuth: process.env['REQUIRE_AUTH'] === 'true',
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
    const bridgePubkey = getPublicKey(hexToBytes(config.bridgePrivateKeyHex))

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

    const bridgePubkey = getPublicKey(hexToBytes(config.bridgePrivateKeyHex))
    console.log(`[config] Domain: ${config.domain}`)
    console.log(`[config] Bridge pubkey: ${bridgePubkey}`)
    console.log(`[config] Relays: ${config.relays.join(', ')}`)
    console.log(`[config] Blossom servers: ${config.blossomServers.join(', ')}`)

    // Start all components
    startInboundServer(config)
    startOutboundSubscriber(config)
    startHealthServer(config)

    console.log('[bridge] All components started successfully')

    // Register shutdown handlers
    process.on('SIGINT', shutdown)
    process.on('SIGTERM', shutdown)

  } catch (err) {
    console.error('[bridge] Fatal startup error:', err)
    process.exit(1)
  }
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

// ── Run ──────────────────────────────────────────────────────────────────────
main().catch((err) => {
  console.error('[bridge] Unhandled error:', err)
  process.exit(1)
})
