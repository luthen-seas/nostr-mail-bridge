// Regression tests for R5 bridge residuals (F-BRIDGE-DOS-01):
// rolling-window rate limiter + file-backed identity persistence.
import { describe, expect, it, afterEach } from 'vitest'
import { mkdtempSync, rmSync, existsSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { _rateLimiters } from '../src/inbound.js'
import {
  registerBridgeUser,
  resolveNostrToEmail,
  initIdentityStore,
  _resetIdentityStoreForTests,
} from '../src/identity.js'

describe('rolling-window rate limiter', () => {
  it('allows up to max then rejects, and resets after the window', () => {
    const rl = _rateLimiters.makeRateLimiter(1000, 3)
    expect(rl.check('a')).toBe(true)
    expect(rl.check('a')).toBe(true)
    expect(rl.check('a')).toBe(true)
    expect(rl.check('a')).toBe(false) // 4th in window rejected
    expect(rl.check('b')).toBe(true) // independent key
    // Simulate window expiry by rewinding the bucket's windowStart.
    const bucket = rl._buckets.get('a')!
    bucket.windowStart -= 2000
    expect(rl.check('a')).toBe(true)
  })
})

describe('file-backed identity persistence', () => {
  const pubkey = 'a'.repeat(64)
  const email = 'alice@bridge.example.com'
  let dir: string

  afterEach(() => {
    _resetIdentityStoreForTests()
    if (dir && existsSync(dir)) rmSync(dir, { recursive: true, force: true })
  })

  it('persists a registration and reloads it across a simulated restart', () => {
    dir = mkdtempSync(join(tmpdir(), 'idstore-'))
    const storePath = join(dir, 'identity.json')

    // First "process": configure store, register, expect file written.
    initIdentityStore(storePath)
    registerBridgeUser(pubkey, email)
    expect(existsSync(storePath)).toBe(true)
    const onDisk = JSON.parse(readFileSync(storePath, 'utf-8'))
    expect(onDisk.registrations[0].pubkey).toBe(pubkey)

    // Simulate restart: wipe memory, reload from disk.
    _resetIdentityStoreForTests()
    initIdentityStore(storePath)
    // The reloaded registration yields the stable registered address, not the
    // deterministic fallback (pubkey.slice(0,20)@domain).
    expect(resolveNostrToEmail(pubkey, 'bridge.example.com')).toBe(email)
  })

  it('is a no-op when no store path is configured (in-memory only)', () => {
    _resetIdentityStoreForTests()
    initIdentityStore(undefined)
    registerBridgeUser(pubkey, email)
    // Works in-memory; nothing thrown, no file dependency.
    expect(resolveNostrToEmail(pubkey, 'bridge.example.com')).toBe(email)
  })
})
