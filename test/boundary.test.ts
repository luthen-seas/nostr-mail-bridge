// Regression tests for the R1 trust-boundary fixes:
//   F-SSRF-01/02 (ssrf.ts guards), domain hardening (security.ts),
//   F-SAN-01 (fail-closed HTML sanitizer).
import { describe, expect, it } from 'vitest'
import {
  isForbiddenAddress,
  resolvePublicAddresses,
  assertPublicUrl,
  BlockedHostError,
} from '../src/ssrf.js'
import { sanitizeDomainName } from '../src/security.js'
import { sanitizeHtml } from '../src/sanitize.js'

describe('SSRF guard — isForbiddenAddress', () => {
  it('flags non-public IPv4 ranges', () => {
    for (const ip of [
      '127.0.0.1', '10.0.0.1', '169.254.169.254', '172.16.0.1',
      '192.168.1.1', '100.64.0.1', '0.0.0.0', '255.255.255.255', '224.0.0.1',
    ]) {
      expect(isForbiddenAddress(ip), ip).toBe(true)
    }
  })
  it('allows public IPv4', () => {
    for (const ip of ['8.8.8.8', '1.1.1.1', '93.184.216.34']) {
      expect(isForbiddenAddress(ip), ip).toBe(false)
    }
  })
  it('flags non-public IPv6 incl. mapped/loopback/ULA/link-local', () => {
    for (const ip of ['::1', '::', 'fe80::1', 'fc00::1', 'fd12::1', '::ffff:127.0.0.1', '::ffff:169.254.169.254']) {
      expect(isForbiddenAddress(ip), ip).toBe(true)
    }
  })
  it('allows public IPv6', () => {
    expect(isForbiddenAddress('2606:4700:4700::1111')).toBe(false)
  })
})

describe('SSRF guard — resolvePublicAddresses', () => {
  it('rejects IP literals in forbidden ranges without DNS', async () => {
    await expect(resolvePublicAddresses('169.254.169.254')).rejects.toBeInstanceOf(BlockedHostError)
    await expect(resolvePublicAddresses('127.0.0.1')).rejects.toBeInstanceOf(BlockedHostError)
  })
  it('rejects forbidden hostnames', async () => {
    for (const h of ['localhost', 'foo.local', 'metadata.internal', 'x.localhost']) {
      await expect(resolvePublicAddresses(h), h).rejects.toBeInstanceOf(BlockedHostError)
    }
  })
  it('accepts a public IP literal', async () => {
    await expect(resolvePublicAddresses('1.1.1.1')).resolves.toEqual(['1.1.1.1'])
  })
})

describe('SSRF guard — assertPublicUrl', () => {
  it('rejects disallowed schemes', async () => {
    await expect(assertPublicUrl('file:///etc/passwd', ['https:'])).rejects.toBeInstanceOf(BlockedHostError)
    await expect(assertPublicUrl('ws://1.1.1.1', ['https:'])).rejects.toBeInstanceOf(BlockedHostError)
  })
  it('rejects embedded credentials', async () => {
    await expect(assertPublicUrl('https://user:pass@1.1.1.1/', ['https:'])).rejects.toBeInstanceOf(BlockedHostError)
  })
  it('rejects metadata/loopback hosts', async () => {
    await expect(assertPublicUrl('https://169.254.169.254/latest/meta-data/', ['https:'])).rejects.toBeInstanceOf(BlockedHostError)
    await expect(assertPublicUrl('http://127.0.0.1:6379/', ['http:', 'https:'])).rejects.toBeInstanceOf(BlockedHostError)
  })
  it('accepts a public https URL by IP literal', async () => {
    await expect(assertPublicUrl('https://1.1.1.1/.well-known/nostr.json', ['https:'])).resolves.toBeInstanceOf(URL)
  })
})

describe('domain hardening — sanitizeDomainName rejects IP literals', () => {
  it('rejects IPv4, decimal IP, and localhost', () => {
    expect(sanitizeDomainName('169.254.169.254')).toBeNull()
    expect(sanitizeDomainName('127.0.0.1')).toBeNull()
    expect(sanitizeDomainName('2130706433')).toBeNull()
    expect(sanitizeDomainName('localhost')).toBeNull()
  })
  it('still accepts real domains', () => {
    expect(sanitizeDomainName('example.com')).toBe('example.com')
    expect(sanitizeDomainName('mail.sub.example.org')).toBe('mail.sub.example.org')
  })
})

describe('HTML sanitizer fail-closed (F-SAN-01)', () => {
  it('neutralizes the regex-bypass payload via the live sanitize-html path', () => {
    const out = sanitizeHtml('<img src="x" alt="a>b" onerror="alert(1)">')
    expect(out).not.toMatch(/onerror/i)
    expect(out).not.toMatch(/alert\(1\)/)
  })
  it('strips script and event handlers', () => {
    const out = sanitizeHtml('<script>alert(1)</script><a href="https://ok.test" onclick="x()">ok</a>')
    expect(out).not.toMatch(/<script/i)
    expect(out).not.toMatch(/onclick/i)
  })
})
