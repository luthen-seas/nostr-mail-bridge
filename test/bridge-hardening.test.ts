import { describe, expect, it } from 'vitest'
import { sanitizeHtml } from '../src/sanitize.js'
import {
  buildMimeAttachments,
  extractAttachments,
  rumorToMime,
  threadingEmailToNostr,
  threadingNostrToEmail,
} from '../src/convert.js'

describe('bridge hardening', () => {
  it('strips dangerous URL schemes and forces safe anchor attributes', () => {
    const html = sanitizeHtml([
      '<a href="javascript:alert(1)" onclick="evil()">bad</a>',
      '<a href="//evil.test/path">proto-relative</a>',
      '<img src="data:text/html,boom" onerror="evil()">',
      '<a href="https://example.com/path">good</a>',
    ].join(''))

    expect(html).not.toContain('javascript:')
    expect(html).not.toContain('data:')
    expect(html).not.toContain('onclick=')
    expect(html).not.toContain('src="')
    expect(html).toContain('href="https://example.com/path"')
    expect(html).toContain('rel="noopener noreferrer"')
    expect(html).toContain('target="_blank"')
  })

  it('normalizes threading IDs before resolving them', async () => {
    const resolved = new Map<string, string>([
      ['<root@nostr>', 'root-id'],
      ['<parent@nostr>', 'parent-id'],
    ])

    const thread = await threadingEmailToNostr(
      '<current@nostr>',
      ' <parent@nostr> ',
      ['junk', '<root@nostr>', '<parent@nostr>'],
      async (msgId) => resolved.get(msgId),
    )

    expect(thread.replyTo).toBe('parent-id')
    expect(thread.threadRoot).toBe('root-id')
  })

  it('drops unsafe nostr event ids when building email threading headers', () => {
    expect(threadingNostrToEmail('not-hex' as unknown as string, 'also-bad' as unknown as string)).toEqual({})

    const valid = 'a'.repeat(64)
    expect(threadingNostrToEmail(valid, valid)).toEqual({
      inReplyTo: `<${valid}@nostr>`,
      references: `<${valid}@nostr>`,
    })
  })

  it('sanitizes outbound headers, senders, and recipient addresses', () => {
    const rumor = {
      kind: 1400 as const,
      pubkey: 'a'.repeat(64),
      created_at: 1710000000,
      tags: [
        ['subject', 'Hello\r\nBcc: injected@example.com'],
        ['p', 'b'.repeat(64), '', 'to'],
        ['p', 'c'.repeat(64), '', 'cc'],
        ['reply', 'd'.repeat(64)],
        ['thread', 'e'.repeat(64)],
      ],
      content: 'plain body',
    }

    const email = rumorToMime(
      rumor,
      new Map([
        ['b'.repeat(64), 'to@example.com'],
        ['c'.repeat(64), 'cc@example.com'],
      ]),
      'bridge@example.com',
      'Mallory"\r\nInjected',
      [],
    )

    expect(email.subject).toBe('Hello Bcc: injected@example.com')
    expect(email.from).toContain('<bridge@example.com>')
    expect(email.from).not.toMatch(/[\r\n]/)
    expect(email.to).toEqual(['to@example.com'])
    expect(email.cc).toEqual(['cc@example.com'])
    expect(email.headers['X-Nostr-Pubkey']).toBe(rumor.pubkey)

    const dropped = rumorToMime(
      rumor,
      new Map([
        ['b'.repeat(64), 'to@example.com\r\nBcc:bad@example.com'],
      ]),
      'bridge@example.com',
      'Mallory"\r\nInjected',
      [],
    )

    expect(dropped.to).toEqual([])
  })

  it('sanitizes attachments and ignores unsafe blossom references', async () => {
    const attachments = extractAttachments({
      attachments: [
        {
          filename: '../../evil.txt',
          contentType: 'text/html; charset=utf-8',
          contentId: '<cid@example.com>\r\n',
          contentDisposition: 'inline',
          content: Buffer.from('x'),
        },
      ],
    } as any)

    expect(attachments).toHaveLength(1)
    expect(attachments[0]?.filename).toBe('evil.txt')
    expect(attachments[0]?.mimeType).toBe('text/html')
    expect(attachments[0]?.contentId).toBe('<cid@example.com>')

    await expect(buildMimeAttachments(
      [['attachment', 'not-a-valid-hash', '../evil.bin', 'text/plain']],
      ['javascript:alert(1)', 'https://example.com'],
    )).resolves.toEqual([])
  })
})
