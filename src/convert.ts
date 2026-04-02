// ─── SMTP <-> NOSTR Mail Bridge — Conversion Utilities ──────────────────────
// Bidirectional conversion between MIME email and NOSTR Mail kind 15 rumors.
// Handles: HTML<->Markdown, threading mapping, attachment extraction/building.

import type { ParsedMail, Attachment as ParsedAttachment } from 'mailparser'
import type {
  MailRumor,
  BufferAttachment,
  MimeAttachment,
  BridgedMessage,
  OutboundEmail,
  AuthResults,
} from './types.js'
import { sanitizeHtml, stripHtml } from './sanitize.js'

// ─── HTML <-> Markdown Conversion ───────────────────────────────────────────

/**
 * Convert HTML email body to Markdown.
 *
 * First sanitizes the HTML, then converts to Markdown using
 * Turndown. Falls back to plain text stripping if Turndown is unavailable.
 *
 * @param html - Raw HTML from email body.
 * @returns Markdown string.
 */
export function htmlToMarkdown(html: string): string {
  const clean = sanitizeHtml(html)

  // Turndown-based conversion. We do a manual conversion here to avoid
  // hard runtime dependency — this covers the most common email HTML patterns.
  let md = clean

  // Block-level elements
  md = md.replace(/<h([1-6])[^>]*>([\s\S]*?)<\/h[1-6]>/gi, (_m, level: string, content: string) => {
    const hashes = '#'.repeat(parseInt(level, 10))
    return `\n\n${hashes} ${stripTags(content).trim()}\n\n`
  })

  md = md.replace(/<blockquote[^>]*>([\s\S]*?)<\/blockquote>/gi, (_m, content: string) => {
    const lines = stripTags(content).trim().split('\n')
    return '\n\n' + lines.map(l => `> ${l}`).join('\n') + '\n\n'
  })

  md = md.replace(/<pre[^>]*><code[^>]*>([\s\S]*?)<\/code><\/pre>/gi, (_m, content: string) => {
    return '\n\n```\n' + decodeHtmlEntities(content) + '\n```\n\n'
  })

  md = md.replace(/<pre[^>]*>([\s\S]*?)<\/pre>/gi, (_m, content: string) => {
    return '\n\n```\n' + stripTags(content) + '\n```\n\n'
  })

  md = md.replace(/<code[^>]*>([\s\S]*?)<\/code>/gi, (_m, content: string) => {
    return '`' + stripTags(content) + '`'
  })

  // Inline formatting
  md = md.replace(/<(strong|b)[^>]*>([\s\S]*?)<\/(strong|b)>/gi, (_m, _t1: string, content: string) => {
    return `**${stripTags(content)}**`
  })

  md = md.replace(/<(em|i)[^>]*>([\s\S]*?)<\/(em|i)>/gi, (_m, _t1: string, content: string) => {
    return `*${stripTags(content)}*`
  })

  md = md.replace(/<u[^>]*>([\s\S]*?)<\/u>/gi, (_m, content: string) => {
    return `__${stripTags(content)}__`
  })

  // Links
  md = md.replace(/<a[^>]*href="([^"]*)"[^>]*>([\s\S]*?)<\/a>/gi, (_m, href: string, text: string) => {
    const linkText = stripTags(text).trim()
    return `[${linkText}](${href})`
  })

  // Images (inline)
  md = md.replace(/<img[^>]*src="([^"]*)"[^>]*alt="([^"]*)"[^>]*\/?>/gi, (_m, src: string, alt: string) => {
    return `![${alt}](${src})`
  })
  md = md.replace(/<img[^>]*src="([^"]*)"[^>]*\/?>/gi, (_m, src: string) => {
    return `![](${src})`
  })

  // Lists
  md = md.replace(/<ul[^>]*>([\s\S]*?)<\/ul>/gi, (_m, content: string) => {
    return '\n' + content.replace(/<li[^>]*>([\s\S]*?)<\/li>/gi, (_m2, item: string) => {
      return `- ${stripTags(item).trim()}\n`
    }) + '\n'
  })

  md = md.replace(/<ol[^>]*>([\s\S]*?)<\/ol>/gi, (_m, content: string) => {
    let index = 0
    return '\n' + content.replace(/<li[^>]*>([\s\S]*?)<\/li>/gi, (_m2, item: string) => {
      index++
      return `${index}. ${stripTags(item).trim()}\n`
    }) + '\n'
  })

  // Line breaks and paragraphs
  md = md.replace(/<br\s*\/?>/gi, '\n')
  md = md.replace(/<\/p>/gi, '\n\n')
  md = md.replace(/<p[^>]*>/gi, '')
  md = md.replace(/<hr\s*\/?>/gi, '\n\n---\n\n')

  // Tables (simplified — convert to pipe tables)
  md = md.replace(/<table[^>]*>([\s\S]*?)<\/table>/gi, (_m, tableContent: string) => {
    return convertTableToMarkdown(tableContent)
  })

  // Strip any remaining tags
  md = stripTags(md)

  // Clean up whitespace
  md = decodeHtmlEntities(md)
  md = md.replace(/\n{3,}/g, '\n\n').trim()

  return md
}

/**
 * Convert Markdown content to sanitized HTML for email.
 *
 * Renders Markdown to HTML, then sanitizes the output.
 * Uses a built-in converter for common Markdown patterns.
 *
 * @param md - Markdown string.
 * @returns Sanitized HTML string.
 */
export function markdownToHtml(md: string): string {
  let html = md

  // Code blocks (must be first to avoid inner processing)
  html = html.replace(/```(\w*)\n([\s\S]*?)```/g, (_m, _lang: string, code: string) => {
    return `<pre><code>${escapeHtml(code.trim())}</code></pre>`
  })

  // Inline code
  html = html.replace(/`([^`]+)`/g, '<code>$1</code>')

  // Headings
  html = html.replace(/^#{6}\s+(.+)$/gm, '<h6>$1</h6>')
  html = html.replace(/^#{5}\s+(.+)$/gm, '<h5>$1</h5>')
  html = html.replace(/^#{4}\s+(.+)$/gm, '<h4>$1</h4>')
  html = html.replace(/^#{3}\s+(.+)$/gm, '<h3>$1</h3>')
  html = html.replace(/^#{2}\s+(.+)$/gm, '<h2>$1</h2>')
  html = html.replace(/^#{1}\s+(.+)$/gm, '<h1>$1</h1>')

  // Bold and italic
  html = html.replace(/\*\*\*(.+?)\*\*\*/g, '<strong><em>$1</em></strong>')
  html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
  html = html.replace(/\*(.+?)\*/g, '<em>$1</em>')
  html = html.replace(/__(.+?)__/g, '<u>$1</u>')

  // Links and images
  html = html.replace(/!\[([^\]]*)\]\(([^)]+)\)/g, '<img src="$2" alt="$1" />')
  html = html.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2">$1</a>')

  // Horizontal rules
  html = html.replace(/^---$/gm, '<hr />')

  // Blockquotes
  html = html.replace(/^>\s+(.+)$/gm, '<blockquote>$1</blockquote>')
  // Merge consecutive blockquotes
  html = html.replace(/<\/blockquote>\n<blockquote>/g, '\n')

  // Unordered lists
  html = html.replace(/(?:^[-*]\s+.+\n?)+/gm, (match) => {
    const items = match.trim().split('\n').map(line => {
      return `<li>${line.replace(/^[-*]\s+/, '')}</li>`
    }).join('\n')
    return `<ul>\n${items}\n</ul>`
  })

  // Ordered lists
  html = html.replace(/(?:^\d+\.\s+.+\n?)+/gm, (match) => {
    const items = match.trim().split('\n').map(line => {
      return `<li>${line.replace(/^\d+\.\s+/, '')}</li>`
    }).join('\n')
    return `<ol>\n${items}\n</ol>`
  })

  // Paragraphs (lines not already wrapped in block elements)
  html = html.replace(/^(?!<[a-z])((?:(?!^$).)+)$/gm, '<p>$1</p>')

  // Line breaks within paragraphs
  html = html.replace(/\n/g, '<br />\n')

  // Wrap in basic email HTML structure
  html = `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; max-width: 680px; margin: 0 auto; padding: 20px;">
${html}
</body>
</html>`

  return sanitizeHtml(html)
}

// ─── MIME <-> Rumor Conversion ──────────────────────────────────────────────

/**
 * Convert a parsed MIME email to a kind 15 NOSTR Mail rumor.
 *
 * Maps MIME fields to NOSTR Mail tags:
 * - Subject -> ["subject", ...]
 * - To/CC -> ["p", pubkey, relay, role] (requires identity resolution)
 * - Attachments -> ["attachment", hash, filename, mime, size]
 * - Threading -> ["reply", ...] / ["thread", ...]
 *
 * Note: Recipient resolution (email -> pubkey) must happen before calling this.
 * This function handles the structural conversion only.
 *
 * @param message - Bridged message (pre-processed from MIME).
 * @param senderPubkey - Bridge's pubkey (used as rumor pubkey for bridged mail).
 * @param recipientMappings - Map of email -> {pubkey, relay} for resolved recipients.
 * @param attachmentHashes - Map of filename -> {hash, size} for uploaded Blossom files.
 * @param threadMapping - Optional threading info from email Message-ID resolution.
 * @returns Kind 15 rumor ready for gift wrapping.
 */
export function mimeToRumor(
  message: BridgedMessage,
  senderPubkey: string,
  recipientMappings: Map<string, { pubkey: string; relay?: string }>,
  attachmentHashes: Map<string, { hash: string; size: number }>,
  threadMapping?: { replyTo?: string; threadRoot?: string },
): MailRumor {
  const tags: string[][] = []

  // Recipient tags
  for (const email of message.toEmails) {
    const mapping = recipientMappings.get(email)
    if (mapping) {
      tags.push(['p', mapping.pubkey, mapping.relay ?? '', 'to'])
    }
  }

  for (const email of message.ccEmails) {
    const mapping = recipientMappings.get(email)
    if (mapping) {
      tags.push(['p', mapping.pubkey, mapping.relay ?? '', 'cc'])
    }
  }

  // Subject
  if (message.subject) {
    tags.push(['subject', message.subject])
  }

  // Content type
  tags.push(['content-type', message.contentType])

  // Threading
  if (threadMapping?.replyTo) {
    tags.push(['reply', threadMapping.replyTo, ''])
  }
  if (threadMapping?.threadRoot) {
    tags.push(['thread', threadMapping.threadRoot, ''])
  }

  // Attachments
  for (const att of message.attachments) {
    const uploaded = attachmentHashes.get(att.filename)
    if (uploaded) {
      tags.push(['attachment', uploaded.hash, att.filename, att.mimeType, String(uploaded.size)])
    }
  }

  // Bridge provenance tags
  tags.push(['bridged-from', 'smtp', message.fromEmail])
  tags.push(['bridged-auth',
    `spf=${message.authResults.spf}`,
    `dkim=${message.authResults.dkim}`,
    `dmarc=${message.authResults.dmarc}`,
  ])

  // Client identifier
  tags.push(['client', 'NostrMail-Bridge/0.1.0'])

  return {
    kind: 15,
    pubkey: senderPubkey,
    created_at: Math.floor(Date.now() / 1000),
    tags,
    content: message.body,
  }
}

/**
 * Convert a kind 15 NOSTR Mail rumor to an outbound email message.
 *
 * Maps NOSTR Mail tags back to MIME headers and structure:
 * - ["subject", ...] -> Subject header
 * - ["p", ...] with email resolution -> To/CC headers
 * - ["attachment", ...] -> MIME attachments (after Blossom download)
 * - ["reply", ...] / ["thread", ...] -> In-Reply-To/References headers
 *
 * @param rumor - Kind 15 NOSTR Mail rumor.
 * @param emailRecipients - Map of pubkey -> email address for resolved recipients.
 * @param senderEmail - Bridge email address for the sender.
 * @param senderName - Display name for the sender.
 * @param downloadedAttachments - Attachment data downloaded from Blossom.
 * @returns Outbound email structure ready for SMTP sending.
 */
export function rumorToMime(
  rumor: MailRumor,
  emailRecipients: Map<string, string>,
  senderEmail: string,
  senderName: string | undefined,
  downloadedAttachments: MimeAttachment[],
): OutboundEmail {
  // Extract tags
  const subject = getTagValue(rumor.tags, 'subject') ?? '(no subject)'
  const contentType = getTagValue(rumor.tags, 'content-type') ?? 'text/plain'

  // Map recipients
  const toAddresses: string[] = []
  const ccAddresses: string[] = []

  for (const tag of rumor.tags) {
    if (tag[0] !== 'p') continue
    const pubkey = tag[1]
    if (!pubkey) continue
    const role = tag[3] ?? 'to'
    const email = emailRecipients.get(pubkey)
    if (!email) continue

    if (role === 'cc') {
      ccAddresses.push(email)
    } else {
      toAddresses.push(email)
    }
  }

  // Generate body
  let text: string
  let html: string

  if (contentType === 'text/html') {
    html = sanitizeHtml(rumor.content)
    text = stripHtml(rumor.content)
  } else if (contentType === 'text/markdown') {
    text = rumor.content
    html = markdownToHtml(rumor.content)
  } else {
    text = rumor.content
    html = markdownToHtml(rumor.content)
  }

  // Threading headers
  const threadInfo = threadingNostrToEmail(
    getTagValue(rumor.tags, 'reply'),
    getTagValue(rumor.tags, 'thread'),
  )

  // Build Message-ID from event rumor timestamp + pubkey (deterministic)
  const messageId = `<${rumor.created_at}.${rumor.pubkey.slice(0, 16)}@nostr-bridge>`

  const fromAddress = senderName
    ? `"${senderName}" <${senderEmail}>`
    : senderEmail

  return {
    from: fromAddress,
    to: toAddresses,
    cc: ccAddresses,
    subject,
    text,
    html,
    attachments: downloadedAttachments,
    messageId,
    inReplyTo: threadInfo.inReplyTo,
    references: threadInfo.references,
    headers: {
      'X-Nostr-Pubkey': rumor.pubkey,
      'X-Nostr-Bridge': 'NostrMail-Bridge/0.1.0',
    },
  }
}

// ─── Threading Conversion ───────────────────────────────────────────────────

/**
 * Map email threading headers to NOSTR Mail event tags.
 *
 * Email uses Message-ID / In-Reply-To / References headers.
 * NOSTR Mail uses ["reply", eventId] and ["thread", eventId] tags.
 *
 * The bridge maintains a Message-ID <-> event-ID mapping database.
 * This function returns the tag values given resolved event IDs.
 *
 * @param messageId - Email Message-ID header value.
 * @param inReplyTo - Email In-Reply-To header value.
 * @param references - Email References header values (space-separated Message-IDs).
 * @param resolveMessageId - Function to resolve a Message-ID to a NOSTR event ID.
 * @returns Object with optional replyTo and threadRoot event IDs.
 */
export async function threadingEmailToNostr(
  messageId: string | undefined,
  inReplyTo: string | undefined,
  references: string[] | undefined,
  resolveMessageId: (msgId: string) => Promise<string | undefined>,
): Promise<{ replyTo?: string; threadRoot?: string }> {
  let replyTo: string | undefined
  let threadRoot: string | undefined

  // In-Reply-To maps to the ["reply", ...] tag (direct parent)
  if (inReplyTo) {
    replyTo = await resolveMessageId(inReplyTo)
  }

  // First Reference is typically the thread root
  if (references && references.length > 0) {
    const firstRef = references[0]
    if (firstRef) {
      threadRoot = await resolveMessageId(firstRef)
    }
  }

  // If we have a reply but no thread root, the reply IS the root
  if (replyTo && !threadRoot) {
    threadRoot = replyTo
  }

  return { replyTo, threadRoot }
}

/**
 * Map NOSTR Mail event tags to email threading headers.
 *
 * Converts ["reply", eventId] and ["thread", eventId] tags to
 * In-Reply-To and References email headers.
 *
 * @param replyEventId - Event ID from the ["reply", ...] tag.
 * @param threadEventId - Event ID from the ["thread", ...] tag.
 * @returns Object with inReplyTo and references header values.
 */
export function threadingNostrToEmail(
  replyEventId: string | undefined,
  threadEventId: string | undefined,
): { inReplyTo?: string; references?: string } {
  let inReplyTo: string | undefined
  let references: string | undefined

  if (replyEventId) {
    inReplyTo = `<${replyEventId}@nostr>`
  }

  const refs: string[] = []
  if (threadEventId) {
    refs.push(`<${threadEventId}@nostr>`)
  }
  if (replyEventId && replyEventId !== threadEventId) {
    refs.push(`<${replyEventId}@nostr>`)
  }

  if (refs.length > 0) {
    references = refs.join(' ')
  }

  return { inReplyTo, references }
}

// ─── Attachment Extraction / Building ───────────────────────────────────────

/**
 * Extract attachments from a parsed MIME email.
 *
 * Separates inline images (with Content-ID) from regular attachments.
 * Converts mailparser Attachment objects to our BufferAttachment format.
 *
 * @param parsedMail - Parsed email from mailparser.
 * @returns Array of BufferAttachment objects with raw data.
 */
export function extractAttachments(parsedMail: ParsedMail): BufferAttachment[] {
  const attachments: BufferAttachment[] = []

  if (!parsedMail.attachments) return attachments

  for (const att of parsedMail.attachments) {
    attachments.push({
      filename: att.filename ?? `attachment-${attachments.length + 1}`,
      mimeType: att.contentType ?? 'application/octet-stream',
      data: new Uint8Array(att.content),
      contentId: att.contentId ?? undefined,
      inline: att.contentDisposition === 'inline',
    })
  }

  return attachments
}

/**
 * Build MIME attachment structures from Blossom-hosted file references.
 *
 * Downloads files from Blossom servers and creates MIME-compatible
 * attachment objects for nodemailer.
 *
 * @param attachmentTags - Attachment tags from the rumor.
 * @param blossomUrls - Blossom server URLs to try.
 * @returns Array of MimeAttachment objects ready for nodemailer.
 */
export async function buildMimeAttachments(
  attachmentTags: string[][],
  blossomUrls: string[],
): Promise<MimeAttachment[]> {
  const attachments: MimeAttachment[] = []

  for (const tag of attachmentTags) {
    if (tag[0] !== 'attachment') continue

    const hash = tag[1]
    const filename = tag[2] ?? 'attachment'
    const mimeType = tag[3] ?? 'application/octet-stream'

    if (!hash) continue

    // Try each Blossom server until we get the file
    let data: Uint8Array | null = null
    for (const baseUrl of blossomUrls) {
      try {
        const url = `${baseUrl.replace(/\/$/, '')}/${hash}`
        const response = await fetch(url, { signal: AbortSignal.timeout(30000) })
        if (response.ok) {
          data = new Uint8Array(await response.arrayBuffer())
          break
        }
      } catch {
        // Try next server
        continue
      }
    }

    if (data) {
      attachments.push({
        filename,
        content: data,
        contentType: mimeType,
      })
    }
  }

  return attachments
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/** Get the first value for a given tag name. */
function getTagValue(tags: string[][], name: string): string | undefined {
  const tag = tags.find(t => t[0] === name)
  return tag?.[1]
}

/** Strip HTML tags (simple regex). */
function stripTags(html: string): string {
  return html.replace(/<[^>]+>/g, '')
}

/** Decode common HTML entities. */
function decodeHtmlEntities(text: string): string {
  return text
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&nbsp;/g, ' ')
}

/** Escape text for HTML output. */
function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

/** Convert an HTML table to Markdown pipe table. */
function convertTableToMarkdown(tableHtml: string): string {
  const rows: string[][] = []

  const rowRegex = /<tr[^>]*>([\s\S]*?)<\/tr>/gi
  let rowMatch: RegExpExecArray | null

  while ((rowMatch = rowRegex.exec(tableHtml)) !== null) {
    const cells: string[] = []
    const cellRegex = /<(?:td|th)[^>]*>([\s\S]*?)<\/(?:td|th)>/gi
    let cellMatch: RegExpExecArray | null

    while ((cellMatch = cellRegex.exec(rowMatch[1]!)) !== null) {
      cells.push(stripTags(cellMatch[1]!).trim())
    }

    if (cells.length > 0) {
      rows.push(cells)
    }
  }

  if (rows.length === 0) return ''

  const maxCols = Math.max(...rows.map(r => r.length))
  const lines: string[] = []

  for (let i = 0; i < rows.length; i++) {
    const row = rows[i]!
    const paddedRow = Array.from({ length: maxCols }, (_, j) => row[j] ?? '')
    lines.push('| ' + paddedRow.join(' | ') + ' |')

    // Add separator after header row
    if (i === 0) {
      lines.push('| ' + Array.from({ length: maxCols }, () => '---').join(' | ') + ' |')
    }
  }

  return '\n\n' + lines.join('\n') + '\n\n'
}
