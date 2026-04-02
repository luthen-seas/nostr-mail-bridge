// ─── SMTP <-> NOSTR Mail Bridge — HTML Sanitization ─────────────────────────
// Sanitizes HTML content from email for safe rendering and conversion.
// Strips dangerous tags, attributes, and URL schemes.

/** Tags allowed in sanitized output. */
const ALLOWED_TAGS = new Set([
  'b', 'i', 'u', 'em', 'strong', 'a', 'p', 'br', 'hr',
  'ul', 'ol', 'li',
  'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
  'blockquote', 'pre', 'code',
  'table', 'thead', 'tbody', 'tr', 'td', 'th',
  'img', 'span', 'div', 'sup', 'sub',
])

/** Tags that must be completely removed (including their content). */
const STRIP_TAGS_WITH_CONTENT = new Set([
  'script', 'style', 'iframe', 'object', 'embed', 'form',
  'input', 'textarea', 'select', 'button', 'applet',
  'link', 'meta', 'base', 'noscript',
])

/** Allowed URL schemes for href/src attributes. */
const ALLOWED_URL_SCHEMES = new Set(['https:', 'http:', 'cid:', 'mailto:'])

/** Denied URL schemes (explicit block). */
const DENIED_URL_SCHEMES = new Set(['javascript:', 'data:', 'vbscript:', 'blob:'])

/** Pattern matching on* event handler attributes. */
const EVENT_HANDLER_PATTERN = /^on\w+$/i

/** Attributes that accept URL values. */
const URL_ATTRIBUTES = new Set(['href', 'src', 'action', 'formaction', 'poster', 'background'])

/** Safe attributes allowed on any element. */
const SAFE_ATTRIBUTES = new Set([
  'href', 'src', 'alt', 'title', 'class', 'id',
  'width', 'height', 'colspan', 'rowspan', 'scope',
  'target', 'rel',
])

/**
 * Sanitize an HTML string by removing dangerous elements and attributes.
 *
 * This strips:
 * - Script, style, iframe, object, embed, form tags (with content)
 * - All on* event handler attributes (onclick, onerror, onload, etc.)
 * - javascript:, data:, vbscript: URL schemes
 *
 * Allows: b, i, a, p, br, ul, ol, li, h1-h6, blockquote, pre, code,
 * table elements, img (with sanitized src).
 *
 * This is a regex-based sanitizer suitable for the bridge use case.
 * For production deployment, consider a DOM-based sanitizer like DOMPurify.
 *
 * @param html - Raw HTML string to sanitize.
 * @returns Sanitized HTML string.
 */
export function sanitizeHtml(html: string): string {
  let result = html

  // Step 0: Strip null bytes (bypass prevention)
  result = result.replace(/\\0/g, '')

  // Step 1: Remove dangerous tags and their content entirely
  for (const tag of STRIP_TAGS_WITH_CONTENT) {
    const regex = new RegExp(`<${tag}[^>]*>[\\s\\S]*?</${tag}>`, 'gi')
    result = result.replace(regex, '')
    // Also remove self-closing variants
    const selfClose = new RegExp(`<${tag}[^>]*/?>`, 'gi')
    result = result.replace(selfClose, '')
  }

  // Step 2: Remove HTML comments (can contain conditional IE directives)
  result = result.replace(/<!--[\s\S]*?-->/g, '')

  // Step 3: Process remaining tags
  result = result.replace(/<\/?([a-zA-Z][a-zA-Z0-9]*)\b([^>]*)?\/?>/g, (match, tagName: string, attrs: string | undefined) => {
    const tag = tagName.toLowerCase()

    // Remove unknown tags (keep content, strip tag)
    if (!ALLOWED_TAGS.has(tag)) {
      return ''
    }

    // For closing tags, just return clean closing tag
    if (match.startsWith('</')) {
      return `</${tag}>`
    }

    // Sanitize attributes
    const cleanAttrs = sanitizeAttributes(tag, attrs ?? '')
    const selfClosing = match.endsWith('/>') ? ' /' : ''

    return cleanAttrs ? `<${tag} ${cleanAttrs}${selfClosing}>` : `<${tag}${selfClosing}>`
  })

  return result
}

/**
 * Sanitize attributes for a given tag.
 * Removes event handlers, dangerous URLs, and unknown attributes.
 */
function sanitizeAttributes(tag: string, attrString: string): string {
  if (!attrString.trim()) return ''

  const attrs: string[] = []
  // Match attribute patterns: name="value", name='value', name=value, name
  const attrRegex = /([a-zA-Z][\w-]*)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|(\S+)))?/g
  let attrMatch: RegExpExecArray | null

  while ((attrMatch = attrRegex.exec(attrString)) !== null) {
    const name = attrMatch[1]!.toLowerCase()
    const value = attrMatch[2] ?? attrMatch[3] ?? attrMatch[4] ?? ''

    // Skip event handlers
    if (EVENT_HANDLER_PATTERN.test(name)) continue

    // Skip dangerous attributes
    if (name === 'style') continue // Style can enable CSS-based attacks
    if (name === 'srcdoc') continue // srcdoc can contain arbitrary HTML

    // Only allow known safe attributes
    if (!SAFE_ATTRIBUTES.has(name)) continue

    // Sanitize URL attributes
    if (URL_ATTRIBUTES.has(name)) {
      const sanitizedUrl = sanitizeUrl(value)
      if (sanitizedUrl === null) continue
      attrs.push(`${name}="${escapeAttrValue(sanitizedUrl)}"`)
    } else {
      attrs.push(`${name}="${escapeAttrValue(value)}"`)
    }
  }

  // For anchor tags, ensure rel="noopener noreferrer" and target="_blank"
  if (tag === 'a') {
    if (!attrs.some(a => a.startsWith('rel='))) {
      attrs.push('rel="noopener noreferrer"')
    }
    if (!attrs.some(a => a.startsWith('target='))) {
      attrs.push('target="_blank"')
    }
  }

  return attrs.join(' ')
}

/**
 * Sanitize a URL value, returning null if the scheme is dangerous.
 *
 * Allows: https:, http:, cid:, mailto:
 * Denies: javascript:, data:, vbscript:, blob:
 */
function sanitizeUrl(url: string): string | null {
  const trimmed = url.trim()

  // Allow relative URLs (no scheme)
  if (!trimmed.includes(':')) return trimmed

  // Decode HTML entities and normalize
  const decoded = trimmed
    .replace(/&#x([0-9a-f]+);/gi, (_m, hex: string) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_m, dec: string) => String.fromCharCode(parseInt(dec, 10)))
    .replace(/\s+/g, '') // Remove whitespace that could obfuscate schemes

  // Extract scheme
  const colonIndex = decoded.indexOf(':')
  if (colonIndex === -1) return trimmed

  const scheme = decoded.slice(0, colonIndex + 1).toLowerCase()

  if (DENIED_URL_SCHEMES.has(scheme)) return null
  if (ALLOWED_URL_SCHEMES.has(scheme)) return trimmed

  // Unknown scheme — deny by default
  return null
}

/**
 * Escape special characters in an HTML attribute value.
 */
function escapeAttrValue(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
}

/**
 * Strip all HTML tags, returning plain text.
 * Useful for generating text/plain alternatives.
 *
 * @param html - HTML string.
 * @returns Plain text with tags removed.
 */
export function stripHtml(html: string): string {
  return html
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/p>/gi, '\n\n')
    .replace(/<\/div>/gi, '\n')
    .replace(/<\/h[1-6]>/gi, '\n\n')
    .replace(/<\/li>/gi, '\n')
    .replace(/<\/tr>/gi, '\n')
    .replace(/<[^>]+>/g, '')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/\n{3,}/g, '\n\n')
    .trim()
}
