// ─── SMTP <-> NOSTR Mail Bridge — HTML Sanitization ─────────────────────────
// Sanitizes HTML content from email for safe rendering and conversion.
// Strips dangerous tags, attributes, and URL schemes.
//
// IMPLEMENTATION NOTE — F-SAN-01 / F-DEPS-01 (fail-closed sanitization):
//   The bridge uses `sanitize-html` (DOM-based, audited) as the ONLY path that
//   emits live HTML. `sanitize-html` is a hard dependency. If it cannot be
//   resolved at runtime we DO NOT fall back to the regex sanitizer (which was
//   bypassable — e.g. `<img alt="a>b" onerror=...>` leaked the handler).
//   Instead we fail closed: strip all tags and HTML-escape the text so no
//   markup can execute. The legacy `regexSanitize` is retained only for the
//   explicit regression test that documents its weakness; it is never the
//   live path.

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
])

/**
 * Lazily-bound preferred implementation. When `sanitize-html` resolves at
 * module init we point this at a thin adapter; otherwise the regex fallback
 * is used. The `let` (not `const`) is deliberate so a future override site
 * (e.g. test injection) can swap the implementation without rebuilds.
 */
let preferred: ((html: string) => string) | null = null

// Module-init: try to wire `sanitize-html`. The dynamic require is wrapped so
// a missing package or environment without CJS bridge is non-fatal — we just
// fall through to the regex implementation.
try {
  const mod = await import('node:module')
  const requireFn = mod.createRequire(import.meta.url)
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const lib: any = requireFn('sanitize-html')
  if (lib && typeof lib === 'function') {
    preferred = (html: string): string =>
      lib(html, {
        allowedTags: ['p', 'br', 'strong', 'em', 'code', 'pre', 'a', 'ul', 'ol', 'li', 'blockquote', 'h1', 'h2', 'h3', 'h4'],
        allowedAttributes: { a: ['href', 'title', 'rel', 'target'] },
        allowedSchemes: ['http', 'https', 'mailto'],
        disallowedTagsMode: 'discard',
        // Force safe navigation on every anchor (prevents reverse tabnabbing
        // and referrer leakage), matching the bridge's prior anchor hardening.
        transformTags: {
          a: (tagName: string, attribs: Record<string, string>) => ({
            tagName,
            attribs: { ...attribs, rel: 'noopener noreferrer', target: '_blank' },
          }),
        },
      })
  }
} catch {
  // sanitize-html not installed — fall back to regex implementation.
  preferred = null
}

/**
 * Sanitize an HTML string by removing dangerous elements and attributes.
 *
 * Prefers `sanitize-html` (DOM-based, well audited) when available; falls
 * back to the regex implementation in `regexSanitize` otherwise. This is the
 * single export call sites should use.
 *
 * Strips:
 * - Script, style, iframe, object, embed, form tags (with content)
 * - All on* event handler attributes (onclick, onerror, onload, etc.)
 * - javascript:, data:, vbscript: URL schemes
 *
 * Allows: b, i, a, p, br, ul, ol, li, h1-h6, blockquote, pre, code,
 * table elements, img (with sanitized src) — under the regex path. The
 * sanitize-html path uses a tighter allowlist (no img/style/etc).
 *
 * @param html - Raw HTML string to sanitize.
 * @returns Sanitized HTML string.
 */
let warnedMissingSanitizer = false

export function sanitizeHtml(html: string): string {
  if (preferred) return preferred(html)
  // F-SAN-01: fail closed. The strong sanitizer is unavailable, so we MUST
  // NOT emit attacker HTML as live markup. Strip all tags and escape the
  // remaining text — formatting is lost, but no script/handler can survive.
  if (!warnedMissingSanitizer) {
    warnedMissingSanitizer = true
    console.error(
      '[sanitize] sanitize-html is not installed — failing closed to plain-text escaping. ' +
        'Install sanitize-html to restore rich HTML handling.',
    )
  }
  return escapeAttrValue(stripHtml(html))
}

/**
 * Regex-based fallback sanitizer. Retained as the zero-dependency default
 * implementation. Slower and harder to audit than `sanitize-html`, but does
 * not require any package install. Exported for tests that want to assert
 * the fallback behaviour explicitly.
 *
 * @param html - Raw HTML string to sanitize.
 * @returns Sanitized HTML string.
 */
export function regexSanitize(html: string): string {
  let result = html

  // Phase 1: Remove dangerous tags and their content entirely
  for (const tag of STRIP_TAGS_WITH_CONTENT) {
    const regex = new RegExp(`<${tag}[^>]*>[\\s\\S]*?</${tag}>`, 'gi')
    result = result.replace(regex, '')
    // Also remove self-closing variants
    const selfClose = new RegExp(`<${tag}[^>]*/?>`, 'gi')
    result = result.replace(selfClose, '')
  }

  // Phase 2: Remove HTML comments (can contain conditional IE directives)
  result = result.replace(/<!--[\s\S]*?-->/g, '')

  // Phase 3: Process remaining tags
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

  // For anchor tags, force safe navigation attributes.
  if (tag === 'a') {
    attrs.push('rel="noopener noreferrer"')
    attrs.push('target="_blank"')
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

  // Decode HTML entities and normalize
  const decoded = trimmed
    .replace(/&#x([0-9a-f]+);/gi, (_m, hex: string) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_m, dec: string) => String.fromCharCode(parseInt(dec, 10)))
    .replace(/\s+/g, '') // Remove whitespace that could obfuscate schemes

  // Reject protocol-relative or scheme-less URLs. In bridge-rendered HTML we
  // only allow explicit safe schemes.
  if (!decoded.includes(':')) return null
  if (decoded.startsWith('//')) return null

  let parsed: URL
  try {
    parsed = new URL(decoded)
  } catch {
    return null
  }

  const scheme = parsed.protocol.toLowerCase()

  if (DENIED_URL_SCHEMES.has(scheme)) return null
  if (ALLOWED_URL_SCHEMES.has(scheme)) return parsed.toString()

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
