// ─── SMTP <-> NOSTR Mail Bridge — Type Definitions ─────────────────────────
// Bridge-specific types for configuration, converted messages, and results.

/** Bridge server configuration. */
export interface BridgeConfig {
  /** SMTP port for inbound mail (default: 25). */
  smtpPort: number
  /** SMTP submission port for authenticated senders (default: 587). */
  smtpSubmissionPort: number
  /** Domain name this bridge serves (e.g., "nostr-bridge.example.com"). */
  domain: string
  /** Hostname for SMTP EHLO/HELO. */
  hostname: string

  /** DKIM private key (PEM format) for outbound signing. */
  dkimPrivateKey: string
  /** DKIM selector (e.g., "default"). */
  dkimSelector: string

  /** NOSTR relay URLs for publishing inbound-converted events. */
  relays: string[]
  /** Bridge NOSTR private key (hex, 32 bytes). Used to sign gift wraps. */
  bridgePrivateKeyHex: string

  /** Blossom server URLs for uploading attachments. */
  blossomServers: string[]

  /** Outbound SMTP transport config (for sending email from NOSTR). */
  outboundSmtp: OutboundSmtpConfig

  /** HTTP health-check port (default: 8080). */
  healthPort: number

  /** Maximum inbound message size in bytes (default: 25MB). */
  maxMessageSize: number

  /** Whether to require SPF/DKIM pass for inbound mail. */
  requireAuth: boolean
}

/** SMTP transport configuration for outbound email. */
export interface OutboundSmtpConfig {
  /** SMTP host. */
  host: string
  /** SMTP port. */
  port: number
  /** Use TLS. */
  secure: boolean
  /** SMTP auth credentials (optional for local relay). */
  auth?: {
    user: string
    pass: string
  }
}

/** A parsed inbound email mapped to NOSTR Mail structure. */
export interface BridgedMessage {
  /** Original sender email address. */
  fromEmail: string
  /** Sender display name, if available. */
  fromName?: string
  /** Recipient email addresses (To). */
  toEmails: string[]
  /** CC email addresses. */
  ccEmails: string[]
  /** BCC email addresses. */
  bccEmails: string[]
  /** Email subject. */
  subject: string
  /** Body content (Markdown-converted or plain text). */
  body: string
  /** Body content type after conversion. */
  contentType: 'text/plain' | 'text/markdown'
  /** Parsed attachments ready for Blossom upload. */
  attachments: BufferAttachment[]
  /** Email Message-ID header. */
  messageId?: string
  /** In-Reply-To header. */
  inReplyTo?: string
  /** References header values. */
  references?: string[]
  /** SPF/DKIM/DMARC authentication results. */
  authResults: AuthResults
  /** Original MIME headers (subset). */
  originalHeaders: Record<string, string>
}

/** An attachment with its raw data buffer. */
export interface BufferAttachment {
  /** Original filename. */
  filename: string
  /** MIME type. */
  mimeType: string
  /** Raw file data. */
  data: Uint8Array
  /** Content-ID for inline images (e.g., "cid:image001"). */
  contentId?: string
  /** Whether this is an inline attachment. */
  inline: boolean
}

/** Email authentication results. */
export interface AuthResults {
  /** SPF result. */
  spf: 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'temperror' | 'permerror'
  /** DKIM result. */
  dkim: 'pass' | 'fail' | 'none' | 'temperror' | 'permerror'
  /** DMARC result. */
  dmarc: 'pass' | 'fail' | 'none' | 'temperror' | 'permerror'
}

/** Result of a conversion operation. */
export interface ConversionResult<T = unknown> {
  /** Whether the conversion succeeded. */
  success: boolean
  /** Converted data (present on success). */
  data?: T
  /** Error message (present on failure). */
  error?: string
  /** Warnings (non-fatal issues). */
  warnings: string[]
}

/** NOSTR Mail rumor structure (kind 1111, unsigned). */
export interface MailRumor {
  kind: 1111
  pubkey: string
  created_at: number
  tags: string[][]
  content: string
}

/** Resolved NOSTR identity from a NIP-05 or pubkey lookup. */
export interface ResolvedIdentity {
  /** Hex public key. */
  pubkey: string
  /** Relay URLs from NIP-05 or kind 10002. */
  relays: string[]
  /** NIP-05 identifier, if resolved. */
  nip05?: string
  /** Display name from kind 0 metadata, if fetched. */
  displayName?: string
}

/** Identity mapping entry in the bridge database. */
export interface IdentityMapping {
  /** NOSTR hex public key. */
  pubkey: string
  /** Bridge-assigned email address (e.g., "npub1abc...@nostr-bridge.example.com"). */
  emailAddress: string
  /** When the mapping was created. */
  createdAt: number
  /** When the mapping was last used. */
  lastUsedAt: number
}

/** Outbound email message ready for SMTP sending. */
export interface OutboundEmail {
  /** From address (bridge domain). */
  from: string
  /** To addresses. */
  to: string[]
  /** CC addresses. */
  cc: string[]
  /** Subject line. */
  subject: string
  /** Plain text body. */
  text: string
  /** HTML body. */
  html: string
  /** MIME attachments. */
  attachments: MimeAttachment[]
  /** Message-ID header. */
  messageId: string
  /** In-Reply-To header, if this is a reply. */
  inReplyTo?: string
  /** References header, if threaded. */
  references?: string
  /** Custom headers. */
  headers: Record<string, string>
}

/** MIME attachment for outbound email. */
export interface MimeAttachment {
  filename: string
  content: Buffer | Uint8Array
  contentType: string
  /** Content-ID for inline images. */
  cid?: string
}
