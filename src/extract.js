import { AccessAuthError } from './errors.js'

const HEADER = 'cf-access-jwt-assertion'
const COOKIE = 'CF_Authorization'

/** A compact JWS is three base64url segments. Anything else is malformed. */
const COMPACT_JWS = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/

/**
 * Read one header from any of the four shapes a caller might hand us:
 * a Fetch `Request` / `Headers`, a Node `IncomingMessage`, or a plain object.
 * Node lowercases incoming header names; a hand-built object might not, so we
 * compare case-insensitively rather than trusting the caller.
 */
function readHeader(source, name) {
  if (!source) return null
  const headers = typeof source.headers === 'object' && source.headers !== null ? source.headers : source

  if (typeof headers.get === 'function') {
    return headers.get(name) ?? null
  }
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() !== name) continue
    const value = headers[key]
    // Node collapses repeats into an array for some headers.
    return Array.isArray(value) ? (value[0] ?? null) : (value ?? null)
  }
  return null
}

function readCookie(source, name) {
  const header = readHeader(source, 'cookie')
  if (typeof header !== 'string') return null
  for (const pair of header.split(';')) {
    const eq = pair.indexOf('=')
    if (eq === -1) continue
    if (pair.slice(0, eq).trim() !== name) continue
    return pair.slice(eq + 1).trim()
  }
  return null
}

/**
 * Pull the Access token out of a request.
 *
 * **Header only by default.** Cloudflare recommends the header because "the
 * cookie is not guaranteed to be passed", and the cookie carries a second
 * property we do not want: a browser attaches it by itself, to any request, from
 * any origin. That is ambient authority, and accepting it here would let a
 * cross-site POST sent *directly at the origin hostname* — bypassing the
 * Cloudflare edge entirely — authenticate on a cookie the victim's browser
 * supplied. Header-only makes that request fail with `missing_token`.
 *
 * It does not fix CSRF (see the README non-goal): a cross-site request that goes
 * *through* the edge still gets a genuine header injected. It removes the one
 * variant this module can remove for free.
 *
 * `acceptCookie: true` restores the fallback for a caller that has something in
 * front of it stripping unknown headers.
 *
 * Absence is `missing_token` — a hard failure, never a default-allow. This is
 * the case that matters: `*.netlify.app` and `*.fly.dev` origins stay publicly
 * reachable and are not behind Access, so a request with no header at all is
 * the ordinary shape of an attack, not an edge case.
 *
 * @param {unknown} input Request | IncomingMessage | headers object | raw token
 * @param {{ acceptCookie?: boolean }} [options]
 * @returns {string}
 */
export function extractToken(input, options = {}) {
  if (typeof input === 'string') {
    return assertCompact(input.trim())
  }
  if (input === null || typeof input !== 'object') {
    throw new AccessAuthError('missing_token', `cannot read a token from ${typeof input}`)
  }

  const raw = readHeader(input, HEADER) ?? (options.acceptCookie ? readCookie(input, COOKIE) : null)
  if (typeof raw !== 'string' || raw.trim() === '') {
    throw new AccessAuthError(
      'missing_token',
      options.acceptCookie ? `no ${HEADER} header and no ${COOKIE} cookie` : `no ${HEADER} header`,
    )
  }
  return assertCompact(raw.trim())
}

function assertCompact(token) {
  if (token === '') {
    throw new AccessAuthError('missing_token', 'token is empty')
  }
  // Access does not send `Bearer `. Accepting it would mean silently accepting a
  // token routed here by something that thinks this is an OAuth endpoint.
  if (!COMPACT_JWS.test(token)) {
    throw new AccessAuthError('malformed_token', 'not a compact JWS')
  }
  return token
}
