import { createRemoteJWKSet, jwtVerify } from 'jose'
import { AccessAuthError, AccessConfigError } from './errors.js'
import { extractToken } from './extract.js'

export { AccessAuthError, AccessConfigError }

/**
 * Cloudflare signs Access application tokens with RS256 and nothing else.
 * Pinning is belt and braces — jose's JWKS resolver already refuses to hand a
 * public RSA key to an HMAC verifier — but the pin is the guarantee we control.
 */
const ALGORITHMS = ['RS256']

/**
 * `exp` is NOT required by a JWT library unless you ask for it: a token with no
 * `exp` claim verifies forever. Cloudflare always sets one, and that is exactly
 * the third-party habit that must not be the only thing standing between a
 * session and a permanent bearer key.
 */
const REQUIRED_CLAIMS = ['exp', 'iat', 'iss', 'aud', 'type']

/**
 * A Cloudflare team name is a single DNS label; it interpolates straight into
 * the JWKS URL. One regex turns an env-var typo into a startup crash instead of
 * a silent transfer of trust to whatever host the typo happens to name.
 */
const TEAM_DOMAIN = /^[a-z0-9][a-z0-9-]{0,61}$/

const ALLOW_KINDS = new Set(['user', 'service', 'any'])

/**
 * Build a verifier for one Cloudflare Access application.
 *
 * Construct this ONCE per process, at module scope. The returned object owns
 * the JWKS cache; building it per request re-fetches Cloudflare's certificates
 * on every call.
 *
 * @param {object} config
 * @param {string} config.teamDomain    bare label, e.g. `aldertwig`
 * @param {string|string[]} config.audience  this application's AUD tag. An array
 *   is supported and WIDENS the trust boundary: a token bearing any one of the
 *   listed AUDs is accepted here. Pass a single string unless you mean that.
 * @param {'user'|'service'|'any'} [config.allow='user']
 * @param {number} [config.clockTolerance=30] seconds
 * @param {boolean} [config.acceptCookie=false] also read the token from the
 *   `CF_Authorization` cookie. Off by default: a cookie is attached by the
 *   browser to any request from any origin, and accepting it lets a cross-site
 *   request aimed straight at the origin hostname authenticate on ambient
 *   authority. Turn on only behind something that strips unknown headers.
 * @param {string} [config.originSecret] when set, a request must ALSO carry this
 *   exact value in `x-aldertwig-origin` — the shared half of a Cloudflare
 *   Transform Rule, so a direct hit on the origin hostname fails before the JWT
 *   is even parsed. This is strictly an AND with the JWT and can never stand in
 *   for it: a shared secret that authenticates on its own is a static bearer key
 *   in a header, which is the thing this module exists to replace.
 * @param {object} [config.jwks] passed through to jose's remote JWKS resolver
 */
export function createAccessVerifier(config = {}) {
  const {
    teamDomain,
    audience,
    allow = 'user',
    clockTolerance = 30,
    acceptCookie = false,
    originSecret,
    jwks: jwksOptions = {},
  } = config

  if (typeof teamDomain !== 'string' || !TEAM_DOMAIN.test(teamDomain)) {
    throw new AccessConfigError(
      `teamDomain must be a bare DNS label matching ${TEAM_DOMAIN}, got ${JSON.stringify(teamDomain)}`,
    )
  }

  const audiences = normaliseAudience(audience)

  if (!ALLOW_KINDS.has(allow)) {
    throw new AccessConfigError(`allow must be one of ${[...ALLOW_KINDS].join(', ')}, got ${JSON.stringify(allow)}`)
  }
  if (!Number.isFinite(clockTolerance) || clockTolerance < 0) {
    throw new AccessConfigError(`clockTolerance must be a non-negative number of seconds, got ${clockTolerance}`)
  }
  if (originSecret !== undefined && (typeof originSecret !== 'string' || originSecret === '')) {
    throw new AccessConfigError('originSecret, when set, must be a non-empty string')
  }
  if (typeof acceptCookie !== 'boolean') {
    throw new AccessConfigError(`acceptCookie must be a boolean, got ${JSON.stringify(acceptCookie)}`)
  }

  const issuer = `https://${teamDomain}.cloudflareaccess.com`

  // jose's resolver already implements Cloudflare's rotation model: it refetches
  // on an unmatched `kid`, but only once per `cooldownDuration`. That cooldown is
  // what stops a flood of tokens bearing random `kid`s turning our auth path into
  // a request amplifier against Cloudflare.
  const getKey =
    jwksOptions.keyResolver ?? createRemoteJWKSet(new URL(`${issuer}/cdn-cgi/access/certs`), jwksOptions)

  return {
    issuer,
    audiences: Object.freeze([...audiences]),
    allow,

    /**
     * @param {unknown} input Request | IncomingMessage | headers object | raw token
     * @returns {Promise<AccessPrincipal>}
     * @throws {AccessAuthError} always 401; never resolves for an unverified caller
     */
    async verify(input) {
      // Order is deliberate and load-bearing: the origin secret is checked
      // first, but passing it grants nothing on its own — extraction and full
      // JWT verification still run, and a request with the secret and no
      // assertion header fails `missing_token`.
      if (originSecret !== undefined) {
        await assertOriginSecret(input, originSecret)
      }

      const token = extractToken(input, { acceptCookie })

      let payload
      try {
        ;({ payload } = await jwtVerify(token, getKey, {
          issuer,
          audience: audiences.length === 1 ? audiences[0] : audiences,
          algorithms: ALGORITHMS,
          requiredClaims: REQUIRED_CLAIMS,
          clockTolerance,
        }))
      } catch (cause) {
        throw translate(cause)
      }

      const principal = toPrincipal(payload, audiences)

      if (allow !== 'any' && principal.kind !== allow) {
        throw new AccessAuthError(
          'principal_kind_not_allowed',
          `this application accepts ${allow} tokens, got a ${principal.kind} token`,
        )
      }
      return principal
    },
  }
}

function normaliseAudience(audience) {
  const list = Array.isArray(audience) ? audience : [audience]
  if (list.length === 0) {
    throw new AccessConfigError('audience is required — there is no "accept any audience" mode')
  }
  for (const entry of list) {
    if (typeof entry !== 'string' || entry.trim() === '') {
      // An unset CF_ACCESS_AUD arrives as undefined. It must crash here rather
      // than become a verifier that checks everything except which app the
      // token was minted for — the only claim separating our own applications.
      throw new AccessConfigError(`audience must be a non-empty string, got ${JSON.stringify(entry)}`)
    }
  }
  return list.map((entry) => entry.trim())
}

/**
 * @typedef {object} AccessPrincipal
 * @property {'user'|'service'} kind
 * @property {string|null} email       null for service tokens
 * @property {string|null} sub         null for service tokens (Cloudflare sends '')
 * @property {string|null} commonName  set only for service tokens
 * @property {string|null} country
 * @property {string} audience         the configured AUD that matched
 * @property {Date} expiresAt
 * @property {Readonly<object>} claims raw verified payload
 */
function toPrincipal(payload, audiences) {
  const tokenAudiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud]
  const matched = audiences.find((candidate) => tokenAudiences.includes(candidate))

  // Cloudflare's own claim table: a service token carries `common_name` and no
  // `email`, and its `sub` is the empty string. A helper that returned a bare
  // email string would return undefined here while reporting success.
  const email = typeof payload.email === 'string' && payload.email !== '' ? payload.email : null
  const commonName = typeof payload.common_name === 'string' && payload.common_name !== '' ? payload.common_name : null
  const sub = typeof payload.sub === 'string' && payload.sub !== '' ? payload.sub : null

  return Object.freeze({
    kind: email === null ? 'service' : 'user',
    email,
    sub,
    commonName,
    country: typeof payload.country === 'string' && payload.country !== '' ? payload.country : null,
    audience: matched,
    expiresAt: new Date(payload.exp * 1000),
    claims: Object.freeze({ ...payload }),
  })
}

const CLAIM_CODES = { aud: 'wrong_audience', iss: 'wrong_issuer', nbf: 'not_yet_valid' }

function translate(cause) {
  if (cause instanceof AccessAuthError) return cause

  switch (cause?.code) {
    case 'ERR_JWT_EXPIRED':
      return new AccessAuthError('expired', 'exp is in the past', { cause })
    case 'ERR_JWT_CLAIM_VALIDATION_FAILED':
      return new AccessAuthError(
        cause.reason === 'missing' ? 'missing_claim' : (CLAIM_CODES[cause.claim] ?? 'missing_claim'),
        `claim ${cause.claim}: ${cause.reason}`,
        { cause },
      )
    case 'ERR_JWKS_NO_MATCHING_KEY':
    case 'ERR_JWKS_MULTIPLE_MATCHING_KEYS':
      return new AccessAuthError('unknown_key', 'no single matching key for this kid', { cause })
    case 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED':
    case 'ERR_JOSE_ALG_NOT_ALLOWED':
    case 'ERR_JOSE_NOT_SUPPORTED':
      return new AccessAuthError('bad_signature', cause.message, { cause })
    case 'ERR_JWS_INVALID':
    case 'ERR_JWT_INVALID':
      return new AccessAuthError('malformed_token', cause.message, { cause })
    case 'ERR_JWKS_TIMEOUT':
      return new AccessAuthError('jwks_unavailable', 'timed out fetching the Cloudflare JWKS', { cause })
    default:
      // A network failure fetching the JWKS lands here as a bare TypeError. It
      // is our outage, not their bad token — it should be loud in logs and still
      // 401 on the wire. Fail closed: an unreachable JWKS is a lockout, which is
      // the correct trade for internal tooling and the reason this module must
      // never sit in front of a paying customer's login.
      return new AccessAuthError('jwks_unavailable', `could not verify: ${cause?.message ?? cause}`, { cause })
  }
}

async function assertOriginSecret(input, expected) {
  const headers = input && typeof input === 'object' ? input : {}
  const presented = readOriginHeader(headers)
  if (typeof presented !== 'string' || !(await constantTimeEquals(presented, expected))) {
    throw new AccessAuthError('missing_origin_secret', 'request did not arrive through the Cloudflare edge')
  }
}

function readOriginHeader(input) {
  const headers = typeof input.headers === 'object' && input.headers !== null ? input.headers : input
  if (typeof headers.get === 'function') return headers.get('x-aldertwig-origin')
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === 'x-aldertwig-origin') {
      const value = headers[key]
      return Array.isArray(value) ? value[0] : value
    }
  }
  return null
}

/**
 * Hash both sides before comparing so the comparison is over two fixed 32-byte
 * digests: equal length regardless of input, so the loop leaks nothing about
 * how much of the secret was correct, or how long it is.
 */
async function constantTimeEquals(a, b) {
  const encoder = new TextEncoder()
  const [left, right] = await Promise.all([
    crypto.subtle.digest('SHA-256', encoder.encode(a)),
    crypto.subtle.digest('SHA-256', encoder.encode(b)),
  ])
  const x = new Uint8Array(left)
  const y = new Uint8Array(right)
  let diff = 0
  for (let i = 0; i < x.length; i += 1) diff |= x[i] ^ y[i]
  return diff === 0
}
