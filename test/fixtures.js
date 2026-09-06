import { SignJWT, UnsecuredJWT, exportJWK, generateKeyPair, createLocalJWKSet } from 'jose'

export const TEAM = 'aldertwig'
export const ISSUER = `https://${TEAM}.cloudflareaccess.com`
export const AUD = 'a'.repeat(64)
export const OTHER_AUD = 'b'.repeat(64)

/**
 * A real RSA keypair and a real JWKS. Every negative case below is a genuine
 * signature over genuine claims — not a valid token with characters edited out,
 * which is a different and much weaker test.
 */
export async function makeKeys(kid = 'k1') {
  const { publicKey, privateKey } = await generateKeyPair('RS256', { extractable: true })
  const jwk = { ...(await exportJWK(publicKey)), kid, alg: 'RS256', use: 'sig' }
  return { publicKey, privateKey, jwk, kid }
}

/** A keyResolver over a fixed set of JWKs — stands in for the remote JWKS. */
export function localResolver(...jwks) {
  return createLocalJWKSet({ keys: jwks })
}

const now = () => Math.floor(Date.now() / 1000)

/** Claim set of a Cloudflare Access *identity* token. */
export function userClaims(overrides = {}) {
  return {
    email: 'eric@example.com',
    type: 'app',
    identity_nonce: 'nonce123',
    country: 'GB',
    sub: '00000000-0000-4000-8000-000000000001',
    ...overrides,
  }
}

/**
 * Claim set of a Cloudflare Access *service token*: `common_name` present,
 * no `email`, no `identity_nonce`, no `country`, and `sub` the EMPTY STRING.
 */
export function serviceClaims(overrides = {}) {
  return { type: 'app', common_name: 'a1-collector.access', sub: '', ...overrides }
}

/**
 * Mint a token. Anything passed as `undefined` in `claims` is omitted, so a test
 * can build a token that genuinely lacks a claim rather than one that carries a
 * falsy value.
 */
export async function mint(privateKey, claims = {}, opts = {}) {
  const {
    kid = 'k1',
    alg = 'RS256',
    iss = ISSUER,
    aud = AUD,
    iat = now(),
    exp = now() + 3600,
    nbf,
  } = opts

  const payload = {}
  for (const [key, value] of Object.entries(claims)) {
    if (value !== undefined) payload[key] = value
  }

  let jwt = new SignJWT(payload).setProtectedHeader({ alg, kid })
  if (iss !== null) jwt = jwt.setIssuer(iss)
  if (aud !== null) jwt = jwt.setAudience(aud)
  if (iat !== null) jwt = jwt.setIssuedAt(iat)
  if (exp !== null) jwt = jwt.setExpirationTime(exp)
  if (nbf !== undefined) jwt = jwt.setNotBefore(nbf)
  return jwt.sign(privateKey)
}

/** An `alg: none` token — the classic downgrade. */
export function mintUnsecured(claims = userClaims()) {
  return new UnsecuredJWT(claims)
    .setIssuer(ISSUER)
    .setAudience(AUD)
    .setIssuedAt()
    .setExpirationTime(now() + 3600)
    .encode()
}

/** Flip the signature without touching the header or payload. */
export function corruptSignature(token) {
  const parts = token.split('.')
  const sig = parts[2]
  parts[2] = sig.slice(0, -4) + (sig.slice(-4) === 'AAAA' ? 'BBBB' : 'AAAA')
  return parts.join('.')
}

export const headerRequest = (token, extra = {}) => ({
  headers: { 'cf-access-jwt-assertion': token, ...extra },
})
