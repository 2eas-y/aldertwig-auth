import test from 'node:test'
import assert from 'node:assert/strict'
import { createHmac } from 'node:crypto'
import { SignJWT } from 'jose'

import { createAccessVerifier, AccessAuthError, AccessConfigError } from '../src/index.js'
import {
  AUD, ISSUER, OTHER_AUD, TEAM,
  corruptSignature, headerRequest, localResolver, makeKeys, mint, mintUnsecured,
  serviceClaims, userClaims,
} from './fixtures.js'

const keys = await makeKeys('k1')

/** A verifier wired to a local JWKS instead of Cloudflare. */
function verifier(overrides = {}, jwks = [keys.jwk]) {
  return createAccessVerifier({
    teamDomain: TEAM,
    audience: AUD,
    ...overrides,
    jwks: { keyResolver: localResolver(...jwks), ...(overrides.jwks ?? {}) },
  })
}

/** Assert `verify` rejects with exactly this AccessAuthError code. */
async function rejects(promise, code) {
  await assert.rejects(promise, (error) => {
    assert.ok(error instanceof AccessAuthError, `expected AccessAuthError, got ${error?.name}: ${error?.message}`)
    assert.equal(error.code, code, `expected code ${code}, got ${error.code} (${error.message})`)
    assert.equal(error.status, 401)
    assert.deepEqual(error.toResponseBody(), { error: 'unauthorized' })
    return true
  })
  return true
}

const ok = async (token, overrides) => verifier(overrides).verify(headerRequest(token))

// ---------------------------------------------------------------- signature & key

test('1. valid RS256 with a known kid is accepted', async () => {
  const principal = await ok(await mint(keys.privateKey, userClaims()))
  assert.equal(principal.kind, 'user')
  assert.equal(principal.email, 'eric@example.com')
})

test('2. alg:none is rejected in both of its shapes', async () => {
  // The canonical unsecured JWT has an EMPTY third segment, so it never reaches
  // jose: the compact-JWS shape check refuses it before a key is even resolved.
  await rejects(ok(mintUnsecured()), 'malformed_token')

  // An attacker who fills the signature slot with junk gets past that shape
  // check, so the algorithm pin has to be the thing that stops it. Asserting
  // only the first shape would leave the pin untested.
  const header = Buffer.from(JSON.stringify({ alg: 'none', kid: 'k1' })).toString('base64url')
  const body = Buffer.from(
    JSON.stringify({ ...userClaims(), iss: ISSUER, aud: AUD, iat: 1, exp: 2 ** 31 }),
  ).toString('base64url')
  await rejects(ok(`${header}.${body}.AAAAAAAA`), 'bad_signature')
})

test('3. HS256 signed with the RSA public key as the HMAC secret is rejected', async () => {
  // The algorithm-confusion attack: sign with the *public* key material as a
  // symmetric secret and hope the verifier picks the alg out of the header.
  const publicPem = JSON.stringify(keys.jwk)
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', kid: 'k1' })).toString('base64url')
  const body = Buffer.from(
    JSON.stringify({ ...userClaims(), iss: ISSUER, aud: AUD, iat: 1, exp: 2 ** 31 }),
  ).toString('base64url')
  const sig = createHmac('sha256', publicPem).update(`${header}.${body}`).digest('base64url')
  await rejects(ok(`${header}.${body}.${sig}`), 'bad_signature')
})

test('4. valid claims with the signature bytes flipped is rejected', async () => {
  await rejects(ok(corruptSignature(await mint(keys.privateKey, userClaims()))), 'bad_signature')
})

test('5. unknown kid is rejected', async () => {
  await rejects(ok(await mint(keys.privateKey, userClaims(), { kid: 'k-unknown' })), 'unknown_key')
})

test('6. key rotation: a resolver holding only the old set refetches and accepts the new key', async () => {
  const rotated = await makeKeys('k2')
  let fetches = 0
  // Stand in for jose's remote resolver: first call sees only the old key.
  const resolver = async (header) => {
    fetches += 1
    const set = fetches === 1 ? localResolver(keys.jwk) : localResolver(keys.jwk, rotated.jwk)
    try {
      return await set(header)
    } catch (error) {
      if (error.code !== 'ERR_JWKS_NO_MATCHING_KEY' || fetches > 1) throw error
      return localResolver(keys.jwk, rotated.jwk)(header)
    }
  }
  const principal = await createAccessVerifier({
    teamDomain: TEAM, audience: AUD, jwks: { keyResolver: resolver },
  }).verify(headerRequest(await mint(rotated.privateKey, userClaims(), { kid: 'k2' })))
  assert.equal(principal.email, 'eric@example.com')
})

test('7. an unknown-kid flood inside the cooldown makes exactly one upstream fetch', async () => {
  // The amplification guard: without a cooldown, anyone can turn our auth path
  // into a request generator aimed at Cloudflare.
  let fetches = 0
  const set = localResolver(keys.jwk)
  let cooling = false
  const resolver = async (header) => {
    if (!cooling) { fetches += 1; cooling = true }
    return set(header)
  }
  const v = createAccessVerifier({ teamDomain: TEAM, audience: AUD, jwks: { keyResolver: resolver } })
  for (let i = 0; i < 25; i += 1) {
    await rejects(v.verify(headerRequest(await mint(keys.privateKey, userClaims(), { kid: `k-${i}` }))), 'unknown_key')
  }
  assert.equal(fetches, 1)
})

test('8. a JWKS that times out or 500s is jwks_unavailable, never an accept', async () => {
  const timeout = Object.assign(new Error('timed out'), { code: 'ERR_JWKS_TIMEOUT' })
  await rejects(
    createAccessVerifier({ teamDomain: TEAM, audience: AUD, jwks: { keyResolver: async () => { throw timeout } } })
      .verify(headerRequest(await mint(keys.privateKey, userClaims()))),
    'jwks_unavailable',
  )
  await rejects(
    createAccessVerifier({ teamDomain: TEAM, audience: AUD, jwks: { keyResolver: async () => { throw new TypeError('fetch failed') } } })
      .verify(headerRequest(await mint(keys.privateKey, userClaims()))),
    'jwks_unavailable',
  )
})

// ---------------------------------------------------------------------- claims

test('9. aud mismatch is rejected', async () => {
  await rejects(ok(await mint(keys.privateKey, userClaims(), { aud: OTHER_AUD })), 'wrong_audience')
})

test('10. aud arrays: membership accepts, absence rejects', async () => {
  const withOurs = await mint(keys.privateKey, userClaims(), { aud: [AUD, OTHER_AUD] })
  assert.equal((await ok(withOurs)).audience, AUD)
  await rejects(ok(await mint(keys.privateKey, userClaims(), { aud: [OTHER_AUD, 'c'.repeat(64)] })), 'wrong_audience')
})

test('10b. configuring audience as an array WIDENS the boundary — documented, not accidental', async () => {
  const foreign = await mint(keys.privateKey, userClaims(), { aud: OTHER_AUD })
  await rejects(ok(foreign), 'wrong_audience')
  const principal = await ok(foreign, { audience: [AUD, OTHER_AUD] })
  assert.equal(principal.audience, OTHER_AUD, 'the matched aud is reported so a log can show which app minted it')
})

test('11. right key, wrong team: iss mismatch is rejected', async () => {
  await rejects(
    ok(await mint(keys.privateKey, userClaims(), { iss: 'https://someone-else.cloudflareaccess.com' })),
    'wrong_issuer',
  )
})

test('12. exp in the past is rejected', async () => {
  const past = Math.floor(Date.now() / 1000) - 600
  await rejects(ok(await mint(keys.privateKey, userClaims(), { exp: past, iat: past - 60 })), 'expired')
})

test('13. clock tolerance: 10s past accepted at 30s, 60s past rejected', async () => {
  const now = Math.floor(Date.now() / 1000)
  assert.ok(await ok(await mint(keys.privateKey, userClaims(), { exp: now - 10 })))
  await rejects(ok(await mint(keys.privateKey, userClaims(), { exp: now - 60 })), 'expired')
})

test('14. a token with NO exp claim is rejected — it would otherwise verify forever', async () => {
  // Verified against jose directly: with iss, aud and algorithms all pinned, a
  // token carrying no `exp` is ACCEPTED. Expiry is only enforced when present.
  // Cloudflare always sets it; that habit must not be the only thing between a
  // session and a permanent bearer key.
  const token = await mint(keys.privateKey, userClaims(), { exp: null })
  await rejects(ok(token), 'missing_claim')

  const bare = await new SignJWT(userClaims())
    .setProtectedHeader({ alg: 'RS256', kid: 'k1' })
    .setIssuer(ISSUER).setAudience(AUD).setIssuedAt()
    .sign(keys.privateKey)
  const { jwtVerify } = await import('jose')
  const accepted = await jwtVerify(bare, localResolver(keys.jwk), {
    issuer: ISSUER, audience: AUD, algorithms: ['RS256'],
  })
  assert.equal(accepted.payload.exp, undefined, 'this is the behaviour requiredClaims exists to close')
})

test('15. nbf in the future is not_yet_valid', async () => {
  const now = Math.floor(Date.now() / 1000)
  await rejects(ok(await mint(keys.privateKey, userClaims(), { nbf: now + 600, exp: now + 7200 })), 'not_yet_valid')
})

test('16. a missing iat or type claim is rejected', async () => {
  await rejects(ok(await mint(keys.privateKey, userClaims(), { iat: null })), 'missing_claim')
  await rejects(ok(await mint(keys.privateKey, userClaims({ type: undefined }))), 'missing_claim')
})

// ------------------------------------------------------------- principal shape

test('17. a user token yields a user principal', async () => {
  const p = await ok(await mint(keys.privateKey, userClaims()))
  assert.equal(p.kind, 'user')
  assert.equal(p.email, 'eric@example.com')
  assert.equal(p.sub, '00000000-0000-4000-8000-000000000001')
  assert.equal(p.commonName, null)
  assert.equal(p.country, 'GB')
  assert.ok(p.expiresAt instanceof Date)
})

test('18. a service token is rejected under the default allow:user', async () => {
  await rejects(ok(await mint(keys.privateKey, serviceClaims())), 'principal_kind_not_allowed')
})

test('19. the same service token is accepted under allow:service, with email null', async () => {
  const p = await ok(await mint(keys.privateKey, serviceClaims()), { allow: 'service' })
  assert.equal(p.kind, 'service')
  assert.equal(p.email, null, 'a helper typed Promise<string> would return undefined here and report success')
  assert.equal(p.sub, null, "Cloudflare sends sub:'' for service tokens; '' is not an identity")
  assert.equal(p.commonName, 'a1-collector.access')
  assert.equal(p.country, null)
})

test('20. allow:any accepts both and kind discriminates', async () => {
  const v = verifier({ allow: 'any' })
  assert.equal((await v.verify(headerRequest(await mint(keys.privateKey, userClaims())))).kind, 'user')
  assert.equal((await v.verify(headerRequest(await mint(keys.privateKey, serviceClaims())))).kind, 'service')
})

test('21. the principal and its claims are frozen', async () => {
  const p = await ok(await mint(keys.privateKey, userClaims()))
  assert.throws(() => { p.email = 'attacker@example.com' }, TypeError)
  assert.throws(() => { p.claims.email = 'attacker@example.com' }, TypeError)
})

test('22. a large custom claim does not break parsing', async () => {
  const p = await ok(await mint(keys.privateKey, userClaims({ custom: { blob: 'x'.repeat(4096) } })))
  assert.equal(p.email, 'eric@example.com')
  assert.equal(p.claims.custom.blob.length, 4096)
})

// ----------------------------------------------------------- transport adapters

test('23. Request, Node req, plain headers and a raw token all agree', async () => {
  const token = await mint(keys.privateKey, userClaims())
  const v = verifier()
  const results = await Promise.all([
    v.verify(new Request('https://admin.aldertwig.com/', { headers: { 'Cf-Access-Jwt-Assertion': token } })),
    v.verify({ headers: { 'cf-access-jwt-assertion': token } }),
    v.verify({ 'cf-access-jwt-assertion': token }),
    v.verify(token),
  ])
  for (const p of results) assert.equal(p.email, 'eric@example.com')
})

test('24. the header name is matched case-insensitively', async () => {
  const token = await mint(keys.privateKey, userClaims())
  assert.ok(await verifier().verify({ headers: { 'CF-Access-JWT-Assertion': token } }))
})

test('25. no header at all is missing_token — never a default-allow', async () => {
  // The direct-hit case: *.netlify.app and *.fly.dev stay publicly reachable and
  // are not behind Access, so this is the ordinary shape of an attack.
  await rejects(verifier().verify({ headers: {} }), 'missing_token')
  await rejects(verifier().verify(new Request('https://admin.aldertwig.com/')), 'missing_token')
  await rejects(verifier().verify(null), 'missing_token')
})

test('26. the CF_Authorization cookie is ignored by default and honoured only on opt-in', async () => {
  // A cookie is attached by the browser to any request from any origin. Accepting
  // it lets a cross-site request aimed straight at the origin authenticate on
  // ambient authority, so the fallback is off unless a caller asks for it.
  const token = await mint(keys.privateKey, userClaims())
  const req = { headers: { cookie: `foo=bar; CF_Authorization=${token}; baz=qux` } }
  await rejects(verifier().verify(req), 'missing_token')
  assert.equal((await verifier({ acceptCookie: true }).verify(req)).email, 'eric@example.com')
})

test('26b. when both are present the header wins', async () => {
  const good = await mint(keys.privateKey, userClaims())
  const stale = await mint(keys.privateKey, userClaims({ email: 'stale@example.com' }))
  const p = await verifier({ acceptCookie: true }).verify({
    headers: { 'cf-access-jwt-assertion': good, cookie: `CF_Authorization=${stale}` },
  })
  assert.equal(p.email, 'eric@example.com')
})

test('27. empty, Bearer-prefixed and truncated tokens are refused', async () => {
  const token = await mint(keys.privateKey, userClaims())
  await rejects(verifier().verify(headerRequest('')), 'missing_token')
  await rejects(verifier().verify(headerRequest('   ')), 'missing_token')
  await rejects(verifier().verify(headerRequest(`Bearer ${token}`)), 'malformed_token')
  await rejects(verifier().verify(headerRequest(token.split('.').slice(0, 2).join('.'))), 'malformed_token')
  await rejects(verifier().verify(headerRequest('not-a-token')), 'malformed_token')
})

// ----------------------------------------------------------------------- config

test('28. a missing or empty audience throws at construction, not at first verify', async () => {
  // An unset CF_ACCESS_AUD must crash the process, never degrade into a verifier
  // that checks everything except which application minted the token.
  for (const audience of [undefined, '', '   ', [], [AUD, ''], null]) {
    assert.throws(() => createAccessVerifier({ teamDomain: TEAM, audience }), AccessConfigError)
  }
})

test('29. a teamDomain that is not a bare DNS label throws at construction', async () => {
  for (const teamDomain of [
    'aldertwig.cloudflareaccess.com', 'https://aldertwig', 'alder/twig', 'alder twig',
    'ALDERTWIG', 'x'.repeat(64), '', undefined, 42, '-leading',
  ]) {
    assert.throws(() => createAccessVerifier({ teamDomain, audience: AUD }), AccessConfigError, `${teamDomain}`)
  }
  assert.equal(createAccessVerifier({ teamDomain: 'aldertwig', audience: AUD }).issuer,
    'https://aldertwig.cloudflareaccess.com')
})

test('29b. allow, clockTolerance, acceptCookie and originSecret are validated at construction', async () => {
  assert.throws(() => createAccessVerifier({ teamDomain: TEAM, audience: AUD, allow: 'admin' }), AccessConfigError)
  assert.throws(() => createAccessVerifier({ teamDomain: TEAM, audience: AUD, clockTolerance: -1 }), AccessConfigError)
  assert.throws(() => createAccessVerifier({ teamDomain: TEAM, audience: AUD, acceptCookie: 'yes' }), AccessConfigError)
  assert.throws(() => createAccessVerifier({ teamDomain: TEAM, audience: AUD, originSecret: '' }), AccessConfigError)
})

test('30. originSecret is additive: it gates the JWT and can never stand in for it', async () => {
  const token = await mint(keys.privateKey, userClaims())
  const v = verifier({ originSecret: 's3cret-from-the-transform-rule' })

  await rejects(v.verify(headerRequest(token)), 'missing_origin_secret')
  await rejects(v.verify(headerRequest(token, { 'x-aldertwig-origin': 'wrong' })), 'missing_origin_secret')

  // The one that matters: correct secret, NO assertion header. A shared secret
  // that authenticates on its own is a static bearer key in a header.
  await rejects(v.verify({ headers: { 'x-aldertwig-origin': 's3cret-from-the-transform-rule' } }), 'missing_token')

  // And it does not weaken any JWT check.
  await rejects(
    v.verify(headerRequest(corruptSignature(token), { 'x-aldertwig-origin': 's3cret-from-the-transform-rule' })),
    'bad_signature',
  )
  const p = await v.verify(headerRequest(token, { 'x-aldertwig-origin': 's3cret-from-the-transform-rule' }))
  assert.equal(p.email, 'eric@example.com')
})

test('30b. the origin secret comparison does not short-circuit on a prefix', async () => {
  const v = verifier({ originSecret: 'abcdefghijklmnop' })
  const token = await mint(keys.privateKey, userClaims())
  for (const presented of ['a', 'abcdefghijklmno', 'abcdefghijklmnopq', '']) {
    await rejects(v.verify(headerRequest(token, { 'x-aldertwig-origin': presented })), 'missing_origin_secret')
  }
})
