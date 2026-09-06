# @aldertwig/access-auth

Verified Cloudflare Access identity. One helper, three runtimes.

Every Aldertwig service that sits behind Cloudflare Access needs the same
five lines and gets them wrong in the same five ways. This is those lines,
once, with the failure modes written down.

```js
// module scope — ONCE per process. The verifier owns the JWKS cache.
import { createAccessVerifier } from '@aldertwig/access-auth'

const access = createAccessVerifier({
  teamDomain: 'aldertwig',            // bare label, not a URL
  audience: process.env.CF_ACCESS_AUD, // this app's AUD tag, not the team's
})

// per request
try {
  const principal = await access.verify(request)
  // principal.kind: 'user' | 'service'
  // principal.email, .sub, .commonName, .country, .audience, .expiresAt, .claims
} catch (error) {
  return json(error.toResponseBody(), { status: error.status }) // always 401
}
```

`verify()` accepts a Fetch `Request`, a Node `IncomingMessage`, a plain headers
object, or a raw token string. That is the whole API.

## What it refuses

Each of these is a test in `test/verify.test.js`, and each negative case is a
real signature over real claims — not a valid token with characters edited out.

| Attack | Code |
|---|---|
| `alg: none`, empty signature | `malformed_token` (refused before a key is resolved) |
| `alg: none` with junk in the signature slot | `bad_signature` (the algorithm pin) |
| HS256 signed with the RSA public key as the HMAC secret | `bad_signature` |
| Signature bytes flipped | `bad_signature` |
| Unknown `kid`, or a `kid` flood | `unknown_key`, one upstream fetch per cooldown |
| A real token for **another one of our apps** | `wrong_audience` |
| A real token from another team | `wrong_issuer` |
| Expired, or `nbf` in the future | `expired`, `not_yet_valid` |
| **No `exp` claim at all** | `missing_claim` |
| No header at all | `missing_token` |
| Unreachable or slow JWKS | `jwks_unavailable` — a lockout, never an accept |

Two of those deserve the extra sentence.

**A token with no `exp` verifies forever.** No JWT library requires the claim
unless you ask. Cloudflare always sets one — and a third party's habit is not a
security control. `exp`, `iat`, `iss`, `aud` and `type` are all required here.

**`audience` is not optional and there is no "any audience" mode.** An unset
`CF_ACCESS_AUD` arrives as `undefined` and crashes at construction. It has to:
the AUD tag is the only claim that separates a token minted for the receptionist
from one minted for the monitor, and both are signed by the same team key. A
verifier that skips it accepts every colleague's token for every app.

## Failing closed, on purpose

An unreachable JWKS is a total lockout of every service using this module. That
is the correct trade for internal tooling and it is the reason this module must
never sit in front of a paying customer's login.

Misconfiguration throws `AccessConfigError` at construction, never at first
request — a typo should crash the process at boot, not degrade into a weaker
check that nobody notices until it is audited.

`AccessAuthError` carries a `code` for our logs. The client gets 401 and
`{ error: 'unauthorized' }` and nothing else, because telling an unauthenticated
caller *which* check failed tells them whether they hold a real token for the
wrong application.

## Non-goals

**This is not CSRF protection.** Cloudflare Access proves *who* is calling. It
says nothing about *intent*. A cross-site request from a page the victim is
visiting still travels through the edge, and the edge still injects a genuine
`Cf-Access-Jwt-Assertion` header on it. Verified identity is not verified intent.
Anything that mutates state needs its own token.

**It is header-only by default.** The `CF_Authorization` cookie is off unless you
pass `acceptCookie: true`. Cloudflare's own guidance is to prefer the header
because the cookie "is not guaranteed to be passed", but the reason it matters
here is different: a browser attaches a cookie by itself, to any request, from
any origin. A cross-site request aimed *straight at the origin hostname* —
bypassing the edge entirely — would authenticate on ambient authority. Refusing
the cookie removes the one variant this module can remove for free. It does not
remove the one above.

**It never decides authorization.** There is no 403 in this module. It answers
"is this token real", and hands you a principal to make the other decision with.

## `originSecret`, and what it is not

`*.netlify.app` and `*.fly.dev` origins stay publicly reachable. Access protects
the hostname, not the origin behind it, so a request that never touches
Cloudflare arrives with no header and fails `missing_token` — which is why the
default is a hard failure and never a default-allow.

`originSecret` is the shared half of a Cloudflare Transform Rule: set it, and a
request must also carry that exact value in `x-aldertwig-origin`, compared
against a SHA-256 digest of both sides so the comparison is over two fixed-length
buffers. It is strictly an **AND** with the JWT and can never stand in for it —
a shared secret that authenticates on its own is a static bearer key in a header,
which is the thing this module exists to replace.

## Configuration

| Option | Default | |
|---|---|---|
| `teamDomain` | — | bare DNS label; a typo crashes at boot rather than silently trusting another host |
| `audience` | — | required. An **array widens** the boundary: any one listed AUD is accepted |
| `allow` | `'user'` | `'user'`, `'service'`, or `'any'` |
| `clockTolerance` | `30` | seconds |
| `acceptCookie` | `false` | see Non-goals |
| `originSecret` | unset | see above |
| `jwks` | `{}` | passed through to jose's remote JWKS resolver |

## Tests

```
npm ci && npm test
```

34 tests, no network: the suite mints against a real RSA keypair and resolves
against a local JWKS, including a rotation case and a cooldown case that counts
upstream fetches.
