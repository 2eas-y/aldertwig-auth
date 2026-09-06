/**
 * One error type for every authentication failure.
 *
 * `code` is for our logs. The client gets 401 and a fixed body — telling an
 * unauthenticated caller *which* check failed tells them whether they hold a
 * real token for the wrong application, which is the one thing they would want
 * to know.
 */
export class AccessAuthError extends Error {
  /**
   * @param {string} code   stable, machine-readable, safe to log
   * @param {string} detail human-readable; NEVER put this on the wire
   * @param {{ cause?: unknown }} [options]
   */
  constructor(code, detail, options = {}) {
    super(detail, options)
    this.name = 'AccessAuthError'
    this.code = code
    // Every failure is 401. There is no 403 here: this module decides whether a
    // token is real, never whether the principal is allowed to do the thing.
    this.status = 401
  }

  /** The only representation that may be sent to a client. */
  toResponseBody() {
    return { error: 'unauthorized' }
  }
}

/**
 * Thrown from `createAccessVerifier()`, at boot, never from `verify()`.
 * Misconfiguration must crash the process, not degrade into a weaker check.
 */
export class AccessConfigError extends Error {
  constructor(detail) {
    super(detail)
    this.name = 'AccessConfigError'
  }
}
