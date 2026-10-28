// SPDX-License-Identifier: Apache-2.0
// Security keys and passkeys of the mock (architecture section 16), shaped like
// services/webauthn_service.py. Registration keeps the SPKI public key the browser
// reports (getPublicKey()); assertions are checked for real: challenge, type,
// origin, rpId hash, flags and the ECDSA or Ed25519 signature.
import { createHash, randomBytes, verify } from 'node:crypto'
import { iso } from './data.mjs'

const b64url = (buf) => Buffer.from(buf).toString('base64url')
const unb64url = (text) => Buffer.from(String(text || ''), 'base64url')
const CEREMONY_MS = 300000
const UP = 0x01
const UV = 0x04

export function webauthnState(state) {
  state.webauthn ||= { keys: new Map(), ceremonies: new Map() }
  return state.webauthn
}

export function keyCount(state, userId) {
  let n = 0
  for (const k of webauthnState(state).keys.values()) if (k.userId === userId) n += 1
  return n
}

// The page origin: the browser sends it on every POST; the Vite proxy rewrites Host, not Origin.
function siteOf(req) {
  const origin = req.headers.origin || `http://${req.headers['x-forwarded-host'] || req.headers.host || 'localhost'}`
  let host = 'localhost'
  try {
    host = new URL(origin).hostname
  } catch {
    // keep localhost
  }
  return { origin, rpId: host }
}

function open(state, kind, req, userId, extra = {}) {
  const { ceremonies } = webauthnState(state)
  const now = Date.now()
  for (const [id, c] of ceremonies) if (now - c.created > CEREMONY_MS) ceremonies.delete(id)
  const cer = { id: randomBytes(18).toString('base64url'), kind, challenge: b64url(randomBytes(32)), userId, created: now, ...siteOf(req), ...extra }
  ceremonies.set(cer.id, cer)
  return cer
}

function take(state, id, kinds) {
  const { ceremonies } = webauthnState(state)
  const cer = ceremonies.get(id)
  ceremonies.delete(id)
  return cer && kinds.includes(cer.kind) && Date.now() - cer.created <= CEREMONY_MS ? cer : null
}

const descriptor = (id, k) => ({ type: 'public-key', id, ...(k.transports?.length ? { transports: k.transports } : {}) })

function userKeys(state, userId) {
  return [...webauthnState(state).keys].filter(([, k]) => k.userId === userId)
}

function requestOptions(cer, allowed) {
  return {
    challenge: cer.challenge,
    timeout: CEREMONY_MS,
    rpId: cer.rpId,
    allowCredentials: allowed.map(([id, k]) => descriptor(id, k)),
    userVerification: cer.kind === 'passkey' ? 'required' : 'preferred',
  }
}

function clientData(response, type, cer) {
  const data = JSON.parse(unb64url(response.clientDataJSON).toString('utf8'))
  if (data.type !== type || data.challenge !== cer.challenge || data.origin !== cer.origin) throw new Error('client data does not match')
  return data
}

function publicKey(spki) {
  return { key: unb64url(spki), format: 'der', type: 'spki' }
}

function checkAssertion(cer, credential, key) {
  const r = credential.response || {}
  clientData(r, 'webauthn.get', cer)
  const auth = unb64url(r.authenticatorData)
  if (!auth.subarray(0, 32).equals(createHash('sha256').update(cer.rpId).digest())) throw new Error('rpId hash differs')
  const flags = auth[32]
  if (!(flags & UP) || (cer.kind === 'passkey' && !(flags & UV))) throw new Error('user not present or not verified')
  const signed = Buffer.concat([auth, createHash('sha256').update(unb64url(r.clientDataJSON)).digest()])
  const algorithm = key.alg === -8 ? null : 'sha256'
  if (!verify(algorithm, signed, publicKey(key.spki), unb64url(r.signature))) throw new Error('bad signature')
  const counter = auth.readUInt32BE(33)
  if (counter > 0 && counter <= key.counter) throw new Error('counter did not move')
  key.counter = counter
  key.last_used_at = iso(Date.now())
}

function credentialView(id, k) {
  const { userId: _u, spki: _s, counter: _c, alg: _a, ...rest } = k
  return { id, ...rest }
}

// Answer of POST /auth/login once the password matched: a Problem to throw, or null.
export function secondFactor(state, user, req, body, Problem) {
  const keys = userKeys(state, user.id)
  if (!keys.length) return null
  if (user.has_totp && body.totp_code) return null
  const cer = open(state, 'second_factor', req, user.id)
  const problem = new Problem(401, 'second_factor_required', 'a security key is required')
  problem.extra = { methods: user.has_totp ? ['webauthn', 'totp'] : ['webauthn'], rp_ids: [], ceremony: cer.id, options: requestOptions(cer, keys) }
  return problem
}

export function webauthnHandlers(state, { Problem, invalid, openSession }) {
  const site = (req) => ({ available: true, rp_id: siteOf(req).rpId, reason: null })
  const refused = () => new Problem(401, 'invalid_credentials', 'security key not accepted')
  const own = (user, id) => {
    const k = webauthnState(state).keys.get(id)
    if (!k || k.userId !== user.id) throw new Problem(404, 'not_found', 'no such security key')
    return k
  }
  return {
    'GET /auth/webauthn': ({ req }) => site(req),
    'POST /auth/webauthn/login/options': ({ req }) => {
      const cer = open(state, 'passkey', req, null)
      return { ceremony: cer.id, options: requestOptions(cer, []) }
    },
    'POST /auth/webauthn/login/verify': ({ body, res }) => {
      const cer = take(state, body.ceremony, ['second_factor', 'passkey'])
      if (!cer) throw new Problem(401, 'invalid_credentials', 'sign-in expired; start again')
      const credential = body.credential || {}
      const key = webauthnState(state).keys.get(credential.id)
      const userId = cer.kind === 'passkey' ? unb64url(credential.response?.userHandle).toString('utf8') : cer.userId
      const user = state.users.find((u) => u.id === userId)
      if (!key || !user || !user.enabled || key.userId !== user.id || key.rp_id !== cer.rpId) throw refused()
      try {
        checkAssertion(cer, credential, key)
      } catch {
        throw refused()
      }
      return openSession(user, res)
    },
    'GET /auth/webauthn/credentials': ({ req, user }) => ({
      items: userKeys(state, user.id).map(([id, k]) => credentialView(id, k)),
      ...site(req),
    }),
    'POST /auth/webauthn/register/options': ({ req, user }) => {
      const cer = open(state, 'register', req, user.id)
      return {
        ceremony: cer.id,
        options: {
          rp: { id: cer.rpId, name: 'Pelagos' },
          user: { id: b64url(Buffer.from(user.id)), name: user.username, displayName: user.username },
          challenge: cer.challenge,
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -8 }, { type: 'public-key', alg: -257 }],
          timeout: CEREMONY_MS,
          excludeCredentials: userKeys(state, user.id).map(([id, k]) => descriptor(id, k)),
          authenticatorSelection: { residentKey: 'preferred', requireResidentKey: false, userVerification: 'preferred' },
          attestation: 'none',
        },
      }
    },
    'POST /auth/webauthn/register/verify': ({ body, user, session, res }) => {
      const name = String(body.name || '').trim()
      if (!name || name.length > 64) throw invalid('name', '1 to 64 characters')
      const cer = take(state, body.ceremony, ['register'])
      if (!cer || cer.userId !== user.id) throw invalid('ceremony', 'expired')
      const r = body.credential?.response || {}
      try {
        clientData(r, 'webauthn.create', cer)
      } catch {
        throw invalid('credential', 'refused')
      }
      if (!r.publicKey) throw invalid('credential', 'the browser did not report the public key')
      const { keys } = webauthnState(state)
      if (keys.has(body.credential.id)) throw new Problem(409, 'conflict', 'this security key is already registered')
      keys.set(body.credential.id, {
        userId: user.id,
        name,
        spki: r.publicKey,
        alg: r.publicKeyAlgorithm ?? -7,
        counter: 0,
        rp_id: cer.rpId,
        transports: r.transports || [],
        aaguid: null,
        backup_eligible: false,
        created_at: iso(Date.now()),
        created_on: state.selfId,
        last_used_at: null,
      })
      if (['webauthn_enrollment', 'totp_enrollment'].includes(session.restriction)) session.restriction = null
      res.statusCode = 201
      return credentialView(body.credential.id, keys.get(body.credential.id))
    },
    'PATCH /auth/webauthn/credentials/{id}': ({ params, body, user }) => {
      const k = own(user, params.id)
      const name = String(body.name || '').trim()
      if (!name || name.length > 64) throw invalid('name', '1 to 64 characters')
      k.name = name
      return credentialView(params.id, k)
    },
    'DELETE /auth/webauthn/credentials/{id}': ({ params, body, user }) => {
      const record = state.users.find((u) => u.id === user.id)
      if (record.password !== body.password) throw new Problem(401, 'invalid_credentials', 'Password is wrong')
      own(user, params.id)
      webauthnState(state).keys.delete(params.id)
      return null
    },
    'GET /admin/users/{id}/webauthn': ({ params }) => ({ items: userKeys(state, params.id).map(([id, k]) => credentialView(id, k)) }),
    'DELETE /admin/users/{id}/webauthn': ({ params }) => {
      for (const [id] of userKeys(state, params.id)) webauthnState(state).keys.delete(id)
      return null
    },
    'DELETE /admin/users/{id}/webauthn/{credential_id}': ({ params }) => {
      const k = webauthnState(state).keys.get(params.credential_id)
      if (!k || k.userId !== params.id) throw new Problem(404, 'not_found', 'no such security key')
      webauthnState(state).keys.delete(params.credential_id)
      return null
    },
    'GET /admin/webauthn': () => {
      const nodes = state.nodes.map((n) => ({ id: n.peer.id, name: n.peer.name, host: `${n.peer.name}.example.lan`, covered: true }))
      return { rp_id: 'example.lan', source: 'common_domain', common_domain: 'example.lan', nodes, warning: null }
    },
  }
}
