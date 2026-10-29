// SPDX-License-Identifier: Apache-2.0
// API tokens of the mock (architecture section 16), shaped like services/token_service.py:
// a fresh second factor (key assertion or TOTP code) to create, secret returned once,
// owner or admin revocation. Bearer calls themselves are tested against the real backend.
import { randomBytes } from 'node:crypto'
import { iso } from './data.mjs'
import { checkAssertion, open, requestOptions, take, userKeys, webauthnState } from './webauthn.mjs'

const DAY = 86400000

export function tokenHandlers(state, { Problem, invalid, permissionsOf }) {
  state.apiTokens ||= []
  const problem = (status, code, detail, extra) => Object.assign(new Problem(status, code, detail), { extra })
  const view = (t) => {
    const { secret: _secret, ...rest } = t
    const owner = state.users.find((u) => u.id === t.user_id)
    return { ...rest, username: owner?.username || null, expired: Date.parse(t.expires_at) <= Date.now() }
  }
  const methods = (user) => [...(userKeys(state, user.id).length ? ['webauthn'] : []), ...(user.has_totp ? ['totp'] : [])]
  return {
    'GET /auth/tokens': ({ user }) => ({ items: state.apiTokens.filter((t) => t.user_id === user.id).map(view), meta: { unavailable: [] } }),
    'POST /auth/tokens/challenge': ({ req, user }) => {
      const m = methods(user)
      if (!m.length) throw problem(409, 'conflict', 'creating an API token needs a second factor', { reason: 'no_second_factor' })
      const out = { methods: m }
      if (m.includes('webauthn')) {
        const cer = open(state, 'reauth', req, user.id)
        out.ceremony = cer.id
        out.options = requestOptions(cer, userKeys(state, user.id))
      }
      return out
    },
    'POST /auth/tokens': ({ body, user, res }) => {
      const name = String(body.name || '').trim()
      if (!name || name.length > 64) throw invalid('name', '1 to 64 characters')
      const days = body.expires_days ?? 90
      if (!Number.isInteger(days) || days < 1 || days > 365) throw invalid('expires_days', '1 to 365')
      const role = body.role || 'viewer'
      const found = [...state.builtinRoles, ...state.customRoles].find((r) => r.name === role)
      if (!found) throw invalid('role', 'unknown')
      const held = permissionsOf(state, user)
      const wider = found.permissions.filter((p) => !held.includes('*') && !held.includes(p))
      if (wider.length) throw problem(403, 'forbidden', `a token cannot hold more than its creator: ${wider.join(', ')}`, { permissions: wider })
      if (body.ceremony) {
        const cer = take(state, body.ceremony, ['reauth'])
        const key = cer && webauthnState(state).keys.get(body.credential?.id)
        if (!cer || !key || key.userId !== user.id) throw new Problem(401, 'invalid_credentials', 'second factor not accepted')
        try {
          checkAssertion(cer, body.credential, key)
        } catch {
          throw new Problem(401, 'invalid_credentials', 'second factor not accepted')
        }
      } else if (body.totp_code) {
        if (!user.has_totp || body.totp_code !== (user.totp || '123456')) throw new Problem(401, 'invalid_credentials', 'second factor not accepted')
      } else {
        throw invalid('ceremony', 'required')
      }
      const id = randomBytes(8).toString('hex')
      const token = { id, name, user_id: user.id, role, permissions: found.permissions, cidrs: (body.cidrs || []).map(String), expires_at: iso(new Date(Date.now() + days * DAY)), created_at: iso(new Date()), created_by: user.username, created_on: state.nodes[0]?.peer?.id || null, last_used_at: null, last_used_node: null, last_used_ip: null }
      state.apiTokens.push(token)
      res.statusCode = 201
      return { token: `pel_${id}_${randomBytes(32).toString('base64url')}`, item: view(token) }
    },
    'DELETE /auth/tokens/{id}': ({ params, user }) => {
      const t = state.apiTokens.find((x) => x.id === params.id && x.user_id === user.id)
      if (!t) throw new Problem(404, 'not_found', 'no such API token')
      state.apiTokens = state.apiTokens.filter((x) => x !== t)
      return null
    },
    'GET /admin/tokens': () => ({ items: state.apiTokens.map(view), meta: { unavailable: [] } }),
    'DELETE /admin/tokens/{id}': ({ params }) => {
      const t = state.apiTokens.find((x) => x.id === params.id)
      if (!t) throw new Problem(404, 'not_found', 'no such API token')
      state.apiTokens = state.apiTokens.filter((x) => x !== t)
      return null
    },
  }
}
