// SPDX-License-Identifier: Apache-2.0
// Desired state verbs of the mock (architecture section 17): PUT and DELETE compare the object with
// the body, build the plan through the mock's own plan endpoints and apply it (or return it with
// dry_run). The comparison follows services/desired_state.py: only the fields given count.

import { createHash } from 'node:crypto'

const strip = (value) => {
  if (Array.isArray(value)) return value.map(strip)
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).filter(([k]) => k !== 'raw').map(([k, v]) => [k, strip(v)]))
  return value
}

export function covers(current, desired) {
  if (Array.isArray(desired)) return Array.isArray(current) && current.length === desired.length && desired.every((d, i) => covers(current[i], d))
  if (desired && typeof desired === 'object') return Boolean(current) && typeof current === 'object' && Object.entries(desired).every(([k, v]) => covers(current[k], v))
  if (desired === null || desired === undefined) return current === null || current === undefined || current === '' || (Array.isArray(current) && !current.length)
  return current === desired
}

const flag = (query, body, name) => {
  if (typeof body?.[name] === 'boolean') return body[name]
  return ['1', 'true', 'yes', 'on'].includes((query.get(name) || '').toLowerCase())
}

export function desiredHandlers(state, { Problem, invalid, notFound, findZone, absName, applyPlan, configHash, call, emit }) {
  const kea = (family) => (family === 'v4' ? 'kea4' : 'kea6')
  const n = (family) => (family === 'v4' ? '4' : '6')

  const ifMatch = (req, etag) => {
    const header = req?.headers?.['if-match']
    if (!header) return
    const tags = header.split(',').map((t) => t.trim().replace(/^W\//, '').replace(/"/g, ''))
    if (tags.includes('*') ? etag : tags.includes(String(etag))) return
    throw new Problem(412, 'precondition_failed', `If-Match ${header} does not match the current ETag ${etag ?? '(none)'}`)
  }

  // `build` returns the plan (a mock plan endpoint) or null when the object already is as asked.
  const converge = async ({ req, res, query, body, user }, etag, build) => {
    ifMatch(req, etag)
    if (etag) res.setHeader('ETag', `"${etag}"`)
    const plan = build()
    if (!plan) return { changed: false, etag: String(etag ?? '') || null }
    if (plan.state === 'failed') throw new Problem(422, 'engine_validation_failed', plan.error || 'the engine rejected the change')
    if (flag(query, body, 'dry_run')) return { changed: true, etag: String(etag ?? '') || null, plan }
    const confirm = flag(query, body, 'confirm')
    if (plan.requires_confirmation && !confirm) {
      const err = new Problem(428, 'confirmation_required', 'this plan needs confirm=true')
      err.extra = { plan }
      throw err
    }
    const out = applyPlan(state, user, plan.id, confirm, emit)
    if (out.code) throw new Problem(out.status, out.code, out.detail)
    return { changed: true, plan_id: plan.id, result: out.body }
  }

  const without = (body, ...keys) => Object.fromEntries(Object.entries(body || {}).filter(([k]) => !keys.includes(k)))

  // DNS
  const rrsetOf = (params, query) => {
    const zone = findZone(state, params.zone, query.get('view'))
    const owner = ['@', ''].includes(params.owner) ? zone.name : absName(params.owner.endsWith('.') ? params.owner : `${params.owner}.${zone.name}`)
    const rtype = params.type.toUpperCase()
    const records = state.records[zone.name] || []
    const found = records.find((r) => r.name === owner && r.rtype === rtype) || null
    return { zone, rtype, found, etag: state.soaSerial(records) }
  }
  const rrsetChange = (args, desired) => {
    const { params, query, body, user } = args
    const { zone, rtype, found, etag } = rrsetOf(params, query)
    if (desired && (!Array.isArray(desired.records) || !desired.records.length)) throw invalid('records', 'non-empty list of strings')
    const target = `${zone.name}/${params.owner}/${rtype}`
    return converge(args, etag, () => {
      let change
      if (!desired) {
        if (!found) return null
        change = { op: 'delete', target, before: found }
      } else {
        const same = found && (desired.ttl == null || desired.ttl === found.ttl) && [...found.rdata].sort().join('\n') === [...desired.records].sort().join('\n')
        if (same) return null
        const after = { rdata: desired.records, ttl: desired.ttl ?? found?.ttl ?? 3600 }
        change = found ? { op: 'replace', target, before: found, after } : { op: 'add', target, after }
      }
      const view = body?.view || query.get('view') || undefined
      return call('POST /dns/zones/{zone}/records/plan', { ...args, params: { zone: zone.name }, user, body: { view, changes: [change], ...(desired?.ptr ? { ptr: desired.ptr } : {}) } })
    })
  }

  const zoneChange = (args, desired) => {
    const { params, query, body } = args
    let zone = null
    try {
      zone = findZone(state, params.zone, body?.view || query.get('view'))
    } catch {
      zone = null
    }
    const etag = zone ? createHash('sha256').update(JSON.stringify(zone)).digest('hex').slice(0, 20) : null
    const view = zone?.view || body?.view || query.get('view') || '_default'
    const name = absName(params.zone)
    return converge(args, etag, () => {
      let change
      if (!desired) {
        if (!zone) return null
        change = { op: 'delete', target: `${view}/${name}`, before: zone }
      } else if (!zone) {
        if (!desired.kind) throw invalid('body.kind', 'required')
        change = { op: 'add', target: `${view}/${name}`, after: { ...desired, name } }
      } else {
        if (covers(strip(zone), desired)) return null
        change = { op: 'replace', target: `${view}/${name}`, before: zone, after: { ...zone, ...desired } }
      }
      return call('POST /dns/zones/plan', { ...args, body: { change } })
    })
  }

  // DHCP
  const keaChange = (args, { current, desired, spec, target, addAfter, many = false }) =>
    converge(args, configHash(state, kea(args.params.family)), () => {
      let change
      if (!desired) {
        if (!current) return null
        change = { op: 'delete', target, before: current }
      } else if (!current) {
        change = { op: 'add', target, after: addAfter() }
      } else {
        if (covers(strip(current), desired)) return null
        change = { op: 'replace', target, before: current, after: { ...strip(current), ...desired } }
      }
      return call(spec, { ...args, body: many ? { changes: [change] } : { change } })
    })

  const reservationOf = (family, key, subnetId) => {
    const [idType, identifier] = key.split('=')
    if (!identifier) throw invalid('key', 'bad format')
    const found = state.reservations[family].find((r) => (r.id_type || 'hw-address') === idType && r.identifier.toLowerCase() === identifier.toLowerCase().replace(/-/g, ':') && (r.subnet_id ?? null) === subnetId) || null
    return { idType, identifier: identifier.toLowerCase().replace(/-/g, ':'), found }
  }
  const reservationChange = (args, desired, subnetId) => {
    const { family, key } = args.params
    const { idType, identifier, found } = reservationOf(family, key, subnetId)
    const scope = subnetId == null ? 'global' : `subnet${n(family)}/${subnetId}`
    return keaChange(args, {
      current: found,
      desired: desired && { ...desired, subnet_id: subnetId },
      spec: 'POST /dhcp/{family}/reservations/plan',
      target: `${scope}/reservations/${idType}=${identifier}`,
      addAfter: () => ({ ...desired, subnet_id: subnetId, id_type: idType, identifier }),
    })
  }
  const subnetId = (query) => (query.get('subnet_id') ? Number(query.get('subnet_id')) : null)

  const optionOf = (family, space, code) => state.globalOptions[family].find((o) => (o.space || (family === 'v4' ? 'dhcp4' : 'dhcp6')) === space && (/^\d+$/.test(code) ? String(o.code) === code : o.name === code)) || null

  const read = (res, current, etag, what) => {
    if (!current) throw notFound(what)
    if (etag) res.setHeader('ETag', `"${etag}"`)
    return current
  }

  return {
    'GET /dns/zones/{zone}/rrsets/{owner}/{type}': ({ params, query, res }) => {
      const { found, etag } = rrsetOf(params, query)
      return read(res, found, etag, `${params.owner} ${params.type}`)
    },
    'PUT /dns/zones/{zone}/rrsets/{owner}/{type}': (args) => rrsetChange(args, args.body || {}),
    'DELETE /dns/zones/{zone}/rrsets/{owner}/{type}': (args) => rrsetChange(args, null),
    'PUT /dns/zones/{zone}': (args) => zoneChange(args, without(args.body, 'view', 'confirm')),
    'DELETE /dns/zones/{zone}': (args) => zoneChange(args, null),

    'GET /dhcp/{family}/reservations/{key}': ({ params, query, res }) =>
      read(res, reservationOf(params.family, params.key, subnetId(query)).found, configHash(state, kea(params.family)), `reservation ${params.key}`),
    'PUT /dhcp/{family}/reservations/{key}': (args) => reservationChange(args, without(args.body, 'confirm', 'subnet_id'), args.body?.subnet_id ?? null),
    'DELETE /dhcp/{family}/reservations/{key}': (args) => reservationChange(args, null, subnetId(args.query)),

    'PUT /dhcp/{family}/subnets/{id}': (args) => {
      const { family, id } = args.params
      const current = state.subnets[family].find((s) => String(s.id) === id) || null
      const desired = without(args.body, 'confirm')
      if (desired.id !== undefined && String(desired.id) !== id) throw invalid('body.id', 'must match the path')
      return keaChange(args, { current, desired: { ...desired, id: Number(id) }, spec: 'POST /dhcp/{family}/subnets/plan', target: `subnet${n(family)}/${id}`, addAfter: () => ({ ...desired, id: Number(id) }) })
    },
    'DELETE /dhcp/{family}/subnets/{id}': (args) => {
      const { family, id } = args.params
      const current = state.subnets[family].find((s) => String(s.id) === id) || null
      return keaChange(args, { current, desired: null, spec: 'POST /dhcp/{family}/subnets/plan', target: `subnet${n(family)}/${id}` })
    },

    'GET /dhcp/{family}/client-classes/{name}': ({ params, res }) =>
      read(res, state.classes[params.family].find((c) => c.name === params.name), configHash(state, kea(params.family)), `client class ${params.name}`),
    'PUT /dhcp/{family}/client-classes/{name}': (args) => {
      const { family, name } = args.params
      const desired = without(args.body, 'confirm')
      return keaChange(args, { current: state.classes[family].find((c) => c.name === name) || null, desired, spec: 'POST /dhcp/{family}/client-classes/plan', target: `client-classes/${name}`, addAfter: () => ({ ...desired, name }) })
    },
    'DELETE /dhcp/{family}/client-classes/{name}': (args) => {
      const { family, name } = args.params
      return keaChange(args, { current: state.classes[family].find((c) => c.name === name) || null, desired: null, spec: 'POST /dhcp/{family}/client-classes/plan', target: `client-classes/${name}` })
    },

    'GET /dhcp/{family}/options/{space}/{code}': ({ params, res }) =>
      read(res, optionOf(params.family, params.space, params.code), configHash(state, kea(params.family)), `option ${params.space}/${params.code}`),
    'PUT /dhcp/{family}/options/{space}/{code}': (args) => {
      const { family, space, code } = args.params
      const desired = without(args.body, 'confirm')
      const named = /^\d+$/.test(code) ? { code: Number(code) } : { name: code }
      const current = optionOf(family, space, code)
      return keaChange(args, { current, desired, many: true, spec: 'POST /dhcp/{family}/options/plan', target: `option-data/${space}/${code}`, addAfter: () => ({ ...desired, ...named, space }) })
    },
    'DELETE /dhcp/{family}/options/{space}/{code}': (args) => {
      const { family, space, code } = args.params
      return keaChange(args, { current: optionOf(family, space, code), desired: null, many: true, spec: 'POST /dhcp/{family}/options/plan', target: `option-data/${space}/${code}` })
    },
  }
}
