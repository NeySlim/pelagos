// SPDX-License-Identifier: Apache-2.0
// B1-KEAOFFLINE in the mock (architecture sections 6 and 9): `state.offlineNodes` lists the peers
// that do not answer; a Kea configuration plan targeting one answers 409 node_unreachable unless the
// apply asks `partial`, which narrows it and records the couple in `state.keaPartials`.

const NARROWABLE = new Set(['dhcp.subnet', 'dhcp.shared_network', 'dhcp.reservation', 'dhcp.class', 'dhcp.options'])
const KEA = new Set(['kea4', 'kea6'])

const name = (state, id) => state.nodes.find((n) => n.peer.id === id)?.peer.name || id

// Called by POST /plans/{id}/apply before the plan is applied; narrows the plan in place.
export function partialApply(state, plan, body, Problem) {
  if (!plan || !KEA.has(plan.engine) || !NARROWABLE.has(plan.scope)) return
  const offline = (plan.target_node_ids || []).filter((id) => (state.offlineNodes || []).includes(id))
  if (!offline.length) return
  if (!body.partial) {
    const p = new Problem(409, 'node_unreachable', `${offline.map((id) => name(state, id)).join(', ')} is offline: apply on the reachable nodes only (partial) or wait for it`)
    p.extra = {
      node_ids: offline,
      node_names: offline.map((id) => name(state, id)),
      nodes: offline.map((node_id) => ({ node_id, reason: 'unreachable' })),
      partial_allowed: true,
    }
    throw p
  }
  if (!body.confirm) throw new Problem(428, 'confirmation_required', 'a partial apply needs confirm=true')
  plan.target_node_ids = plan.target_node_ids.filter((id) => !offline.includes(id))
  plan.partial = true
  plan.skipped_node_ids = offline
  plan.skipped = offline.map((node_id) => ({ node_id, reason: 'unreachable' }))
  plan.requires_confirmation = true
  plan.requires_confirmation_reasons = [...new Set([...(plan.requires_confirmation_reasons || []), 'partial_apply'])]
  state.keaPartials = state.keaPartials || []
  for (const target of offline) {
    const id = `${plan.engine}:${state.selfId}:${target}`
    let rec = state.keaPartials.find((r) => r.id === id)
    if (!rec) {
      rec = { id, engine: plan.engine, source_node_id: state.selfId, target_node_id: target, since: new Date().toISOString(), plans: [], plan_count: 0 }
      state.keaPartials.push(rec)
    }
    rec.plans.push({ plan_id: plan.id, created_by: plan.created_by, summary: plan.summary })
    rec.plan_count += 1
    rec.last_applied_at = new Date().toISOString()
  }
}

export function keaOfflineHandlers(state, { invalid, createPlan, Problem }) {
  return {
    'POST /dhcp/{family}/config/reconcile/plan': ({ params, body, user }) => {
      const { source_node_id: source, target_node_id: target } = body || {}
      if (!source || !target || source === target) throw invalid('target_node_id', 'same node')
      if ((state.offlineNodes || []).includes(source) || (state.offlineNodes || []).includes(target)) {
        throw new Problem(503, 'engine_unavailable', `node ${name(state, target)}: unreachable`)
      }
      const engine = params.family === 'v6' ? 'kea6' : 'kea4'
      const plan = createPlan(state, user, {
        scope: 'dhcp.config',
        engine,
        summary: `${engine}: reconcile ${name(state, target)} from ${name(state, source)}`,
        summary_message: { key: 'plan.kea.reconcile', params: { engine, source: name(state, source), target: name(state, target) } },
        changes: [{ op: 'replace', target: 'config', before: null, after: {}, node_ids: [] }],
        diff: `# ${name(state, target)}\n+shared view of ${name(state, source)}\n`,
        targets: [target],
        tool: 'config-test',
        requires_confirmation: true,
      })
      plan.requires_confirmation_reasons = ['reconcile']
      plan.preconditions = [{ kind: 'config_hash', subject: `reconcile:${engine}`, value: 'mock', node_id: source }]
      return plan
    },
  }
}
