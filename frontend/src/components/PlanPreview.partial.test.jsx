// SPDX-License-Identifier: Apache-2.0
// Partial apply in PlanPreview (section 6, B1-KEAOFFLINE). Contract skeleton: each todo becomes a
// test as the lot implements it.
import { describe, it } from 'vitest'

describe('PlanPreview partial apply', () => {
  it.todo('a 409 node_unreachable with partial_allowed shows the "reachable nodes" box naming the nodes')
  it.todo('a 409 node_unreachable with ha_partner_in_touch shows the explanation and no box')
  it.todo('checking the box asks for confirmation with the partial_apply reason')
  it.todo('apply then calls applyFn(id, true, { partial: true })')
  it.todo('a controlled partialOption from the caller wins over the internal box')
  it.todo('the applied result lists the skipped nodes with their reason')
  it.todo('a 409 reconcile_required names the nodes and the source to reconcile from')
})

describe('Alerts reconcile action', () => {
  it.todo('a config_divergence alert with details.reconcile offers "Reconcile from <node>"')
  it.todo('both directions are offered when both sides changed')
  it.todo('the action builds POST /dhcp/{family}/config/reconcile/plan and opens the plan preview')
  it.todo('without write:dhcp.config the action is replaced by a read-only note')
})
