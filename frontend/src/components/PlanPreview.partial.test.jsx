// SPDX-License-Identifier: Apache-2.0
// Partial apply in PlanPreview (section 6, B1-KEAOFFLINE). Contract skeleton: each todo becomes a
// test as the lot implements it.
import { describe, it } from 'vitest'

describe('PlanPreview partial apply', () => {
  it.todo('a 409 node_unreachable with partial_allowed shows the "reachable nodes" box naming the nodes')
  it.todo('a 409 node_unreachable without partial_allowed shows the error only')
  it.todo('checking the box asks for confirmation with the partial_apply reason')
  it.todo('apply then calls applyFn(id, true, { partial: true })')
  it.todo('a controlled partialOption from the caller wins over the internal box')
  it.todo('the applied result lists the skipped nodes')
})

describe('Alerts reconcile action', () => {
  it.todo('a config_divergence alert with details.reconcile offers "Reconcile from <node>"')
  it.todo('the action builds POST /dhcp/{family}/config/reconcile/plan and opens the plan preview')
})
