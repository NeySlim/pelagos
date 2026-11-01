// SPDX-License-Identifier: Apache-2.0
// Saves the changed RPZ category cards one after the other. Each save returns a plan computed from
// every saved selection, so the last plan carries all changes; earlier previews are deleted as the
// next one arrives. A failure stops the run: `saved` are already persisted, `failed` is the category
// that was refused and `skipped` were not tried.

export async function saveCategoryDrafts(drafts, api) {
  const entries = Object.entries(drafts)
  const saved = []
  let plan = null
  let failure = null
  for (const [index, [id, draft]] of entries.entries()) {
    try {
      const res = await (draft.clear ? api.dns.rpzClearCategory(id) : api.dns.rpzSetCategory(id, draft.body))
      if (plan?.id && plan.id !== res?.plan?.id) await api.plans.remove(plan.id).catch(() => {})
      plan = res?.plan || null
      saved.push(id)
    } catch (error) {
      failure = { failed: id, skipped: entries.slice(index + 1).map(([k]) => k), error }
      break
    }
  }
  return { plan, saved, failure }
}
