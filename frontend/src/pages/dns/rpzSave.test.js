// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi } from 'vitest'
import { saveCategoryDrafts } from './rpzSave'

const makeApi = (failOn) => {
  let n = 0
  return {
    dns: {
      rpzSetCategory: vi.fn(async (id) => {
        if (id === failOn) throw new Error('refused')
        n += 1
        return { plan: { id: `p${n}` } }
      }),
      rpzClearCategory: vi.fn(async () => {
        n += 1
        return { plan: { id: `p${n}` } }
      }),
    },
    plans: { remove: vi.fn(async () => null) },
  }
}

describe('saveCategoryDrafts', () => {
  it('returns the last plan and deletes the superseded previews', async () => {
    const api = makeApi()
    const out = await saveCategoryDrafts({ ads: { body: { a: 1 } }, spam: { clear: true }, adult: { body: {} } }, api)
    expect(out.plan.id).toBe('p3')
    expect(out.saved).toEqual(['ads', 'spam', 'adult'])
    expect(out.failure).toBeNull()
    expect(api.plans.remove.mock.calls).toEqual([['p1'], ['p2']])
  })

  it('keeps the plan of the saved ones and names what was not saved', async () => {
    const api = makeApi('spam')
    const out = await saveCategoryDrafts({ ads: { body: {} }, spam: { body: {} }, adult: { body: {} } }, api)
    expect(out.saved).toEqual(['ads'])
    expect(out.plan.id).toBe('p1')
    expect(out.failure).toMatchObject({ failed: 'spam', skipped: ['adult'] })
    expect(api.plans.remove).not.toHaveBeenCalled()
  })

  it('does not fail when a preview cannot be deleted', async () => {
    const api = makeApi()
    api.plans.remove = vi.fn(async () => {
      throw new Error('gone')
    })
    const out = await saveCategoryDrafts({ ads: { body: {} }, adult: { body: {} } }, api)
    expect(out.plan.id).toBe('p2')
  })
})
