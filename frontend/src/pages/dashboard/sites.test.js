// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest'
import { spansSites } from './sites'

const node = (site) => ({ peer: { site } })

describe('spansSites', () => {
  it('needs two different sites', () => {
    expect(spansSites([node('dc1'), node('dc1'), node(null)])).toBe(false)
    expect(spansSites([node('dc1'), node('dc2')])).toBe(true)
    expect(spansSites([node(null), node(undefined)])).toBe(false)
    expect(spansSites(undefined)).toBe(false)
  })
})
