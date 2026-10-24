// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest'
import { permitted } from './access'
import advanced from '../pages/advanced/routes'

const holder = (...perms) => (p) => perms.includes(p)

describe('permitted', () => {
  it('checks a single permission', () => {
    expect(permitted({ permission: 'read:dns' }, holder('read:dns'))).toBe(true)
    expect(permitted({ permission: 'read:dns' }, holder())).toBe(false)
    expect(permitted({}, holder())).toBe(true)
  })

  it('needs one of anyPermission', () => {
    const ops = advanced.nav.find((n) => n.id === 'advanced-ops')
    expect(permitted(ops, holder())).toBe(false)
    expect(permitted(ops, holder('read:alerts'))).toBe(false)
    expect(permitted(ops, holder('read:dhcp'))).toBe(true)
    expect(permitted(ops, holder('read:dns'))).toBe(true)
    const route = advanced.routes.find((r) => r.path === '/advanced/ops')
    expect(permitted(route, holder())).toBe(false)
  })
})
