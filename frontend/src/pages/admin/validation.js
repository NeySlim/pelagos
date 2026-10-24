// SPDX-License-Identifier: Apache-2.0
// Client-side checks mirroring the server rules (the server stays authoritative).

export const USERNAME_RE = /^[a-z0-9._-]{2,64}$/
export const ROLE_NAME_RE = /^[a-z0-9-]{2,64}$/
export const PASSWORD_MIN = 12

// Password policy of section 16: 12 characters, three character classes.
export function passwordProblem(password) {
  const value = String(password || '')
  if (value.length < PASSWORD_MIN) return 'passwordShort'
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((re) => re.test(value)).length
  return classes < 3 ? 'passwordClasses' : null
}

// RFC 7807 `errors[]` of a validation_error as { field: message }.
export function fieldErrors(err) {
  return Object.fromEntries((err?.errors || []).filter((e) => e.field).map((e) => [e.field.split('.').pop(), e.message]))
}

// Group permission strings "<action>:<resource>" by the resource family (dns, dhcp, ...).
export function groupPermissions(permissions) {
  const groups = new Map()
  for (const p of permissions) {
    const resource = p.split(':')[1] || p
    const family = resource.split('.')[0]
    if (!groups.has(family)) groups.set(family, [])
    groups.get(family).push(p)
  }
  return [...groups.entries()].map(([family, items]) => ({ family, items }))
}
