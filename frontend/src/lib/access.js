// SPDX-License-Identifier: Apache-2.0
// Permission gate shared by routes and nav items: `permission` must be held, and when
// `anyPermission` is set at least one of its entries must be held too.
export function permitted({ permission, anyPermission } = {}, hasPermission) {
  if (permission && !hasPermission(permission)) return false
  if (anyPermission?.length && !anyPermission.some((p) => hasPermission(p))) return false
  return true
}
