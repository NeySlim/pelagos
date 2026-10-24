// SPDX-License-Identifier: Apache-2.0
// Permission helpers over AuthContext. Permissions are "<action>:<resource>" strings
// (architecture section 16); "*" is admin and passes everything.
import { useAuth } from '../contexts/AuthContext'

export function usePermission() {
  const { permissions, hasPermission, isAdmin } = useAuth()
  return {
    permissions,
    hasPermission,
    isAdmin: () => isAdmin,
    canRead: (resource) => hasPermission(`read:${resource}`),
    canWrite: (resource) => hasPermission(`write:${resource}`),
    canOps: (resource) => hasPermission(`ops:${resource}`),
    canAdmin: (resource) => hasPermission(`admin:${resource}`),
  }
}
