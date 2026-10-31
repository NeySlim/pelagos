// SPDX-License-Identifier: Apache-2.0
// Why an action is read only for the current user, for ReadOnlyNote: 'permission' when
// the roles lack every listed permission, 'node' when `nodeId` names another node than
// the one answering, else null.
import { useAuth } from '../contexts/AuthContext'

export function useReadOnlyReason(permission, { nodeId } = {}) {
  const { hasPermission, node } = useAuth()
  if (permission && !hasPermission(permission)) return 'permission'
  const selfId = node?.peer?.id || node?.id
  if (nodeId && selfId && nodeId !== selfId) return 'node'
  return null
}
