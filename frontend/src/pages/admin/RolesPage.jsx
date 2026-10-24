// SPDX-License-Identifier: Apache-2.0
import { UserGear } from '@phosphor-icons/react'
import { AreaPlaceholder } from '../../components/AreaPlaceholder'
import { api } from '../../services/api'

export default function RolesPage() {
  return <AreaPlaceholder ns="admin" page="roles" icon={UserGear} load={() => api.admin.roles()} endpoint="GET /admin/roles" />
}
