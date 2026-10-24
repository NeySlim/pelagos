// SPDX-License-Identifier: Apache-2.0
import { Users } from '@phosphor-icons/react'
import { AreaPlaceholder } from '../../components/AreaPlaceholder'
import { api } from '../../services/api'

export default function UsersPage() {
  return <AreaPlaceholder ns="admin" page="users" icon={Users} load={() => api.admin.users()} endpoint="GET /admin/users" />
}
