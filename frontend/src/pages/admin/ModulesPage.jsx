// SPDX-License-Identifier: Apache-2.0
import { SquaresFour } from '@phosphor-icons/react'
import { AreaPlaceholder } from '../../components/AreaPlaceholder'
import { api } from '../../services/api'

export default function ModulesPage() {
  return <AreaPlaceholder ns="admin" page="modules" icon={SquaresFour} load={() => api.admin.modules()} endpoint="GET /admin/modules" />
}
