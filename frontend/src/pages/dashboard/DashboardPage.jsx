// SPDX-License-Identifier: Apache-2.0
import { Gauge } from '@phosphor-icons/react'
import { AreaPlaceholder } from '../../components/AreaPlaceholder'
import { api } from '../../services/api'

export default function DashboardPage() {
  return <AreaPlaceholder ns="dashboard" page="overview" icon={Gauge} load={() => api.dashboard.summary()} endpoint="GET /dashboard/summary" />
}
