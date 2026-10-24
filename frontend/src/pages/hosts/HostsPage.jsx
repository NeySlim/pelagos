// SPDX-License-Identifier: Apache-2.0
import { Desktop } from '@phosphor-icons/react'
import { AreaPlaceholder } from '../../components/AreaPlaceholder'
import { api } from '../../services/api'

export default function HostsPage() {
  return <AreaPlaceholder ns="hosts" page="list" icon={Desktop} load={() => api.hosts.list({ per_page: 25 })} endpoint="GET /hosts" />
}
