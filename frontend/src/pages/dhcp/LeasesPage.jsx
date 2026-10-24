// SPDX-License-Identifier: Apache-2.0
import { Clock } from '@phosphor-icons/react'
import { AreaPlaceholder } from '../../components/AreaPlaceholder'
import { api } from '../../services/api'

// `family` is 'v4' or 'v6', given by the route.
export default function LeasesPage({ family }) {
  return (
    <AreaPlaceholder
      ns="dhcp"
      page="leases"
      icon={Clock}
      deps={[family]}
      load={() => api.dhcp.leases(family, { per_page: 25 })}
      endpoint={`GET /dhcp/${family}/leases`}
    />
  )
}
