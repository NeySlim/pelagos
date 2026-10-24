// SPDX-License-Identifier: Apache-2.0
import { useParams } from 'react-router-dom'
import { Globe } from '@phosphor-icons/react'
import { AreaPlaceholder } from '../../components/AreaPlaceholder'
import { api } from '../../services/api'

export default function ZoneDetailPage() {
  const { zone } = useParams()
  return (
    <AreaPlaceholder
      ns="dns"
      page="zoneDetail"
      icon={Globe}
      deps={[zone]}
      load={() =>
        Promise.all([api.dns.zone(zone), api.dns.records(zone, { per_page: 50 })]).then(([detail, records]) => ({ ...detail, records }))
      }
      endpoint={`GET /dns/zones/${zone}, GET /dns/zones/${zone}/records`}
    />
  )
}
