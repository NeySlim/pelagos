// SPDX-License-Identifier: Apache-2.0
import { ArrowsClockwise } from '@phosphor-icons/react'
import { AreaPlaceholder } from '../../components/AreaPlaceholder'
import { api } from '../../services/api'

// `family` is 'v4' or 'v6', given by the route.
export default function DdnsPage({ family }) {
  return (
    <AreaPlaceholder
      ns="dhcp"
      page="ddns"
      icon={ArrowsClockwise}
      deps={[family]}
      load={() => Promise.all([api.dhcp.ddns(family), api.d2.stats()]).then(([ddns, d2]) => ({ ddns, d2 }))}
      endpoint={`GET /dhcp/${family}/ddns, GET /dhcp/d2/stats`}
    />
  )
}
