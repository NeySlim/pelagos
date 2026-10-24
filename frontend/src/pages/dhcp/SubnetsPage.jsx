// SPDX-License-Identifier: Apache-2.0
import { Network } from '@phosphor-icons/react'
import { AreaPlaceholder } from '../../components/AreaPlaceholder'
import { api } from '../../services/api'

// `family` is 'v4' or 'v6', given by the route.
export default function SubnetsPage({ family }) {
  return (
    <AreaPlaceholder
      ns="dhcp"
      page="subnets"
      icon={Network}
      deps={[family]}
      load={() => api.dhcp.subnets(family)}
      endpoint={`GET /dhcp/${family}/subnets`}
    />
  )
}
