// SPDX-License-Identifier: Apache-2.0
import { TreeStructure } from '@phosphor-icons/react'
import { AreaPlaceholder } from '../../components/AreaPlaceholder'
import { api } from '../../services/api'

// `family` is 'v4' or 'v6', given by the route.
export default function SharedNetworksPage({ family }) {
  return (
    <AreaPlaceholder
      ns="dhcp"
      page="sharedNetworks"
      icon={TreeStructure}
      deps={[family]}
      load={() => api.dhcp.sharedNetworks(family)}
      endpoint={`GET /dhcp/${family}/shared-networks`}
    />
  )
}
