// SPDX-License-Identifier: Apache-2.0
import { Heartbeat } from '@phosphor-icons/react'
import { AreaPlaceholder } from '../../components/AreaPlaceholder'
import { api } from '../../services/api'

// `family` is 'v4' or 'v6', given by the route.
export default function HaPage({ family }) {
  return (
    <AreaPlaceholder
      ns="dhcp"
      page="ha"
      icon={Heartbeat}
      deps={[family]}
      load={() => Promise.all([api.dhcp.ha(family), api.dhcp.servers(family)]).then(([ha, servers]) => ({ ha, servers }))}
      endpoint={`GET /dhcp/${family}/ha, GET /dhcp/${family}/servers`}
    />
  )
}
