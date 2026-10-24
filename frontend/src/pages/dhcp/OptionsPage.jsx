// SPDX-License-Identifier: Apache-2.0
import { SlidersHorizontal } from '@phosphor-icons/react'
import { AreaPlaceholder } from '../../components/AreaPlaceholder'
import { api } from '../../services/api'

// `family` is 'v4' or 'v6', given by the route.
export default function OptionsPage({ family }) {
  return (
    <AreaPlaceholder
      ns="dhcp"
      page="options"
      icon={SlidersHorizontal}
      deps={[family]}
      load={() => api.dhcp.options(family)}
      endpoint={`GET /dhcp/${family}/options`}
    />
  )
}
