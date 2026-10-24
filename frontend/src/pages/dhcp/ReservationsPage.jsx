// SPDX-License-Identifier: Apache-2.0
import { BookmarkSimple } from '@phosphor-icons/react'
import { AreaPlaceholder } from '../../components/AreaPlaceholder'
import { api } from '../../services/api'

// `family` is 'v4' or 'v6', given by the route.
export default function ReservationsPage({ family }) {
  return (
    <AreaPlaceholder
      ns="dhcp"
      page="reservations"
      icon={BookmarkSimple}
      deps={[family]}
      load={() => api.dhcp.reservations(family, { per_page: 25 })}
      endpoint={`GET /dhcp/${family}/reservations`}
    />
  )
}
