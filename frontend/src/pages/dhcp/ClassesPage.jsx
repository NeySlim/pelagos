// SPDX-License-Identifier: Apache-2.0
import { Tag } from '@phosphor-icons/react'
import { AreaPlaceholder } from '../../components/AreaPlaceholder'
import { api } from '../../services/api'

// `family` is 'v4' or 'v6', given by the route.
export default function ClassesPage({ family }) {
  return (
    <AreaPlaceholder
      ns="dhcp"
      page="classes"
      icon={Tag}
      deps={[family]}
      load={() => api.dhcp.clientClasses(family)}
      endpoint={`GET /dhcp/${family}/client-classes`}
    />
  )
}
