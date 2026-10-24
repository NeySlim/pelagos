// SPDX-License-Identifier: Apache-2.0
import { PuzzlePiece } from '@phosphor-icons/react'
import { AreaPlaceholder } from '../../components/AreaPlaceholder'
import { api } from '../../services/api'

// `family` is 'v4' or 'v6', given by the route.
export default function HooksPage({ family }) {
  return (
    <AreaPlaceholder
      ns="dhcp"
      page="hooks"
      icon={PuzzlePiece}
      deps={[family]}
      load={() => api.dhcp.hooks(family)}
      endpoint={`GET /dhcp/${family}/hooks`}
    />
  )
}
