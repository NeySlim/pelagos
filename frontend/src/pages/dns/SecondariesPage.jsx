// SPDX-License-Identifier: Apache-2.0
import { CopySimple } from '@phosphor-icons/react'
import { AreaPlaceholder } from '../../components/AreaPlaceholder'
import { api } from '../../services/api'

export default function SecondariesPage() {
  return <AreaPlaceholder ns="dns" page="secondaries" icon={CopySimple} load={() => api.dns.zones({ kind: 'secondary' })} endpoint="GET /dns/zones?kind=secondary" />
}
