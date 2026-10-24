// SPDX-License-Identifier: Apache-2.0
import { Globe } from '@phosphor-icons/react'
import { AreaPlaceholder } from '../../components/AreaPlaceholder'
import { api } from '../../services/api'

export default function ZonesPage() {
  return <AreaPlaceholder ns="dns" page="zones" icon={Globe} load={() => api.dns.zones()} endpoint="GET /dns/zones" />
}
