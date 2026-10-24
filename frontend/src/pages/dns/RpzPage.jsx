// SPDX-License-Identifier: Apache-2.0
import { Prohibit } from '@phosphor-icons/react'
import { AreaPlaceholder } from '../../components/AreaPlaceholder'
import { api } from '../../services/api'

export default function RpzPage() {
  return <AreaPlaceholder ns="dns" page="rpz" icon={Prohibit} load={() => Promise.all([api.dns.rpz(), api.dns.catalogZones()]).then(([rpz, catalog]) => ({ rpz, catalog }))} endpoint="GET /dns/rpz, GET /dns/catalog-zones" />
}
