// SPDX-License-Identifier: Apache-2.0
import { ShieldCheck } from '@phosphor-icons/react'
import { AreaPlaceholder } from '../../components/AreaPlaceholder'
import { api } from '../../services/api'

export default function DnssecPage() {
  return <AreaPlaceholder ns="dns" page="dnssec" icon={ShieldCheck} load={() => api.dns.zones({ kind: 'primary' })} endpoint="GET /dns/zones, GET /dns/zones/{zone}/dnssec" />
}
