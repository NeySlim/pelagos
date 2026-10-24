// SPDX-License-Identifier: Apache-2.0
import { ArrowsLeftRight } from '@phosphor-icons/react'
import { AreaPlaceholder } from '../../components/AreaPlaceholder'
import { api } from '../../services/api'

export default function ResolverPage() {
  return <AreaPlaceholder ns="dns" page="resolver" icon={ArrowsLeftRight} load={() => api.dns.resolver()} endpoint="GET /dns/resolver" />
}
