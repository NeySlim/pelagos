// SPDX-License-Identifier: Apache-2.0
import { ShieldWarning } from '@phosphor-icons/react'
import { AreaPlaceholder } from '../../components/AreaPlaceholder'
import { api } from '../../services/api'

export default function SecurityPage() {
  return <AreaPlaceholder ns="install" page="security" icon={ShieldWarning} load={() => api.install.security()} endpoint="GET /install/security" />
}
