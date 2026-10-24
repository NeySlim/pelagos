// SPDX-License-Identifier: Apache-2.0
import { UserCircle } from '@phosphor-icons/react'
import { AreaPlaceholder } from '../../components/AreaPlaceholder'
import { api } from '../../services/api'

export default function AccountPage() {
  return <AreaPlaceholder ns="account" page="account" icon={UserCircle} load={() => api.account.getPreferences()} endpoint="GET /account/preferences" />
}
