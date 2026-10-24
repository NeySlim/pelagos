// SPDX-License-Identifier: Apache-2.0
import { Gear } from '@phosphor-icons/react'
import { AreaPlaceholder } from '../../components/AreaPlaceholder'
import { api } from '../../services/api'

export default function SettingsPage() {
  return <AreaPlaceholder ns="admin" page="settings" icon={Gear} load={() => api.admin.settings()} endpoint="GET /admin/settings" />
}
