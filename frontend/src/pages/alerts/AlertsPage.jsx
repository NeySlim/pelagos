// SPDX-License-Identifier: Apache-2.0
import { Bell } from '@phosphor-icons/react'
import { AreaPlaceholder } from '../../components/AreaPlaceholder'
import { api } from '../../services/api'

export default function AlertsPage() {
  return <AreaPlaceholder ns="alerts" page="list" icon={Bell} load={() => Promise.all([api.alerts.summary(), api.alerts.list({ state: 'open' })]).then(([summary, open]) => ({ summary, open }))} endpoint="GET /alerts/summary, GET /alerts" />
}
