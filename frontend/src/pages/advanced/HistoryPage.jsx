// SPDX-License-Identifier: Apache-2.0
import { ClockCounterClockwise } from '@phosphor-icons/react'
import { AreaPlaceholder } from '../../components/AreaPlaceholder'
import { api } from '../../services/api'

export default function HistoryPage() {
  return <AreaPlaceholder ns="advanced" page="history" icon={ClockCounterClockwise} load={() => api.advanced.history()} endpoint="GET /advanced/history" />
}
