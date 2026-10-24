// SPDX-License-Identifier: Apache-2.0
import { ClipboardText } from '@phosphor-icons/react'
import { AreaPlaceholder } from '../../components/AreaPlaceholder'
import { api } from '../../services/api'

export default function AuditPage() {
  return <AreaPlaceholder ns="audit" page="list" icon={ClipboardText} load={() => api.audit.list({ per_page: 25 })} endpoint="GET /audit" />
}
