// SPDX-License-Identifier: Apache-2.0
import { BracketsCurly } from '@phosphor-icons/react'
import { AreaPlaceholder } from '../../components/AreaPlaceholder'
import { api } from '../../services/api'

export default function KeaEditorPage() {
  return <AreaPlaceholder ns="advanced" page="kea" icon={BracketsCurly} load={() => api.dhcp.config('v4')} endpoint="GET /dhcp/v4/config, GET /advanced/kea/v4/schema" />
}
