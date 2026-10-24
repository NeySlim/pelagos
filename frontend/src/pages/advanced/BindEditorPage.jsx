// SPDX-License-Identifier: Apache-2.0
import { Code } from '@phosphor-icons/react'
import { AreaPlaceholder } from '../../components/AreaPlaceholder'
import { api } from '../../services/api'

export default function BindEditorPage() {
  return <AreaPlaceholder ns="advanced" page="bind" icon={Code} load={() => api.advanced.bindTree()} endpoint="GET /advanced/bind/tree, GET /advanced/bind/grammar" />
}
