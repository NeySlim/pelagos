// SPDX-License-Identifier: Apache-2.0
import { HardDrives } from '@phosphor-icons/react'
import { AreaPlaceholder } from '../../components/AreaPlaceholder'
import { api } from '../../services/api'

export default function NodesPage() {
  return <AreaPlaceholder ns="nodes" page="list" icon={HardDrives} load={() => Promise.all([api.nodes.list(), api.nodes.replication()]).then(([nodes, replication]) => ({ nodes, replication }))} endpoint="GET /nodes, GET /nodes/replication" />
}
