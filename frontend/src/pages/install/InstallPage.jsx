// SPDX-License-Identifier: Apache-2.0
import { DownloadSimple } from '@phosphor-icons/react'
import { AreaPlaceholder } from '../../components/AreaPlaceholder'
import { api } from '../../services/api'

export default function InstallPage() {
  return <AreaPlaceholder ns="install" page="detect" icon={DownloadSimple} load={() => api.install.detect()} endpoint="GET /install/detect" />
}
