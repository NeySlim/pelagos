// SPDX-License-Identifier: Apache-2.0
// Section 9: a Kea configuration file that no longer says what the daemon runs blocks every
// Kea write until one side is adopted. The banner shows it on the DHCP pages and offers both
// adopt plans for this node; another node's file is adopted from that node.
import { useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { FileX } from '@phosphor-icons/react'
import { Button } from '../../components/Button'
import { usePermission } from '../../hooks/usePermission'
import { useApi } from '../../hooks/useApi'
import { useWsTopic } from '../../hooks/useWebSocket'
import { api } from '../../services/api'
import { useNodeNames, usePlanFlow } from './hooks'
import { adoptCall, divergedFiles } from './keaFile'

// `engine` is 'v4', 'v6' or 'd2'.
export function KeaFileBanner({ engine }) {
  const { t } = useTranslation('dhcp')
  const { hasPermission } = usePermission()
  const canAdopt = hasPermission('write:dhcp.config')
  const { nodes, nameOf } = useNodeNames()
  const status = useApi(() => (engine === 'd2' ? api.d2.configFile() : api.dhcp.configFile(engine)), [engine])
  const refetch = status.refetch
  const flow = usePlanFlow({ onApplied: refetch })
  useWsTopic(
    'alerts',
    useCallback(() => refetch(), [refetch]),
  )
  const selfId = nodes.find((n) => n.is_self)?.peer?.id
  const diverged = divergedFiles(status.data?.items)
  if (!diverged.length) return flow.modal
  return (
    <div className="flex flex-col gap-2" data-testid={`kea-file-banner-${engine}`}>
      {diverged.map((item) => {
        const here = !selfId || item.node_id === selfId
        return (
          <div
            key={item.node_id}
            role="alert"
            className="flex flex-col gap-2 rounded-lg border status-warning-bg status-warning-border px-3 py-2 text-xs status-warning-text"
          >
            <div className="flex items-start gap-2">
              <FileX size={16} weight="fill" className="shrink-0 mt-0.5" />
              <div className="flex-1 min-w-0">
                <p className="font-semibold">{t('keaFile.title', { path: item.path || '-', node: nameOf(item.node_id) })}</p>
                <p className="text-text-secondary">{t('keaFile.blocked')}</p>
                {item.differences?.length > 0 && (
                  <ul className="mt-1 font-mono text-2xs text-text-secondary list-disc pl-4 break-all" data-testid="kea-file-differences">
                    {item.differences.slice(0, 5).map((d) => (
                      <li key={d}>{d}</li>
                    ))}
                    {(item.count || item.differences.length) > 5 && <li>{t('keaFile.more', { n: (item.count || item.differences.length) - 5 })}</li>}
                  </ul>
                )}
              </div>
            </div>
            {canAdopt && here && (
              <div className="flex flex-wrap items-center gap-2 pl-6">
                <Button size="xs" variant="secondary" disabled={flow.building} onClick={() => flow.build(() => adoptCall(engine, 'file'))} data-testid="adopt-file">
                  {t('keaFile.adoptFile')}
                </Button>
                <Button size="xs" variant="secondary" disabled={flow.building} onClick={() => flow.build(() => adoptCall(engine, 'running'))} data-testid="adopt-running">
                  {t('keaFile.adoptRunning')}
                </Button>
                <span className="text-2xs text-text-tertiary">{t('keaFile.hint')}</span>
              </div>
            )}
            {canAdopt && !here && <p className="pl-6 text-2xs text-text-tertiary">{t('keaFile.otherNode', { node: nameOf(item.node_id) })}</p>}
          </div>
        )
      })}
      {flow.modal}
    </div>
  )
}

export default KeaFileBanner
