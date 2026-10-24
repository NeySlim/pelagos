// SPDX-License-Identifier: Apache-2.0
// Modules: cluster-wide features (DHCPv6, advanced editor) and the engines each
// node drives. Saved as one partial PUT; navigation follows the new modules.
import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { SquaresFour, FloppyDisk, ArrowCounterClockwise } from '@phosphor-icons/react'
import { PageLayout, Card, Button, ToggleSwitch, LoadingSpinner } from '../../components'
import { useApi } from '../../hooks'
import { useAuth } from '../../contexts/AuthContext'
import { useNotification } from '../../contexts/NotificationContext'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'
import { modulesPatch, setClusterModule } from './settingsForm'

const CLUSTER = ['dhcpv6', 'advanced_editor']
const ENGINES = ['bind', 'kea4', 'kea6', 'd2']

export default function ModulesPage() {
  const { t } = useTranslation(['admin', 'common'])
  const { refreshCapabilities } = useAuth()
  const { showSuccess, showError } = useNotification()
  const modulesQ = useApi(() => api.admin.modules(), [])
  const nodesQ = useApi(() => api.nodes.list().catch(() => ({ items: [] })), [])
  const [draft, setDraft] = useState(null)
  const [busy, setBusy] = useState(false)
  useEffect(() => {
    if (modulesQ.data) setDraft(JSON.parse(JSON.stringify(modulesQ.data)))
  }, [modulesQ.data])
  const patch = useMemo(() => (draft && modulesQ.data ? modulesPatch(modulesQ.data, draft) : null), [draft, modulesQ.data])
  const nodeName = (id) => nodesQ.data?.items?.find((n) => n.peer.id === id)?.peer?.name || id

  const save = async () => {
    setBusy(true)
    try {
      const merged = await api.admin.updateModules(patch)
      modulesQ.setData(merged)
      await refreshCapabilities()
      showSuccess(t('modules.saved'))
    } catch (err) {
      showError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <PageLayout
      icon={SquaresFour}
      title={t('pages.modules.title')}
      subtitle={t('pages.modules.subtitle')}
      testId="page-admin-modules"
      actions={
        <>
          <Button variant="secondary" size="sm" disabled={!patch} onClick={() => setDraft(JSON.parse(JSON.stringify(modulesQ.data)))}>
            <ArrowCounterClockwise size={14} />
            {t('common:actions.cancel')}
          </Button>
          <Button size="sm" disabled={!patch} loading={busy} onClick={save} data-testid="modules-save">
            <FloppyDisk size={14} />
            {t('common:actions.save')}
          </Button>
        </>
      }
    >
      {!draft ? (
        modulesQ.error ? <p className="text-sm status-danger-text" role="alert">{errorMessage(modulesQ.error)}</p> : <div className="flex justify-center py-12"><LoadingSpinner size="md" /></div>
      ) : (
        <div className="space-y-4 max-w-4xl">
          <Card className="p-4 space-y-4" hover={false} data-testid="modules-cluster">
            <h3 className="ui-card-title text-sm font-semibold text-text-primary">{t('modules.cluster')}</h3>
            {CLUSTER.map((key) => (
              <ToggleSwitch
                key={key}
                checked={Boolean(draft.cluster?.[key])}
                onChange={(v) => setDraft((d) => setClusterModule(d, key, v))}
                label={t(`modules.features.${key}`)}
                description={t(`modules.features.${key}Help`)}
              />
            ))}
          </Card>
          <Card className="p-4 space-y-3" hover={false} data-testid="modules-nodes">
            <div>
              <h3 className="ui-card-title text-sm font-semibold text-text-primary">{t('modules.nodes')}</h3>
              <p className="text-xs text-text-secondary">{t('modules.nodesHelp')}</p>
            </div>
            <div className="overflow-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-2xs uppercase tracking-wider text-text-tertiary">
                    <th className="py-1 pr-3">{t('modules.node')}</th>
                    {ENGINES.map((e) => <th key={e} className="py-1 pr-3">{t(`modules.engines.${e}`)}</th>)}
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(draft.nodes || {}).map(([id, mods]) => (
                    <tr key={id} className="border-t border-border-op30" data-node={id}>
                      <td className="py-2 pr-3 font-medium">{nodeName(id)}</td>
                      {ENGINES.map((e) => (
                        <td key={e} className="py-2 pr-3">
                          <ToggleSwitch size="sm" ariaLabel={`${t(`modules.engines.${e}`)} ${nodeName(id)}`} checked={Boolean(mods?.[e])} disabled={e === 'kea6' && !draft.cluster?.dhcpv6} onChange={(v) => setDraft((d) => ({ ...d, nodes: { ...d.nodes, [id]: { ...d.nodes[id], [e]: v } } }))} />
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        </div>
      )}
    </PageLayout>
  )
}
