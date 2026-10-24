// SPDX-License-Identifier: Apache-2.0
// Hook libraries: what Kea loads, with parameters, and add/remove through a plan
// on the whole hooks-libraries list (the order of the list is kept).
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { PuzzlePiece, Plus } from '@phosphor-icons/react'
import { Badge } from '../../components/Badge'
import { Button } from '../../components/Button'
import { DataTable } from '../../components/DataTable'
import { FormModal } from '../../components/FormModal'
import { JsonTree } from '../../components/JsonTree'
import { useApi } from '../../hooks/useApi'
import { usePermission } from '../../hooks/usePermission'
import { api } from '../../services/api'
import { AreaPage, NativeSelect, RowActions } from './ui'
import { usePlanFlow } from './hooks'
import { hookLibraryPath } from './lib'

// Hooks the other DHCP screens depend on: removing them degrades Pelagos.
const CORE_HOOKS = ['lease_cmds', 'host_cmds', 'subnet_cmds', 'stat_cmds', 'ha']

export default function HooksPage({ family }) {
  const { t } = useTranslation(['dhcp', 'common'])
  const { hasPermission } = usePermission()
  const canWrite = hasPermission('write:dhcp.config')
  const hooks = useApi(() => api.dhcp.hooks(family), [family])
  const [adding, setAdding] = useState(false)
  const [expanded, setExpanded] = useState(null)
  const flow = usePlanFlow({ onApplied: hooks.refetch })
  const items = hooks.data?.items || []
  const available = (hooks.data?.available || []).filter((name) => !items.some((h) => h.name === name))

  const plan = (next) =>
    flow.build(() => api.dhcp.hooksPlan(family, [{ op: 'replace', target: 'hooks-libraries', before: items, after: next.map(({ library, parameters }) => ({ library, parameters })) }]))

  const columns = [
    {
      key: 'name',
      label: t('fields.name'),
      render: (h) => (
        <span className="inline-flex items-center gap-1.5">
          <span className="font-mono text-xs">{h.name}</span>
          {!h.known && <Badge variant="warning" size="sm">{t('hooks.unknown')}</Badge>}
          {CORE_HOOKS.includes(h.name) && <Badge variant="outline" size="sm">{t('hooks.core')}</Badge>}
        </span>
      ),
    },
    { key: 'library', label: t('fields.library'), mono: true, truncate: true },
    {
      key: 'parameters',
      label: t('fields.parameters'),
      render: (h) => {
        const count = Object.keys(h.parameters || {}).length
        return count ? (
          <Button variant="ghost" size="xs" onClick={(e) => { e.stopPropagation(); setExpanded(expanded === h.library ? null : h.library) }}>
            {t('hooks.parameterCount', { n: count })}
          </Button>
        ) : (
          <span className="text-text-tertiary">-</span>
        )
      },
    },
    ...(canWrite
      ? [{
          key: 'actions',
          label: '',
          align: 'right',
          render: (h) => <RowActions deleteLabel={t('hooks.remove')} onDelete={() => plan(items.filter((x) => x.library !== h.library))} />,
        }]
      : []),
  ]
  const shown = items.find((h) => h.library === expanded)

  return (
    <AreaPage
      ns="dhcp"
      page="hooks"
      icon={PuzzlePiece}
      family={family}
      onRefresh={hooks.refetch}
      loading={hooks.loading}
      actions={
        canWrite && available.length > 0 && (
          <Button size="sm" onClick={() => setAdding(true)} data-testid="hook-add">
            <Plus size={14} />
            {t('hooks.add')}
          </Button>
        )
      }
    >
      <div className="space-y-4">
        <DataTable
          columns={columns}
          rows={items}
          rowKey="library"
          loading={hooks.loading}
          error={hooks.error}
          onRetry={hooks.refetch}
          emptyTitle={t('hooks.empty')}
          emptyIcon={PuzzlePiece}
          testId="hooks-table"
        />
        {shown && (
          <div className="rounded-xl border border-border bg-bg-secondary p-3" data-testid="hook-parameters">
            <p className="text-xs font-semibold text-text-primary mb-2 font-mono">{shown.name}</p>
            <JsonTree data={shown.parameters} expandedDepth={3} />
          </div>
        )}
      </div>
      {adding && (
        <AddHookForm
          available={available}
          building={flow.building}
          onClose={() => setAdding(false)}
          onSubmit={async (name) => {
            const created = await plan([...items, { library: hookLibraryPath(items, name), parameters: {} }])
            if (created) setAdding(false)
          }}
        />
      )}
      {flow.modal}
    </AreaPage>
  )
}

function AddHookForm({ available, building, onClose, onSubmit }) {
  const { t } = useTranslation(['dhcp', 'common'])
  const [name, setName] = useState(available[0])
  return (
    <FormModal open onClose={onClose} title={t('hooks.addTitle')} onSubmit={() => onSubmit(name)} submitLabel={t('form.preview')} loading={building} size="sm" testId="hook-form">
      <NativeSelect label={t('fields.name')} value={name} onChange={setName} options={available.map((n) => ({ value: n, label: n }))} testId="hook-name" />
      <p className="text-xs text-text-tertiary">{t('hooks.addHint')}</p>
    </FormModal>
  )
}
