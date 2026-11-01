// SPDX-License-Identifier: Apache-2.0
// A Kea config-hash divergence left by a partial apply (section 9) is settled by copying the
// shared configuration of one node onto the other: one button per direction, then PlanPreview.
import { useTranslation } from 'react-i18next'
import { ArrowsLeftRight } from '@phosphor-icons/react'
import { Button } from '../../components/Button'
import { ReadOnlyNote } from '../../components/ReadOnlyNote'
import { usePermission } from '../../hooks/usePermission'
import { api } from '../../services/api'
import { useNodeNames, usePlanFlow } from '../dhcp/hooks'
import { reconcileOptions } from '../dhcp/keaFile'

export function ReconcileActions({ alert }) {
  const { t } = useTranslation('alerts')
  const { hasPermission } = usePermission()
  const { nameOf } = useNodeNames()
  const flow = usePlanFlow()
  const options = reconcileOptions(alert)
  if (!options.length || alert.state === 'resolved') return null
  if (!hasPermission('write:dhcp.config')) return <ReadOnlyNote permission="write:dhcp.config" />
  return (
    <>
      {options.map((o) => (
        <Button
          key={`${o.source}>${o.target}`}
          variant="secondary"
          size="sm"
          disabled={flow.building}
          title={t('actions.reconcileHelp', { source: nameOf(o.source), target: nameOf(o.target) })}
          onClick={() => flow.build(() => api.dhcp.reconcilePlan(o.family, o.source, o.target))}
          data-testid="alert-reconcile"
        >
          <ArrowsLeftRight size={14} />
          {t('actions.reconcileFrom', { node: nameOf(o.source) })}
        </Button>
      ))}
      {flow.modal}
    </>
  )
}
