// SPDX-License-Identifier: Apache-2.0
// "Hand over to Pelagos": the statements a screen shows as locked because they sit in the
// user's own files, each with an action, and "Hand over all" for the screen. One plan moves the
// statement to the managed file, checks the effective value and rolls back otherwise.
import { useTranslation } from 'react-i18next'
import { HandGrabbing } from '@phosphor-icons/react'
import { Card } from '../../components/Card'
import { Button } from '../../components/Button'
import { Badge } from '../../components/Badge'
import { api } from '../../services/api'
import { handoverBatch, handoverChanges } from './handover'
import { useNodeNames } from './helpers'

export function HandoverCard({ items, flow, compact = false, testId = 'handover' }) {
  const { t } = useTranslation(['dns', 'common'])
  const { nameOf } = useNodeNames()
  if (!items.length) return null
  const run = (batch) => flow.run(() => api.dns.configPlan(handoverChanges(batch), [...new Set(batch.flatMap((i) => i.nodes || []))]))
  const batch = handoverBatch(items)
  return (
    <Card className="p-4" hover={false} data-testid={testId}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h3 className="text-sm font-semibold text-text-primary">{t('handover.title')}</h3>
          <p className="text-xs text-text-secondary">{t('handover.help', { count: items.length })}</p>
        </div>
        <Button size="sm" variant="secondary" onClick={() => run(batch)} loading={flow.busy} data-testid={`${testId}-all`}>
          <HandGrabbing size={14} />
          {t('handover.all', { count: batch.length })}
        </Button>
      </div>
      {!compact && (
        <ul className="mt-3 divide-y divide-border-op40">
          {items.map((item) => (
            <li key={item.target} className="flex flex-wrap items-center gap-2 py-2" data-testid="handover-item">
              <span className="font-mono text-xs whitespace-nowrap">{item.name}</span>
              <span className="font-mono text-xs text-text-secondary truncate max-w-md">{item.value}</span>
              <span className="font-mono text-2xs text-text-tertiary truncate">{item.config_path}</span>
              {(item.nodes || []).length > 1 && (
                <Badge variant="outline" size="sm" title={(item.nodes || []).map(nameOf).join(', ')}>
                  {t('handover.nodes', { count: item.nodes.length })}
                </Badge>
              )}
              <span className="ml-auto">
                <Button size="xs" variant="ghost" onClick={() => run([item])} disabled={flow.busy} data-testid="handover-one">
                  <HandGrabbing size={13} />
                  {t(`handover.one.${item.kind}`)}
                </Button>
              </span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  )
}
