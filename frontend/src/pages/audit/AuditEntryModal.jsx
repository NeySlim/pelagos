// SPDX-License-Identifier: Apache-2.0
// One audit entry: who, what, where, the request sent to the engine, its answer
// and the diff. Engine payloads are untrusted and render as text only.
import { useTranslation } from 'react-i18next'
import { useMessage } from '../../i18n/message'
import { Modal, StatusBadge, Badge, JsonTree, DiffView, LoadingSpinner } from '../../components'
import { useApi } from '../../hooks'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'
import { formatDate } from '../../lib/utils'

function Field({ label, children, mono }) {
  return (
    <div className="min-w-0">
      <dt className="text-2xs uppercase tracking-wider text-text-tertiary">{label}</dt>
      <dd className={mono ? 'font-mono text-xs text-text-primary break-all' : 'text-sm text-text-primary break-words'}>{children ?? '-'}</dd>
    </div>
  )
}

function Payload({ title, data, testId }) {
  const { t } = useTranslation('audit')
  const empty = !data || (typeof data === 'object' && Object.keys(data).length === 0)
  return (
    <section className="space-y-1" data-testid={testId}>
      <h4 className="text-xs font-semibold text-text-secondary">{title}</h4>
      <div className="rounded-lg border border-border bg-bg-primary p-2 max-h-56 overflow-auto">
        {empty ? <p className="text-xs italic text-text-tertiary">{t('detail.empty')}</p> : <JsonTree data={data} expandedDepth={2} />}
      </div>
    </section>
  )
}

export function AuditEntryDetail({ entry, nodeName = (id) => id }) {
  const { t } = useTranslation(['audit', 'common'])
  const msg = useMessage()
  return (
    <div className="space-y-4" data-testid="audit-entry">
      <dl className="grid grid-cols-2 md:grid-cols-3 gap-3">
        <Field label={t('columns.ts')}>{formatDate(entry.ts, { format: 'long', second: '2-digit' })}</Field>
        <Field label={t('columns.user')}>{entry.user || t('anonymous')}</Field>
        <Field label={t('columns.result')}>
          <StatusBadge status={entry.result} />
        </Field>
        <Field label={t('columns.action')} mono>{entry.action}</Field>
        <Field label={t('columns.target')} mono>{entry.target}</Field>
        <Field label={t('columns.engine')}>{entry.engine ? <Badge variant="outline" size="sm" className="font-mono">{entry.engine}</Badge> : '-'}</Field>
        <Field label={t('columns.node')}>{nodeName(entry.node_id)}</Field>
        <Field label={t('detail.clientIp')} mono>{entry.client_ip}</Field>
        <Field label={t('detail.plan')} mono>{entry.plan_id}</Field>
        <Field label={t('detail.id')} mono>{entry.id}</Field>
      </dl>
      {entry.request?.summary && (
        <p className="text-sm text-text-primary" data-testid="audit-entry-summary">
          {msg(entry.request.summary_message, entry.request.summary)}
        </p>
      )}
      {entry.message && (
        <p className="rounded-lg border border-border px-3 py-2 text-sm text-text-primary" data-testid="audit-entry-message">
          {msg(entry.request?.title_message, entry.message)}
        </p>
      )}
      <section className="space-y-1">
        <h4 className="text-xs font-semibold text-text-secondary">{t('detail.diff')}</h4>
        <DiffView diff={entry.diff} maxHeight={280} emptyLabel={t('detail.noDiff')} />
      </section>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <Payload title={t('detail.request')} data={entry.request} testId="audit-entry-request" />
        <Payload title={t('detail.response')} data={entry.response} testId="audit-entry-response" />
      </div>
    </div>
  )
}

export function AuditEntryModal({ id, rows = [], nodeName, onClose }) {
  const { t } = useTranslation('audit')
  const cached = rows.find((r) => r.id === id)
  const { data, error, loading } = useApi(() => (cached ? Promise.resolve(cached) : api.audit.get(id)), [id], { enabled: Boolean(id) })
  const entry = data && data.id === id ? data : cached
  return (
    <Modal open={Boolean(id)} onClose={onClose} title={t('detail.title')} size="lg">
      <div className="p-4 overflow-auto">
        {entry ? (
          <AuditEntryDetail entry={entry} nodeName={nodeName} />
        ) : loading ? (
          <div className="flex justify-center py-8">
            <LoadingSpinner size="md" />
          </div>
        ) : error ? (
          <p className="text-sm status-danger-text" role="alert">
            {errorMessage(error)}
          </p>
        ) : null}
      </div>
    </Modal>
  )
}

export default AuditEntryModal
