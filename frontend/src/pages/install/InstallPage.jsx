// SPDX-License-Identifier: Apache-2.0
// Install and import: what detection found on this node, then a step by step
// wizard (mode, engines, package source, review) that builds an install or
// import plan; applying it runs a Job whose steps PlanPreview follows live.
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { DownloadSimple, ArrowsClockwise, CheckCircle, XCircle, CaretLeft, CaretRight, Lightning, ShieldWarning, Package, ArrowsLeftRight } from '@phosphor-icons/react'
import { PageLayout, Card, Button, Badge, StatusBadge, LoadingSpinner, PlanPreview } from '../../components'
import { useApi } from '../../hooks'
import { useAuth } from '../../contexts/AuthContext'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'
import { cn } from '../../lib/utils'
import {
  stepsFor, engineChoices, initialState, setMode, toggleEngine, validateStep, canGoNext, next, prev,
  buildRequest, needsSeries, SOURCES, ISC_SERIES,
} from './wizard'

function Check({ ok, label }) {
  return (
    <li className="flex items-center gap-2 text-sm">
      {ok ? <CheckCircle size={16} weight="fill" className="status-success-text" /> : <XCircle size={16} weight="fill" className="status-warning-text" />}
      <span className="text-text-primary">{label}</span>
    </li>
  )
}

function DetectCard({ detect }) {
  const { t } = useTranslation('install')
  const engines = detect.engines || {}
  return (
    <Card className="p-4 space-y-4" hover={false} data-testid="install-detect">
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="text-sm font-semibold text-text-primary">{t('detect.title')}</h3>
        {detect.distro && (
          <Badge variant="outline" size="sm">
            {detect.distro.pretty_name || detect.distro.name || `${detect.distro.id} ${detect.distro.version_id}`}
          </Badge>
        )}
        {detect.distro?.package_manager && <Badge variant="secondary" size="sm" className="font-mono">{detect.distro.package_manager}</Badge>}
      </div>
      <div className="overflow-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-2xs uppercase tracking-wider text-text-tertiary">
              <th className="py-1 pr-3">{t('detect.engine')}</th>
              <th className="py-1 pr-3">{t('detect.installed')}</th>
              <th className="py-1 pr-3">{t('detect.version')}</th>
              <th className="py-1 pr-3">{t('detect.service')}</th>
              <th className="py-1 pr-3">{t('detect.running')}</th>
              <th className="py-1">{t('detect.config')}</th>
            </tr>
          </thead>
          <tbody>
            {Object.entries(engines).map(([name, e]) => (
              <tr key={name} className="border-t border-border-op30" data-testid="install-engine-row">
                <td className="py-1.5 pr-3 font-medium">{t(`engines.${name}`, { defaultValue: name })}</td>
                <td className="py-1.5 pr-3"><StatusBadge status={e.installed ? 'true' : 'false'} /></td>
                <td className="py-1.5 pr-3 font-mono text-xs">{e.version || '-'}</td>
                <td className="py-1.5 pr-3 font-mono text-xs">{e.service || '-'}</td>
                <td className="py-1.5 pr-3">{e.installed ? <StatusBadge status={e.running ? 'online' : 'offline'} label={e.running ? t('detect.yes') : t('detect.no')} /> : '-'}</td>
                <td className="py-1.5 font-mono text-xs break-all">{e.config || '-'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {detect.pelagos && (
        <ul className="grid grid-cols-1 md:grid-cols-3 gap-2" data-testid="install-checks">
          <Check ok={detect.pelagos.include_present} label={t('detect.include')} />
          <Check ok={detect.pelagos.sockets_ok} label={t('detect.sockets')} />
          <Check ok={detect.pelagos.keys_present} label={t('detect.keys')} />
        </ul>
      )}
    </Card>
  )
}

function Stepper({ steps, current }) {
  const { t } = useTranslation('install')
  const index = steps.indexOf(current)
  return (
    <ol className="flex flex-wrap items-center gap-2" data-testid="wizard-steps">
      {steps.map((step, i) => (
        <li key={step} className="flex items-center gap-2">
          <span
            className={cn(
              'w-6 h-6 rounded-full flex items-center justify-center text-xs font-semibold',
              i < index ? 'status-success-bg status-success-text' : i === index ? 'status-primary-bg-solid text-white' : 'bg-bg-tertiary text-text-tertiary',
            )}
          >
            {i + 1}
          </span>
          <span className={cn('text-xs', i === index ? 'text-text-primary font-semibold' : 'text-text-secondary')} data-current={i === index || undefined}>
            {t(`wizard.steps.${step}`)}
          </span>
          {i < steps.length - 1 && <span className="w-6 h-px bg-border" />}
        </li>
      ))}
    </ol>
  )
}

function Choice({ selected, onClick, icon: Icon, title, body, disabled, testId }) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className={cn(
        'text-left rounded-lg border p-3 transition-colors disabled:opacity-50 disabled:cursor-not-allowed',
        selected ? 'border-accent-primary bg-accent-primary-op10' : 'border-border hover:bg-bg-tertiary',
      )}
      aria-pressed={selected}
      data-testid={testId}
    >
      <div className="flex items-center gap-2 text-sm font-semibold text-text-primary">
        {Icon && <Icon size={16} />}
        {title}
      </div>
      {body && <p className="text-xs text-text-secondary mt-1">{body}</p>}
    </button>
  )
}

function Wizard({ detect, onDone }) {
  const { t } = useTranslation(['install', 'common'])
  const { modules } = useAuth()
  const [state, setState] = useState(() => initialState(detect, modules))
  const [plan, setPlan] = useState(null)
  const [building, setBuilding] = useState(false)
  const [buildError, setBuildError] = useState(null)
  const steps = stepsFor(state.mode)
  const error = validateStep(state, detect, modules)
  const choices = engineChoices(state.mode, detect, modules)

  useEffect(() => {
    setPlan(null)
    setBuildError(null)
  }, [state.mode, state.engines, state.source, state.iscSeries])

  const build = async () => {
    setBuilding(true)
    setBuildError(null)
    try {
      const { kind, body } = buildRequest(state)
      setPlan(kind === 'import' ? await api.install.importPlan(body.engines) : await api.install.plan(body))
    } catch (err) {
      setBuildError(err)
    } finally {
      setBuilding(false)
    }
  }

  return (
    <Card className="p-4 space-y-4" hover={false} data-testid="install-wizard">
      <div className="flex flex-wrap items-center gap-3">
        <h3 className="text-sm font-semibold text-text-primary mr-2">{t('wizard.title')}</h3>
        <Stepper steps={steps} current={state.step} />
      </div>

      {state.step === 'mode' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <Choice selected={state.mode === 'import'} onClick={() => setState((s) => setMode(s, 'import', detect, modules))} icon={ArrowsLeftRight} title={t('wizard.mode.import')} body={t('wizard.mode.importBody')} testId="wizard-mode-import" />
          <Choice selected={state.mode === 'install'} onClick={() => setState((s) => setMode(s, 'install', detect, modules))} icon={Package} title={t('wizard.mode.install')} body={t('wizard.mode.installBody')} testId="wizard-mode-install" />
        </div>
      )}

      {state.step === 'engines' && (
        <div className="space-y-2">
          <p className="text-xs text-text-secondary">{t(`wizard.engines.help.${state.mode}`)}</p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
            {choices.map((c) => (
              <label key={c.engine} className={cn('flex items-start gap-2 rounded-lg border border-border p-3', c.selectable ? 'cursor-pointer hover:bg-bg-tertiary' : 'opacity-60')} data-testid={`wizard-engine-${c.engine}`}>
                <input type="checkbox" className="mt-0.5" checked={state.engines.includes(c.engine)} disabled={!c.selectable} onChange={() => setState((s) => toggleEngine(s, c.engine))} />
                <span>
                  <span className="block text-sm font-medium text-text-primary">{t(`engines.${c.engine}`)}</span>
                  <span className="block text-xs text-text-tertiary">{c.reason ? t(`wizard.engines.reason.${c.reason}`) : t(`wizard.engines.about.${c.engine}`)}</span>
                </span>
              </label>
            ))}
          </div>
        </div>
      )}

      {state.step === 'source' && (
        <div className="space-y-3">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {SOURCES.map((source) => (
              <Choice key={source} selected={state.source === source} onClick={() => setState((s) => ({ ...s, source }))} title={t(`wizard.source.${source}`)} body={t(`wizard.source.${source}Body`)} testId={`wizard-source-${source}`} />
            ))}
          </div>
          {needsSeries(state) && (
            <div className="flex flex-wrap items-center gap-2" data-testid="wizard-series">
              <span className="text-xs text-text-secondary">{t('wizard.source.series')}</span>
              {ISC_SERIES.map((series) => (
                <Button key={series} size="xs" variant={state.iscSeries === series ? 'primary' : 'secondary'} onClick={() => setState((s) => ({ ...s, iscSeries: series }))}>
                  Kea {series}
                </Button>
              ))}
            </div>
          )}
        </div>
      )}

      {state.step === 'review' && (
        <div className="space-y-3" data-testid="wizard-review">
          <dl className="grid grid-cols-1 md:grid-cols-3 gap-2 text-sm">
            <div><dt className="text-2xs uppercase text-text-tertiary">{t('wizard.review.mode')}</dt><dd>{t(`wizard.mode.${state.mode}`)}</dd></div>
            <div><dt className="text-2xs uppercase text-text-tertiary">{t('wizard.review.engines')}</dt><dd>{state.engines.map((e) => t(`engines.${e}`)).join(', ')}</dd></div>
            {state.mode === 'install' && (
              <div><dt className="text-2xs uppercase text-text-tertiary">{t('wizard.review.source')}</dt><dd>{t(`wizard.source.${state.source}`)}{needsSeries(state) ? `, Kea ${state.iscSeries}` : ''}</dd></div>
            )}
          </dl>
          <p className="text-xs text-text-secondary">{t(`wizard.review.help.${state.mode}`)}</p>
          {!plan && (
            <Button onClick={build} loading={building} data-testid="wizard-build">
              <Lightning size={14} weight="fill" />
              {t('wizard.review.build')}
            </Button>
          )}
          {buildError && <p className="text-sm status-danger-text" role="alert">{errorMessage(buildError)}</p>}
          {plan && <PlanPreview plan={plan} onApplied={onDone} closeLabel={t('wizard.review.another')} onClose={() => setPlan(null)} />}
        </div>
      )}

      {error && state.step !== 'review' && (
        <p className="text-xs status-warning-text" data-testid="wizard-error">{t(`wizard.errors.${error}`)}</p>
      )}
      <div className="flex items-center gap-2 pt-2 border-t border-border">
        <Button variant="secondary" size="sm" onClick={() => setState(prev)} disabled={state.step === steps[0]} data-testid="wizard-prev">
          <CaretLeft size={14} />
          {t('wizard.prev')}
        </Button>
        {state.step !== 'review' && (
          <Button size="sm" className="ml-auto" onClick={() => setState((s) => next(s, detect, modules))} disabled={!canGoNext(state, detect, modules)} data-testid="wizard-next">
            {t('wizard.next')}
            <CaretRight size={14} />
          </Button>
        )}
      </div>
    </Card>
  )
}

export default function InstallPage() {
  const { t } = useTranslation(['install', 'common'])
  const detectQ = useApi(() => api.install.detect(), [])

  return (
    <PageLayout
      icon={DownloadSimple}
      title={t('pages.detect.title')}
      subtitle={t('pages.detect.subtitle')}
      testId="page-install-detect"
      actions={
        <>
          <Link to="/install/security" className="btn-soft focus-ring text-text-primary inline-flex items-center justify-center rounded-md font-medium px-2.5 py-1.5 text-xs gap-1.5">
            <ShieldWarning size={14} />
            {t('nav.security')}
          </Link>
          <Button variant="secondary" size="sm" onClick={detectQ.refetch} disabled={detectQ.loading}>
            <ArrowsClockwise size={14} />
            {t('detect.again')}
          </Button>
        </>
      }
    >
      {detectQ.loading && !detectQ.data ? (
        <div className="flex justify-center py-12"><LoadingSpinner size="md" /></div>
      ) : detectQ.error ? (
        <Card className="p-4" hover={false}><p className="text-sm status-danger-text" role="alert">{errorMessage(detectQ.error)}</p></Card>
      ) : detectQ.data ? (
        <div className="space-y-4 max-w-5xl">
          <DetectCard detect={detectQ.data} />
          <Wizard detect={detectQ.data} onDone={() => detectQ.refetch()} />
        </div>
      ) : null}
    </PageLayout>
  )
}
