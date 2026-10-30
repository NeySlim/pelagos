// SPDX-License-Identifier: Apache-2.0
// Live rate of one counter source (hooks/useLiveRates): the current value per second
// counting up, and the recent window as a stippled area with a glass tooltip.
import { useTranslation } from 'react-i18next'
import { useLiveRates } from '../hooks/useLiveRates'
import { LIVE_CAPACITY, LIVE_INTERVAL_MS, latest, liveWindowLabel } from '../lib/liveRates'
import { cn } from '../lib/utils'
import { CountUp, StatusDot, StippledAreaChart } from './motion'

export function LiveRatePanel({ target, title, tone = 'primary', height = 64, className, testId = 'live-rate' }) {
  const { t, i18n } = useTranslation('common')
  const sources = useLiveRates(target ? [target] : [])
  const points = ((target && sources[target.key]?.points) || []).slice(-LIVE_CAPACITY)
  const current = latest(points)
  const format = (v) => new Intl.NumberFormat(i18n.language, { maximumFractionDigits: v < 10 ? 1 : 0 }).format(v)
  const time = (p) => (p?.t ? new Date(p.t).toLocaleTimeString(i18n.language) : '')
  return (
    <div className={cn('ui-subpanel rounded-lg border border-border px-3 pt-2.5 pb-2', `fx-tone-${tone}`, className)} data-testid={testId}>
      <div className="flex items-end justify-between gap-3 mb-1.5">
        <div className="min-w-0">
          <div className="ui-label text-2xs uppercase tracking-wider text-text-tertiary">{title}</div>
          <div className="text-xl font-semibold tabular-nums leading-tight" style={{ color: 'var(--fx-c)' }}>
            {current === null ? '-' : <CountUp value={current} format={format} />}
            <span className="text-xs font-medium text-text-tertiary ml-1">{t('live.perSecond')}</span>
          </div>
        </div>
        <span className="inline-flex items-center gap-1.5 text-2xs text-text-tertiary shrink-0">
          {t('live.label')}
          <StatusDot tone={current === null ? 'neutral' : 'success'} pulse={current !== null} />
        </span>
      </div>
      {points.length < 2 ? (
        <div className="flex items-center justify-center gap-2 text-xs text-text-tertiary" style={{ height }} data-testid="live-rate-collecting">
          <StatusDot tone={tone} pulse />
          {/* One sample already gives the rate above; the curve needs a second one. */}
          {current === null ? t('live.collecting') : t('live.nextSample', { seconds: Math.round(LIVE_INTERVAL_MS / 1000) })}
        </div>
      ) : (
        <StippledAreaChart
          points={points.map((p) => ({ value: p.v, t: p.t }))}
          capacity={LIVE_CAPACITY}
          height={height}
          step={6}
          tone={tone}
          label={t('live.chartLabel', { title, rate: format(current ?? 0) })}
          formatValue={(v) => `${format(v)} ${t('live.perSecond')}`}
          formatLabel={time}
        />
      )}
      {/* The time axis belongs to the chart; the collecting state keeps its height. */}
      <div className={cn('flex justify-between text-3xs text-text-tertiary mt-1', points.length < 2 && 'invisible')} data-testid="live-rate-axis">
        <span>{liveWindowLabel(t, points.length)}</span>
        <span>{t('live.now')}</span>
      </div>
    </div>
  )
}

export default LiveRatePanel
