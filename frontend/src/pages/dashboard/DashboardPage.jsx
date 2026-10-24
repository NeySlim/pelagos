// SPDX-License-Identifier: Apache-2.0
// Dashboard: react-grid-layout tiles over GET /dashboard/summary: the hero row (cluster
// radar, live DNS and DHCP rates) then nodes, HA, inconsistencies, zone sync, pools and
// DDNS errors. The layout is per user, read from and saved to /dashboard/layout; live
// events refresh the data and the rate counters are polled while the page is visible.
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import ReactGridLayout, { useContainerWidth } from 'react-grid-layout'
import 'react-grid-layout/css/styles.css'
import './dashboard.css'
import { Gauge, ArrowsClockwise, PencilSimple, FloppyDisk, ArrowCounterClockwise, X } from '@phosphor-icons/react'
import { PageLayout } from '../../components/PageLayout'
import { Button } from '../../components/Button'
import { LoadingSpinner } from '../../components/LoadingSpinner'
import { EmptyState } from '../../components/EmptyState'
import { useApi } from '../../hooks/useApi'
import { usePermission } from '../../hooks/usePermission'
import { useWsTopic } from '../../hooks/useWebSocket'
import { useMobile } from '../../contexts/MobileContext'
import { useNotification } from '../../contexts/NotificationContext'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'
import { COLS, ROW_HEIGHT, DEFAULT_LAYOUT, normalizeLayout, serializeLayout, sameLayout } from './layout'
import { NodesTile, HaTile, InconsistenciesTile, ZoneSyncTile, PoolsTile, D2Tile } from './tiles'
import { RadarTile, DnsTile, DhcpTile } from './heroTiles'
import { liveTargets, useLiveRates } from '../../hooks/useLiveRates'
import { summarizeLive } from '../../lib/liveRates'

const TILE_COMPONENTS = {
  radar: RadarTile, dns: DnsTile, dhcp: DhcpTile,
  nodes: NodesTile, ha: HaTile, inconsistencies: InconsistenciesTile, zones: ZoneSyncTile, pools: PoolsTile, d2: D2Tile,
}
const REFRESH_MS = 30000
const SEVERITY_RANK = { critical: 0, warning: 1, info: 2 }

export default function DashboardPage() {
  const { t } = useTranslation(['dashboard', 'common'])
  const { isMobile } = useMobile()
  const { hasPermission } = usePermission()
  const { showSuccess, showError } = useNotification()
  const canAlerts = hasPermission('read:alerts')
  const canSettings = hasPermission('admin:settings')
  const canDns = hasPermission('read:dns')
  const canDhcp = hasPermission('read:dhcp')

  const summary = useApi(() => api.dashboard.summary(), [])
  const alerts = useApi(() => (canAlerts ? api.alerts.list({ state: 'open', per_page: 100 }) : Promise.resolve(null)), [canAlerts])
  const topAlerts = useMemo(
    () => [...(alerts.data?.items || [])].sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] || String(b.last_seen).localeCompare(String(a.last_seen))).slice(0, 6),
    [alerts.data],
  )
  // Pool thresholds come with the summary; older answers fall back to the alert settings (admins).
  const needSettings = canSettings && Boolean(summary.data) && !summary.data.thresholds
  const settings = useApi(() => (needSettings ? api.admin.settings().catch(() => null) : Promise.resolve(null)), [needSettings])
  const saved = useApi(() => api.dashboard.getLayout().catch(() => ({ layout: [] })), [])
  const nodes = summary.data?.nodes
  const targets = useMemo(() => liveTargets(nodes, { dns: canDns, dhcp: canDhcp }), [nodes, canDns, canDhcp])
  const sources = useLiveRates(targets)
  const live = useMemo(() => summarizeLive(targets, sources), [targets, sources])
  const nameOf = useCallback((id) => (nodes || []).find((n) => n.peer.id === id)?.peer.name || String(id || '').slice(-6), [nodes])

  const [layout, setLayout] = useState(DEFAULT_LAYOUT)
  const [stored, setStored] = useState(DEFAULT_LAYOUT)
  const [editing, setEditing] = useState(false)
  const [saving, setSaving] = useState(false)
  useEffect(() => {
    if (!saved.data) return
    const next = normalizeLayout(saved.data.layout)
    setLayout(next)
    setStored(next)
  }, [saved.data])

  // Live events coalesce into one refetch per second at most.
  const timer = useRef(null)
  const { refetch: refetchSummary } = summary
  const { refetch: refetchAlerts } = alerts
  const refetchAll = useCallback(() => {
    refetchSummary()
    if (canAlerts) refetchAlerts()
  }, [refetchSummary, refetchAlerts, canAlerts])
  const refreshSoon = useCallback(() => {
    if (timer.current) return
    timer.current = setTimeout(() => {
      timer.current = null
      refetchAll()
    }, 1000)
  }, [refetchAll])
  useEffect(() => () => timer.current && clearTimeout(timer.current), [])
  useWsTopic('ha', refreshSoon)
  useWsTopic('nodes', refreshSoon)
  useWsTopic('alerts', refreshSoon)
  useWsTopic('plans', refreshSoon)
  useEffect(() => {
    const id = setInterval(() => {
      if (document.visibilityState !== 'hidden') refreshSoon()
    }, REFRESH_MS)
    return () => clearInterval(id)
  }, [refreshSoon])

  const { width, containerRef, mounted } = useContainerWidth({ initialWidth: 1200 })
  const dirty = !sameLayout(layout, stored)

  const save = async () => {
    setSaving(true)
    try {
      const res = await api.dashboard.saveLayout(serializeLayout(layout))
      const next = normalizeLayout(res?.layout)
      setLayout(next)
      setStored(next)
      setEditing(false)
      showSuccess(t('layout.saved'))
    } catch (err) {
      showError(errorMessage(err))
    } finally {
      setSaving(false)
    }
  }

  const cancel = () => {
    setLayout(stored)
    setEditing(false)
  }

  const openAlerts = canAlerts ? alerts.data?.items || [] : []
  const tileProps = { summary: summary.data, alerts: canAlerts ? topAlerts : null, openAlerts, editing, nameOf, thresholds: settings.data, live }
  const ordered = useMemo(() => [...layout].sort((a, b) => a.y - b.y || a.x - b.x), [layout])
  // Tiles enter in reading order (top-left first), whatever the layout array order.
  const entryIndex = useMemo(() => Object.fromEntries(ordered.map((item, i) => [item.i, i])), [ordered])

  return (
    <PageLayout
      icon={Gauge}
      title={t('pages.overview.title')}
      subtitle={t('pages.overview.subtitle')}
      testId="page-dashboard-overview"
      actions={
        editing ? (
          <>
            <Button variant="secondary" size="sm" onClick={() => setLayout(normalizeLayout(DEFAULT_LAYOUT))} data-testid="dashboard-reset">
              <ArrowCounterClockwise size={14} />
              {t('layout.reset')}
            </Button>
            <Button variant="secondary" size="sm" onClick={cancel}>
              <X size={14} />
              {t('common:actions.cancel')}
            </Button>
            <Button size="sm" onClick={save} loading={saving} disabled={!dirty} data-testid="dashboard-save">
              <FloppyDisk size={14} />
              {t('layout.save')}
            </Button>
          </>
        ) : (
          <>
            <Button variant="secondary" size="sm" onClick={refetchAll} disabled={summary.loading}>
              <ArrowsClockwise size={14} />
              {t('common:actions.refresh')}
            </Button>
            {!isMobile && (
              <Button variant="secondary" size="sm" onClick={() => setEditing(true)} data-testid="dashboard-edit">
                <PencilSimple size={14} />
                {t('layout.edit')}
              </Button>
            )}
          </>
        )
      }
    >
      {/* The measured container exists from the first render, so its width is observed before the grid shows. */}
      <div ref={containerRef} className={editing ? 'dashboard-grid editing' : 'dashboard-grid'} data-testid="dashboard-grid">
      {summary.loading && !summary.data ? (
        <div className="flex justify-center py-12">
          <LoadingSpinner size="md" />
        </div>
      ) : summary.error && !summary.data ? (
        <EmptyState icon={Gauge} title={errorMessage(summary.error)} action={{ label: t('common:actions.retry'), onClick: refetchAll }} />
      ) : isMobile ? (
        <div className="space-y-3" data-testid="dashboard-stack">
          {ordered.map((item, i) => {
            const Tile = TILE_COMPONENTS[item.i]
            return (
              <div key={item.i} className="fx-stagger-item" style={{ height: item.h * ROW_HEIGHT, '--fx-i': i }}>
                <Tile {...tileProps} />
              </div>
            )
          })}
        </div>
      ) : (
        <>
          {mounted && (
            <ReactGridLayout
              width={width}
              layout={layout}
              gridConfig={{ cols: COLS, rowHeight: ROW_HEIGHT, margin: [12, 12], containerPadding: [0, 0] }}
              dragConfig={{ enabled: editing, handle: '.tile-handle' }}
              resizeConfig={{ enabled: editing }}
              onLayoutChange={(next) => editing && setLayout((cur) => (sameLayout(cur, next) ? cur : normalizeLayout(next)))}
            >
              {layout.map((item) => {
                const Tile = TILE_COMPONENTS[item.i]
                return (
                  <div key={item.i}>
                    <div className="fx-stagger-item h-full" style={{ '--fx-i': entryIndex[item.i] }}>
                      <Tile {...tileProps} />
                    </div>
                  </div>
                )
              })}
            </ReactGridLayout>
          )}
        </>
      )}
      </div>
    </PageLayout>
  )
}
