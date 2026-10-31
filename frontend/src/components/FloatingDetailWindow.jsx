// SPDX-License-Identifier: Apache-2.0
// Draggable detail window driven by WindowManagerContext. Areas register a renderer
// per entity type (host, lease, zone, ...) with registerDetailRenderer; the window
// gives it { entityId, data, windowId, close, update } and reads title/subtitle/icon
// from the renderer's `meta(data)` or from the data itself.
import { useCallback, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Info } from '@phosphor-icons/react'
import { FloatingWindow } from './ui/FloatingWindow'
import { useWindowManager, WINDOW_POS_PREFIX } from '../contexts/WindowManagerContext'
import { useMobile } from '../contexts/MobileContext'

const renderers = new Map()

// renderer: { component, icon?, iconClass?, meta?(data) -> { title, subtitle } }
export function registerDetailRenderer(type, renderer) {
  renderers.set(type, typeof renderer === 'function' ? { component: renderer } : renderer)
  return () => renderers.delete(type)
}

export function getDetailRenderer(type) {
  return renderers.get(type)
}

// Window ids opened with { wide: true }: the window manager owns no per-window options.
const wideIds = new Set()
const WIDE_W = 720

export function useOpenDetail() {
  const { openWindow } = useWindowManager()
  return useCallback((type, entityId, data, options = {}) => {
    // The latest open decides; a mounted window consumes its entry.
    if (options.wide) wideIds.add(`${type}:${entityId}`)
    else wideIds.delete(`${type}:${entityId}`)
    openWindow(type, entityId, data)
  }, [openWindow])
}

export function FloatingDetailWindow({ windowInfo }) {
  const { t } = useTranslation()
  const { closeWindow, focusWindow, updateWindowData } = useWindowManager()
  const [minimized, setMinimized] = useState(false)
  const renderer = renderers.get(windowInfo.type)
  const meta = renderer?.meta?.(windowInfo.data) || {}
  const title = meta.title || windowInfo.data?.title || windowInfo.entityId
  const subtitle = meta.subtitle || windowInfo.data?.subtitle || t(`detail.type.${windowInfo.type}`, { defaultValue: windowInfo.type })
  const Icon = renderer?.icon || Info
  const Component = renderer?.component
  const close = () => closeWindow(windowInfo.id)
  // Read once at mount so the width is per open; tiling keeps its own widths.
  const [wide] = useState(() => {
    const asked = wideIds.delete(windowInfo.id)
    return asked && !windowInfo.tileKey
  })
  const dp = windowInfo.defaultPos
  // A wide window re-centres by the real width change.
  const defaultPos = wide && dp ? { ...dp, w: WIDE_W, x: Math.max(20, Math.round(dp.x - (WIDE_W - dp.w) / 2)) } : dp

  return (
    <FloatingWindow
      storageKey={`${WINDOW_POS_PREFIX}${windowInfo.id}`}
      defaultPos={defaultPos}
      wide={wide}
      forcePosition={Boolean(windowInfo.tileKey)}
      minimized={minimized}
      onMinimizeToggle={() => setMinimized((m) => !m)}
      onClose={close}
      onFocus={() => focusWindow(windowInfo.id)}
      zIndex={windowInfo.zIndex}
      title={title}
      subtitle={subtitle}
      icon={Icon}
      iconClass={renderer?.iconClass}
      constraints={{ minW: 380, maxW: 1100, minH: 240, defW: 520, defH: 480 }}
    >
      <div className="flex-1 overflow-auto p-3" data-testid={`detail-window-${windowInfo.type}`}>
        {Component ? (
          <Component
            entityId={windowInfo.entityId}
            data={windowInfo.data}
            windowId={windowInfo.id}
            close={close}
            update={(data) => updateWindowData(windowInfo.id, data)}
          />
        ) : (
          <p className="text-xs text-text-tertiary">{t('detail.noRenderer', { type: windowInfo.type })}</p>
        )}
      </div>
    </FloatingWindow>
  )
}

// Mounted once in App: renders every open window (desktop only).
export function DetailWindowLayer() {
  const { windows } = useWindowManager()
  const { isMobile } = useMobile()
  if (isMobile || windows.length === 0) return null
  return (
    <>
      {windows.map((win) => (
        <FloatingDetailWindow key={win.tileKey ? `${win.id}-${win.tileKey}` : win.id} windowInfo={win} />
      ))}
    </>
  )
}

export default FloatingDetailWindow
