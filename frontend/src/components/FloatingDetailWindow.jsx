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

export function useOpenDetail() {
  const { openWindow } = useWindowManager()
  return useCallback((type, entityId, data) => openWindow(type, entityId, data), [openWindow])
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

  return (
    <FloatingWindow
      storageKey={`${WINDOW_POS_PREFIX}${windowInfo.id}`}
      defaultPos={windowInfo.defaultPos}
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
