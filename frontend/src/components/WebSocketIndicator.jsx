// SPDX-License-Identifier: Apache-2.0
// Live connection status of the event WebSocket; click reconnects when down.
import { useTranslation } from 'react-i18next'
import { WifiHigh, WifiSlash, CircleNotch } from '@phosphor-icons/react'
import { useWebSocket, WsState } from '../hooks/useWebSocket'
import { cn } from '../lib/utils'
import { StatusDot } from './motion/Decor'

const stateConfig = {
  [WsState.CONNECTED]: { icon: WifiHigh, color: 'status-success-text', labelKey: 'websocket.connected', spin: false },
  [WsState.CONNECTING]: { icon: CircleNotch, color: 'status-warning-text', labelKey: 'websocket.connecting', spin: true },
  [WsState.DISCONNECTED]: { icon: WifiSlash, color: 'text-text-tertiary', labelKey: 'websocket.disconnected', spin: false },
  [WsState.ERROR]: { icon: WifiSlash, color: 'status-danger-text', labelKey: 'websocket.error', spin: false },
}

export function WebSocketIndicator({ className, showLabel = false, variant = 'default' }) {
  const { state, isConnected, connect } = useWebSocket()
  const { t } = useTranslation()
  const config = stateConfig[state] || stateConfig[WsState.DISCONNECTED]
  const Icon = config.icon

  if (variant === 'dot') {
    return (
      // The wrapper takes the caller's placement: .fx-dot sets its own position.
      <span className={cn('inline-flex', className)}>
        <StatusDot
          title={t(config.labelKey)}
          data-testid="ws-dot"
          data-ws-state={state}
          size={10}
          tone={isConnected ? 'success' : state === WsState.ERROR ? 'danger' : 'neutral'}
          pulse={isConnected}
          className="border-2 border-bg-secondary"
        />
      </span>
    )
  }

  return (
    <button
      type="button"
      onClick={() => !isConnected && connect()}
      title={t(config.labelKey)}
      className={cn('flex items-center gap-1.5 p-1 rounded hover:bg-bg-tertiary transition-colors', className)}
    >
      <Icon size={16} weight="bold" className={cn(config.color, config.spin && 'animate-spin')} />
      {showLabel && <span className={cn('text-xs', config.color)}>{t(config.labelKey)}</span>}
    </button>
  )
}
