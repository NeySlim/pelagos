// SPDX-License-Identifier: Apache-2.0
/**
 * Error Boundary - Catch React errors gracefully
 * Auto-polls /api/v1/health and reloads when service is back.
 */
import { Component } from 'react'
import { Warning, ArrowClockwise, ArrowsClockwise, Check } from '@phosphor-icons/react'
import i18n from '../i18n'
import { API_BASE_URL } from '../services/apiClient'

const HEALTH_URL = `${API_BASE_URL}/health`
const POLL_INTERVAL = 3000

export class ErrorBoundary extends Component {
  constructor(props) {
    super(props)
    this.state = { hasError: false, error: null, errorInfo: null, reconnectStatus: 'polling', attempt: 0 }
    this._pollTimer = null
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error }
  }

  componentDidCatch(error, errorInfo) {
    this.setState({ errorInfo })
    if (import.meta.env.DEV) {
      console.error('ErrorBoundary caught:', error, errorInfo)
    }
    this._startPolling()
  }

  componentWillUnmount() {
    this._stopPolling()
  }

  _startPolling = () => {
    this._stopPolling()
    this.setState({ reconnectStatus: 'polling', attempt: 0 })
    this._poll()
  }

  _stopPolling = () => {
    if (this._pollTimer) {
      clearTimeout(this._pollTimer)
      this._pollTimer = null
    }
  }

  _poll = async () => {
    this.setState(s => ({ attempt: s.attempt + 1 }))
    try {
      const resp = await fetch(HEALTH_URL, { cache: 'no-store' })
      if (resp.ok) {
        this.setState({ reconnectStatus: 'reloading' })
        setTimeout(() => window.location.reload(), 800)
        return
      }
    } catch {
      // still down
    }
    this._pollTimer = setTimeout(this._poll, POLL_INTERVAL)
  }

  handleReset = () => {
    this._stopPolling()
    this.setState({ hasError: false, error: null, errorInfo: null, reconnectStatus: 'polling', attempt: 0 })
    if (this.props.onReset) {
      this.props.onReset()
    }
  }

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback
      }

      const { reconnectStatus, attempt } = this.state
      const isReloading = reconnectStatus === 'reloading'

      return (
        <div className="flex flex-col items-center justify-center min-h-[400px] p-8 text-center">
          <div className="w-16 h-16 rounded-full status-danger-bg flex items-center justify-center mb-4">
            <Warning size={32} className="status-danger-text" />
          </div>
          <h2 className="text-lg font-semibold text-text-primary mb-2">
            {i18n.t('errorBoundary.title')}
          </h2>
          <p className="text-sm text-text-secondary mb-1 max-w-md">
            {i18n.t('errorBoundary.body')}
          </p>

          <div className="flex items-center gap-2 text-sm text-text-tertiary mb-4">
            {isReloading ? (
              <>
                <Check size={16} weight="bold" className="text-accent-success" />
                <span className="text-accent-success">{i18n.t('errorBoundary.reloading')}</span>
              </>
            ) : (
              <>
                <ArrowsClockwise size={16} className="animate-spin text-accent-primary" />
                <span>{attempt > 1 ? i18n.t('errorBoundary.reconnectingAttempt', { attempt }) : i18n.t('errorBoundary.reconnecting')}</span>
              </>
            )}
          </div>

          {import.meta.env.DEV && this.state.error && (
            <pre className="text-xs text-left bg-bg-tertiary p-3 rounded-md mb-4 max-w-lg overflow-auto text-status-danger">
              {this.state.error.toString()}
            </pre>
          )}
          <button
            onClick={this.handleReset}
            className="flex items-center gap-2 px-4 py-2 bg-accent-primary text-white rounded-md hover:bg-accent-primary-op90 transition-colors"
          >
            <ArrowClockwise size={16} />
            {i18n.t('errorBoundary.retry')}
          </button>
        </div>
      )
    }

    return this.props.children
  }
}
