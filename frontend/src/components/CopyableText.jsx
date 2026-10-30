// SPDX-License-Identifier: Apache-2.0
// A long value (fingerprint, key) shown shortened, with the full text in the tooltip and a copy button.
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Copy, Check } from '@phosphor-icons/react'
import { cn } from '../lib/utils'

function shorten(value, max) {
  const text = String(value ?? '')
  if (!max || text.length <= max) return text
  return `${text.slice(0, max)}…`
}

export function CopyableText({ value, max = 24, label, className, testId }) {
  const { t } = useTranslation('common')
  const [copied, setCopied] = useState(false)
  if (!value) return <span className={className}>-</span>
  const text = String(value)
  const copy = () => {
    const done = () => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    }
    const write = navigator.clipboard?.writeText(text)
    if (write) write.then(done, () => {})
  }
  return (
    <span className={cn('inline-flex items-center gap-1 min-w-0 max-w-full', className)} data-testid={testId}>
      <span className="font-mono truncate" title={text}>
        {label ? `${label} ` : ''}
        {shorten(text, max)}
      </span>
      <button
        type="button"
        onClick={copy}
        className="shrink-0 rounded p-0.5 text-text-tertiary hover:text-text-primary hover:bg-bg-tertiary"
        aria-label={copied ? t('common.copied') : `${t('actions.copy')} ${text}`}
        title={copied ? t('common.copied') : t('actions.copy')}
      >
        {copied ? <Check size={12} /> : <Copy size={12} />}
      </button>
    </span>
  )
}

export default CopyableText
