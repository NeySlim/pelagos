// SPDX-License-Identifier: Apache-2.0
/**
 * SearchBar Component - Search with debounce
 */
import { useState, useEffect, useRef } from 'react'
import { MagnifyingGlass, X } from '@phosphor-icons/react'
import { cn } from '../lib/utils'
import i18n from '../i18n'

export function SearchBar({ 
  placeholder, 
  value = '', 
  onChange, 
  onClear,
  debounce = 300,
  className 
}) {
  const [internalValue, setInternalValue] = useState(value)

  useEffect(() => {
    setInternalValue(value)
  }, [value])

  // Latest value and callback through refs: the debounce restarts only on typing.
  const latest = useRef({ value, onChange })
  latest.current = { value, onChange }
  useEffect(() => {
    const timer = setTimeout(() => {
      if (internalValue !== latest.current.value) {
        latest.current.onChange?.(internalValue)
      }
    }, debounce)

    return () => clearTimeout(timer)
  }, [internalValue, debounce])

  const handleClear = () => {
    setInternalValue('')
    onChange?.('')
    onClear?.()
  }

  return (
    <div className={cn("relative", className)}>
      <MagnifyingGlass 
        size={14} 
        className="absolute left-2 top-1/2 -translate-y-1/2 text-text-secondary" 
      />
      <input
        type="text"
        value={internalValue}
        onChange={(e) => setInternalValue(e.target.value)}
        placeholder={placeholder ?? i18n.t('table.search')}
        className="w-full pl-7 pr-7 py-1.5 bg-bg-tertiary border border-border rounded-md text-sm text-text-primary placeholder-text-secondary focus:outline-none focus:ring-1 focus:ring-accent-primary focus:border-transparent transition-all"
      />
      {internalValue && (
        <button
          onClick={handleClear}
          className="absolute right-2 top-1/2 -translate-y-1/2 text-text-secondary hover:text-text-primary transition-colors"
        >
          <X size={14} />
        </button>
      )}
    </div>
  )
}
