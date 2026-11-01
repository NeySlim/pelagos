// SPDX-License-Identifier: Apache-2.0
// Global search: a palette opened by Ctrl+K (Cmd+K) or "/", fed by GET /search. Results are
// grouped by kind, each with the UI route that shows it; arrows move, Enter opens, Escape closes.
// The input is a combobox over a listbox (aria-activedescendant), so focus never leaves the box.
import { useCallback, useEffect, useId, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import * as Dialog from '@radix-ui/react-dialog'
import {
  MagnifyingGlass, Globe, ListBullets, Clock, BookmarkSimple, Desktop, Bell, HardDrives, TreeStructure,
} from '@phosphor-icons/react'
import { cn } from '../lib/utils'
import { api } from '../services/api'
import { ErrorNotice } from './ErrorNotice'
import { useOpenDetail } from './FloatingDetailWindow'

const GROUPS = ['hosts', 'zones', 'records', 'leases', 'reservations', 'alerts', 'nodes', 'networks']
const ICONS = {
  hosts: Desktop, zones: Globe, records: ListBullets, leases: Clock, reservations: BookmarkSimple,
  alerts: Bell, nodes: HardDrives, networks: TreeStructure,
}
const MIN_CHARS = 2
const DEBOUNCE_MS = 180

export function GlobalSearch({ open, onOpenChange }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const openDetail = useOpenDetail()
  const base = useId()
  const [q, setQ] = useState('')
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(false)
  const [active, setActive] = useState(0)
  const seq = useRef(0)

  // Reset on close, so the next open starts clean.
  useEffect(() => {
    if (open) return
    seq.current += 1
    setQ('')
    setData(null)
    setError(null)
    setLoading(false)
    setActive(0)
  }, [open])

  const run = useCallback(async (text) => {
    const mine = ++seq.current
    setLoading(true)
    try {
      const res = await api.search.query(text)
      if (mine !== seq.current) return
      setData(res)
      setError(null)
      setActive(0)
    } catch (err) {
      if (mine !== seq.current) return
      setError(err)
      setData(null)
    } finally {
      if (mine === seq.current) setLoading(false)
    }
  }, [])

  useEffect(() => {
    const text = q.trim()
    if (!open || text.length < MIN_CHARS) {
      seq.current += 1
      setData(null)
      setError(null)
      setLoading(false)
      return undefined
    }
    const timer = setTimeout(() => run(text), DEBOUNCE_MS)
    return () => clearTimeout(timer)
  }, [q, open, run])

  const groups = useMemo(
    () => GROUPS.map((g) => ({ id: g, items: data?.results?.[g] || [], total: data?.totals?.[g] || 0 })).filter((g) => g.items.length > 0),
    [data],
  )
  const flat = useMemo(() => groups.flatMap((g) => g.items.map((item) => ({ ...item, group: g.id }))), [groups])
  const optionId = (i) => `${base}-opt-${i}`

  const choose = (item) => {
    onOpenChange(false)
    navigate(item.route)
    // A host opens its sheet over the list the route filters.
    if (item.kind === 'host') openDetail('host', item.id, { title: item.label, subtitle: item.sublabel || undefined })
  }

  const onKeyDown = (e) => {
    if (!flat.length) return
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      setActive((i) => (i + 1) % flat.length)
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setActive((i) => (i - 1 + flat.length) % flat.length)
    } else if (e.key === 'Home' && e.ctrlKey) {
      e.preventDefault()
      setActive(0)
    } else if (e.key === 'End' && e.ctrlKey) {
      e.preventDefault()
      setActive(flat.length - 1)
    } else if (e.key === 'Enter') {
      e.preventDefault()
      if (flat[active]) choose(flat[active])
    }
  }

  useEffect(() => {
    document.getElementById(optionId(active))?.scrollIntoView?.({ block: 'nearest' })
  }, [active]) // eslint-disable-line react-hooks/exhaustive-deps

  const text = q.trim()
  const searched = text.length >= MIN_CHARS
  const sourceErrors = Object.keys(data?.errors || {})
  const status = !searched
    ? t('search.hint', { count: MIN_CHARS })
    : loading && !data
      ? t('search.searching')
      : flat.length
        ? t('search.count', { count: flat.length })
        : data
          ? t('search.none', { q: text })
          : ''
  let index = -1

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="modal-backdrop fixed inset-0 z-[200]" />
        <Dialog.Content
          className="ui-modal modal-enhanced fixed z-[201] left-1/2 top-[12vh] -translate-x-1/2 w-[min(92vw,38rem)] max-h-[70vh] flex flex-col rounded-xl bg-bg-primary"
          aria-describedby={undefined}
          data-testid="global-search"
        >
          <Dialog.Title className="sr-only">{t('search.title')}</Dialog.Title>
          <div className="flex items-center gap-2 px-3 py-2.5 border-b border-border-op50 shrink-0">
            <MagnifyingGlass size={16} className="text-text-tertiary shrink-0" aria-hidden="true" />
            <input
              type="search"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              onKeyDown={onKeyDown}
              placeholder={t('search.placeholder')}
              aria-label={t('search.title')}
              role="combobox"
              aria-expanded={flat.length > 0}
              aria-controls={`${base}-list`}
              aria-autocomplete="list"
              aria-activedescendant={flat.length ? optionId(active) : undefined}
              autoComplete="off"
              autoCorrect="off"
              spellCheck={false}
              className="flex-1 min-w-0 bg-transparent text-sm text-text-primary placeholder:text-text-tertiary outline-none"
              data-testid="global-search-input"
            />
          </div>
          <div className="px-3 py-1 text-xs text-text-tertiary shrink-0" role="status" aria-live="polite" data-testid="global-search-status">{status}</div>
          {error && <ErrorNotice error={error} onRetry={() => run(text)} className="px-3 pb-2" />}
          {!error && sourceErrors.length > 0 && <p className="px-3 pb-1 text-xs status-warning-text">{t('search.partial')}</p>}
          <div id={`${base}-list`} role="listbox" aria-label={t('search.title')} className="overflow-auto px-1 pb-2 min-h-0">
            {groups.map((g) => {
              const Icon = ICONS[g.id]
              return (
                <div key={g.id} role="group" aria-label={t(`search.groups.${g.id}`)} data-testid={`search-group-${g.id}`}>
                  <div className="px-2 pt-2 pb-0.5 text-3xs font-semibold uppercase tracking-wider text-text-tertiary flex items-center gap-1.5" aria-hidden="true">
                    <Icon size={11} />
                    {t(`search.groups.${g.id}`)}
                    {g.total > g.items.length && <span className="ml-auto normal-case font-normal">{t('search.more', { count: g.total - g.items.length })}</span>}
                  </div>
                  {g.items.map((item) => {
                    index += 1
                    const i = index
                    return (
                      <div
                        key={`${item.kind}:${item.id}`}
                        id={optionId(i)}
                        role="option"
                        aria-selected={i === active}
                        data-testid="search-result"
                        data-kind={item.kind}
                        onMouseMove={() => i !== active && setActive(i)}
                        onClick={() => choose(item)}
                        className={cn('flex items-baseline gap-2 px-2 py-1.5 rounded-md cursor-pointer text-sm', i === active ? 'bg-bg-tertiary text-text-primary' : 'text-text-secondary')}
                      >
                        <span className="font-mono text-xs truncate shrink-0 max-w-[55%]">{item.label}</span>
                        {item.sublabel && <span className="text-xs text-text-tertiary truncate">{item.sublabel}</span>}
                      </div>
                    )
                  })}
                </div>
              )
            })}
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}

export default GlobalSearch
