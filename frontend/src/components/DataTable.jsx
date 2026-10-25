// SPDX-License-Identifier: Apache-2.0
// Table for every list screen: columns with renderers, server or client sorting,
// search box, filter selects with removable chips, pagination, loading, empty and
// error states, selectable rows and a right-side toolbar. Cells render as text.
import { useLayoutEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { CaretUp, CaretDown, CaretUpDown, ArrowsClockwise, Table as TableIcon } from '@phosphor-icons/react'
import { cn } from '../lib/utils'
import { titleCaseClass } from '../lib/displayCase'
import { Pagination } from './Pagination'
import { SearchBar } from './SearchBar'
import { FilterSelect } from './ui/Select'
import { FilterChips } from './ui/FilterChips'
import { EmptyState } from './EmptyState'
import { SkeletonTable } from './motion/Skeleton'
import { RowEnter, RowLeave } from './motion/Rows'
import { glideRows, orderChanged } from './motion/primitives'
import { useMotionLevel } from '../contexts/MotionContext'
import { useColumnBand } from '../hooks/useColumnBand'
import { useSharedName } from '../hooks/useSharedName'
import { Button } from './Button'
import { errorMessage } from '../services/apiClient'

function getValue(row, key) {
  if (!key) return undefined
  return key.split('.').reduce((acc, part) => (acc == null ? undefined : acc[part]), row)
}

// More inserted or removed rows than this at once is a page or filter change, not an event.
export const MAX_ROW_MOTION = 10

const cellText = (v) => (v === null || v === undefined ? '' : typeof v === 'object' ? JSON.stringify(v) : String(v))

function compare(a, b) {
  if (a === b) return 0
  if (a === undefined || a === null) return 1
  if (b === undefined || b === null) return -1
  if (typeof a === 'number' && typeof b === 'number') return a - b
  return String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: 'base' })
}

export function DataTable({
  columns = [],
  rows = [],
  rowKey = 'id',
  loading = false,
  error = null,
  onRetry,
  emptyTitle,
  emptyDescription,
  emptyIcon,
  onRowClick,
  selectedKey,
  rowClassName,
  // Sorting: controlled (sort + onSortChange) or local when `clientSort` is true.
  sort,
  onSortChange,
  clientSort = false,
  // Toolbar
  search,
  filters = [],
  toolbar,
  title,
  // Pagination: { page, perPage, total, onPageChange, onPerPageChange }
  pagination,
  dense = false,
  // Rows whose key appears after the first load unfold into place with a highlight
  // (inserted records, hosts, alerts). Off by default: a refetch is not an insertion.
  animateInserts = false,
  // { name, to }: the whole table panel travels with a view transition to or from `to`.
  shared,
  // Rows that disappear fold away in place (fade below full motion) instead of vanishing.
  animateRemovals = false,
  // Time a removed row stays in place before it folds (struck-through rows, for instance).
  leaveHoldMs = 0,
  // Column keys whose cells tint once when their value changes for the same row (serials,
  // counters); `col.changeValue(row)` overrides what is compared.
  highlightChanges = null,
  className,
  testId = 'data-table',
}) {
  const { t } = useTranslation()
  const [localSort, setLocalSort] = useState(null)
  const activeSort = sort || localSort
  const bodyRef = useRef(null)
  const sharedStyle = useSharedName(shared?.name || 'table', shared?.to || '/')
  const known = useRef(null)
  const entering = useRef(new Set())
  const lastRows = useRef(new Map()) // key -> { row, index } of the last settled render
  const leaving = useRef(new Map())
  const cellValues = useRef(new Map()) // `${key}|${col}` -> compared value
  const cellGen = useRef(new Map()) // `${key}|${col}` -> highlight generation
  const [, setLeft] = useState(0)

  const keyOf = (row, index) => (typeof rowKey === 'function' ? rowKey(row, index) : getValue(row, rowKey) ?? index)

  const sortedRows = useMemo(() => {
    if (!clientSort || !activeSort?.field) return rows
    const col = columns.find((c) => (c.sortKey || c.key) === activeSort.field)
    const accessor = col?.sortValue || ((row) => getValue(row, activeSort.field))
    const dir = activeSort.order === 'desc' ? -1 : 1
    return [...rows].sort((a, b) => dir * compare(accessor(a), accessor(b)))
  }, [rows, clientSort, activeSort, columns])

  const toggleSort = (col) => {
    if (!col.sortable) return
    const field = col.sortKey || col.key
    const next =
      activeSort?.field === field ? { field, order: activeSort.order === 'asc' ? 'desc' : 'asc' } : { field, order: 'asc' }
    if (onSortChange) onSortChange(next)
    else setLocalSort(next)
  }

  // Rows already on screen that change order (a sort, a divergence resolved by a refetch)
  // glide to their new place: their old tops are read before this render commits.
  const level = useMotionLevel()
  const orderRef = useRef([])
  const firstTops = useRef(null)
  const liveKeys = loading || error ? [] : sortedRows.map((row, index) => keyOf(row, index))
  if (level === 'full' && bodyRef.current && liveKeys.length <= 300 && orderChanged(orderRef.current, liveKeys)) {
    const domRows = bodyRef.current.rows
    if (domRows.length === orderRef.current.length) {
      firstTops.current = new Map(orderRef.current.map((k, i) => [k, domRows[i].getBoundingClientRect().top]))
    }
  }
  useLayoutEffect(() => {
    const first = firstTops.current
    firstTops.current = null
    const domRows = bodyRef.current?.rows
    if (first && domRows?.length === liveKeys.length) {
      const moves = []
      liveKeys.forEach((k, i) => {
        const dy = first.has(k) ? first.get(k) - domRows[i].getBoundingClientRect().top : 0
        if (Math.abs(dy) >= 0.5) moves.push([domRows[i], dy])
      })
      glideRows(moves)
    }
    orderRef.current = liveKeys
  })
  const wrapRef = useRef(null)
  const bandRef = useRef(null)
  useColumnBand(wrapRef, bandRef)

  if ((animateInserts || animateRemovals) && !loading) {
    const keys = sortedRows.map((row, index) => keyOf(row, index))
    const present = new Set(keys)
    if (known.current) {
      const added = keys.filter((key) => !known.current.has(key))
      const removed = [...known.current].filter((key) => !present.has(key))
      if (added.length + removed.length <= MAX_ROW_MOTION) {
        if (animateInserts) for (const key of added) entering.current.add(key)
        if (animateRemovals) for (const key of removed) if (lastRows.current.has(key)) leaving.current.set(key, lastRows.current.get(key))
      }
      for (const key of entering.current) if (!present.has(key)) entering.current.delete(key)
      for (const key of leaving.current.keys()) if (present.has(key)) leaving.current.delete(key)
    }
    if (keys.length || known.current) known.current = present
    lastRows.current = new Map(sortedRows.map((row, index) => [keys[index], { row, index }]))
  }

  // A changed value of a known row lights its cell once (after the first load only).
  const highlighted = new Set(highlightChanges || [])
  if (highlighted.size && !loading) {
    sortedRows.forEach((row, index) => {
      const key = keyOf(row, index)
      for (const col of columns) {
        if (!highlighted.has(col.key)) continue
        const id = `${key}|${col.key}`
        const value = cellText(col.changeValue ? col.changeValue(row) : getValue(row, col.key))
        const before = cellValues.current.get(id)
        if (before !== undefined && before !== value) cellGen.current.set(id, (cellGen.current.get(id) || 0) + 1)
        cellValues.current.set(id, value)
      }
    })
  }

  // Ghost rows of removed keys keep their last place while they fold.
  const renderItems = sortedRows.map((row, index) => ({ row, index, key: keyOf(row, index) }))
  for (const [key, ghost] of leaving.current) {
    renderItems.splice(Math.min(ghost.index, renderItems.length), 0, { row: ghost.row, index: ghost.index, key, ghost: true })
  }

  const chipFilters = filters
    .filter((f) => f.value !== undefined && f.value !== null && f.value !== '')
    .map((f) => ({
      key: f.key,
      label: f.label,
      value: f.value,
      displayValue: f.options?.find((o) => o.value === f.value)?.label || f.value,
    }))

  const hasToolbar = Boolean(title || search || filters.length > 0 || toolbar)
  const cellPad = dense ? 'px-3 py-1.5' : 'px-3 py-2'

  return (
    <div className={cn('ui-table flex flex-col rounded-xl border border-border bg-bg-secondary overflow-hidden', className)} data-testid={testId} style={{ ...(dense ? { '--fx-cell-py': '6px' } : null), ...(shared ? sharedStyle : null) }}>
      {hasToolbar && (
        <div className="flex flex-wrap items-center gap-2 px-3 py-2 border-b border-border-op60">
          {title && <h3 className={cn('ui-card-title text-sm font-semibold text-text-primary mr-2', titleCaseClass(title))}>{title}</h3>}
          {search && (
            <SearchBar
              value={search.value}
              onChange={search.onChange}
              placeholder={search.placeholder || t('table.search')}
              className="w-56"
            />
          )}
          {filters.map((filter) => (
            <FilterSelect
              key={filter.key}
              value={filter.value ?? ''}
              onChange={filter.onChange}
              options={filter.options || []}
              placeholder={filter.placeholder || filter.label}
              size="sm"
            />
          ))}
          <div className="ml-auto flex items-center gap-1.5">{toolbar}</div>
        </div>
      )}
      {chipFilters.length > 0 && (
        <FilterChips
          filters={chipFilters}
          onRemove={(key) => filters.find((f) => f.key === key)?.onChange?.('')}
          onClearAll={() => filters.forEach((f) => f.onChange?.(''))}
        />
      )}

      <div className="overflow-auto flex-1 min-h-0">
        <div ref={wrapRef} className="relative">
        <span ref={bandRef} className="fx-colband" aria-hidden="true" />
        <table className="w-full text-sm border-collapse">
          <thead className="table-header-gradient sticky top-0 z-10">
            <tr>
              {columns.map((col) => {
                const field = col.sortKey || col.key
                const isSorted = activeSort?.field === field
                return (
                  <th
                    key={col.key || col.label}
                    scope="col"
                    style={col.width ? { width: col.width } : undefined}
                    className={cn(
                      'text-left text-2xs font-semibold uppercase tracking-wider text-text-tertiary whitespace-nowrap border-b border-border',
                      cellPad,
                      col.align === 'right' && 'text-right',
                      col.align === 'center' && 'text-center',
                      col.sortable && 'cursor-pointer select-none hover:text-text-primary',
                      col.headerClassName,
                    )}
                    onClick={() => toggleSort(col)}
                    aria-sort={isSorted ? (activeSort.order === 'asc' ? 'ascending' : 'descending') : undefined}
                  >
                    <span className="inline-flex items-center gap-1">
                      {col.label}
                      {col.sortable &&
                        (isSorted ? (
                          activeSort.order === 'asc' ? <CaretUp size={10} weight="bold" /> : <CaretDown size={10} weight="bold" />
                        ) : (
                          <CaretUpDown size={10} className="opacity-50" />
                        ))}
                    </span>
                  </th>
                )
              })}
            </tr>
          </thead>
          <tbody ref={bodyRef}>
            {!loading &&
              !error &&
              renderItems.map(({ row, key, ghost }) => {
                const selected = !ghost && selectedKey !== undefined && selectedKey === key
                const isEntering = entering.current.has(key)
                const Row = ghost ? RowLeave : isEntering ? RowEnter : 'tr'
                const ghostProps = ghost
                  ? {
                      holdMs: leaveHoldMs,
                      onLeft: () => {
                        leaving.current.delete(key)
                        setLeft((n) => n + 1)
                      },
                    }
                  : {}
                return (
                  <Row
                    key={ghost ? `leave:${key}` : key}
                    {...ghostProps}
                    className={cn(
                      'ui-row border-b border-border-op30 last:border-b-0 transition-colors',
                      onRowClick && 'cursor-pointer hover:bg-tertiary-op40',
                      selected && 'bg-accent-primary-op10 is-selected',
                      typeof rowClassName === 'function' ? rowClassName(row) : rowClassName,
                    )}
                    onClick={onRowClick && !ghost ? () => onRowClick(row) : undefined}
                    data-testid={ghost ? 'data-table-row-leaving' : 'data-table-row'}
                  >
                    {columns.map((col) => {
                      const raw = getValue(row, col.key)
                      const content = col.render ? col.render(row, raw, { entering: isEntering && !ghost }) : raw === null || raw === undefined ? '' : String(raw)
                      const gen = ghost ? 0 : cellGen.current.get(`${key}|${col.key}`) || 0
                      return (
                        <td
                          key={col.key || col.label}
                          className={cn(
                            'text-text-primary align-middle',
                            cellPad,
                            col.mono && 'font-mono text-xs',
                            col.align === 'right' && 'text-right',
                            col.align === 'center' && 'text-center',
                            col.truncate && 'max-w-[1px] truncate',
                            gen > 0 && (gen % 2 ? 'fx-hl-a' : 'fx-hl-b'),
                            col.className,
                          )}
                          data-changed={gen > 0 ? gen : undefined}
                          title={col.truncate && typeof content === 'string' ? content : undefined}
                        >
                          {content}
                        </td>
                      )
                    })}
                  </Row>
                )
              })}
          </tbody>
        </table>
        </div>

        {loading && <SkeletonTable columns={columns.length} testId="data-table-loading" />}
        {!loading && error && (
          <div className="flex flex-col items-center justify-center gap-3 py-10 px-4 text-center" data-testid="data-table-error">
            <p className="text-sm status-danger-text">{errorMessage(error)}</p>
            {onRetry && (
              <Button variant="secondary" size="sm" onClick={onRetry}>
                <ArrowsClockwise size={14} />
                {t('actions.retry')}
              </Button>
            )}
          </div>
        )}
        {!loading && !error && renderItems.length === 0 && (
          <EmptyState icon={emptyIcon || TableIcon} title={emptyTitle || t('table.empty')} description={emptyDescription} />
        )}
      </div>

      {pagination && (pagination.total > (pagination.perPage || 50) || pagination.page > 1 || pagination.onPerPageChange) && (
        <div className="border-t border-border-op60">
          <Pagination
            total={pagination.total}
            page={pagination.page}
            perPage={pagination.perPage}
            onChange={pagination.onPageChange}
            onPerPageChange={pagination.onPerPageChange}
          />
        </div>
      )}
    </div>
  )
}

export default DataTable
